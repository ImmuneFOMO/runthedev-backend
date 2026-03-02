from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .models import DocumentContext, FetchGraphContext, FetchedDoc, FetchedEdge, LinkInfo, ParsedMarkdown
from .parser import parse_markdown


MARKDOWN_SUFFIXES = {".md", ".markdown"}
CONFIG_SUFFIXES = {".json", ".yml", ".yaml", ".toml"}
DEFAULT_TIMEOUT = 10.0
DEFAULT_BRANCHES = ("main", "master")
SKILL_DEPENDENCY_RE = re.compile(
    r"\bnpx\s+skills\s+add\s+(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)@(?P<skill>[A-Za-z0-9_.-]+)\b",
    re.IGNORECASE,
)
SHA_LIKE_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


class AuditServiceError(Exception):
    status_code = 500

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class InvalidGitHubUrl(AuditServiceError):
    status_code = 400


class DocumentNotFound(AuditServiceError):
    status_code = 404


class UpstreamRateLimited(AuditServiceError):
    status_code = 429


class UpstreamFetchError(AuditServiceError):
    status_code = 502


class FetchLimitExceeded(AuditServiceError):
    status_code = 422


@dataclass(frozen=True, slots=True)
class GitHubLocation:
    host_kind: str
    owner: str
    repo: str
    ref: str
    path: str

    @property
    def repo_key(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def raw_url(self) -> str:
        suffix = f"/{self.path}" if self.path else ""
        return f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.ref}{suffix}"


@dataclass(frozen=True, slots=True)
class SkillDependency:
    owner: str
    repo: str
    skill_name: str

    @property
    def repo_key(self) -> str:
        return f"{self.owner}/{self.repo}"


def _strip_fragment_and_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _path_suffix(url: str) -> str:
    return PurePosixPath(urlsplit(url).path).suffix.lower()


def _github_segments(url: str) -> tuple[str, list[str]]:
    stripped = _strip_fragment_and_query(url)
    parts = urlsplit(stripped)
    return parts.netloc.lower(), [segment for segment in parts.path.split("/") if segment]


def parse_github_location(url: str) -> GitHubLocation:
    normalized = _strip_fragment_and_query(url)
    host, segments = _github_segments(normalized)

    if host == "raw.githubusercontent.com":
        if len(segments) < 4:
            raise InvalidGitHubUrl("Raw GitHub URLs must include owner, repo, ref, and path.")
        owner, repo, ref = segments[:3]
        path = "/".join(segments[3:])
        return GitHubLocation(host_kind="raw", owner=owner, repo=repo, ref=ref, path=path)

    if host == "github.com":
        if len(segments) < 5:
            raise InvalidGitHubUrl("GitHub blob/tree URLs must include owner, repo, ref, and path.")
        owner, repo, kind = segments[:3]
        if kind not in {"blob", "tree"}:
            raise InvalidGitHubUrl("Only github.com blob/tree URLs are supported.")
        ref = segments[3]
        path = "/".join(segments[4:])
        return GitHubLocation(host_kind=kind, owner=owner, repo=repo, ref=ref, path=path)

    raise InvalidGitHubUrl("Only github.com and raw.githubusercontent.com URLs are supported.")


def blob_to_raw_url(url: str) -> str:
    location = parse_github_location(url)
    if location.host_kind not in {"blob", "raw"}:
        raise InvalidGitHubUrl("URL must point to a markdown file, not a folder.")
    return location.raw_url


def resolve_relative_link(base_url: str, href: str) -> str | None:
    if not href or href.startswith("#"):
        return None

    candidate = _strip_fragment_and_query(urljoin(base_url, href))
    host = urlsplit(candidate).netloc.lower()
    if host not in {"github.com", "raw.githubusercontent.com"}:
        return None

    location = parse_github_location(candidate)
    if location.host_kind == "tree":
        return None
    return location.raw_url


def extract_skill_dependencies(text: str) -> list[SkillDependency]:
    dependencies: list[SkillDependency] = []
    seen: set[tuple[str, str, str]] = set()
    for match in SKILL_DEPENDENCY_RE.finditer(text):
        key = (
            match.group("owner"),
            match.group("repo"),
            match.group("skill"),
        )
        if key in seen:
            continue
        seen.add(key)
        dependencies.append(
            SkillDependency(
                owner=match.group("owner"),
                repo=match.group("repo"),
                skill_name=match.group("skill"),
            )
        )
    return dependencies


def dependency_candidate_urls(owner: str, repo: str, skill_name: str) -> list[str]:
    base = f"https://raw.githubusercontent.com/{owner}/{repo}/main/skills/{skill_name}"
    return [f"{base}/SKILL.md", f"{base}/README.md"]


class GitHubDocFetcher:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT, client: httpx.AsyncClient | None = None):
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None
        self._content_cache: dict[str, tuple[str, str]] = {}
        self._existence_cache: dict[str, bool] = {}

    async def __aenter__(self) -> "GitHubDocFetcher":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def resolve_root_doc_url(self, url: str) -> str:
        normalized = _strip_fragment_and_query(url)
        host, segments = _github_segments(normalized)

        if host == "raw.githubusercontent.com":
            location = parse_github_location(normalized)
            if _path_suffix(location.raw_url) not in MARKDOWN_SUFFIXES:
                raise InvalidGitHubUrl("Input URL must point to a markdown document or a folder.")
            return location.raw_url

        if host != "github.com" or len(segments) < 4:
            raise InvalidGitHubUrl("Only github.com and raw.githubusercontent.com URLs are supported.")

        owner, repo, kind = segments[:3]
        if kind not in {"blob", "tree"}:
            raise InvalidGitHubUrl("Only github.com blob/tree URLs are supported.")

        tail_segments = segments[3:]
        if kind == "blob":
            resolved = await self._resolve_blob_segments(owner, repo, tail_segments)
            if _path_suffix(resolved) not in MARKDOWN_SUFFIXES:
                raise InvalidGitHubUrl("Input URL must point to a markdown document or a folder.")
            return resolved

        resolved = await self._resolve_tree_segments(owner, repo, tail_segments)
        if resolved is None:
            raise DocumentNotFound("Could not resolve SKILL.md or README.md from the provided tree URL.")
        return resolved

    async def fetch_graph(
        self,
        input_url: str,
        max_depth: int = 2,
        max_docs: int = 30,
        max_total_chars: int = 500000,
    ) -> FetchGraphContext:
        root_doc_url = await self.resolve_root_doc_url(input_url)
        queue: deque[tuple[str, int, str, str | None]] = deque([(root_doc_url, 0, "root", None)])
        queued = {root_doc_url}
        visited: set[str] = set()
        documents: list[DocumentContext] = []
        edge_candidates: list[FetchedEdge] = []
        total_chars = 0
        max_depth_reached = 0

        while queue and len(documents) < max_docs:
            current_url, depth, reason, parent_url = queue.popleft()
            queued.discard(current_url)
            if current_url in visited:
                if parent_url is not None:
                    edge_candidates.append(FetchedEdge(from_=parent_url, to=current_url, reason=reason))
                continue

            document = await self._fetch_document(current_url, depth)
            projected_total = total_chars + len(document.text)
            if projected_total > max_total_chars:
                if not documents:
                    raise FetchLimitExceeded("The root document exceeds max_total_chars.")
                break

            documents.append(document)
            visited.add(current_url)
            total_chars = projected_total
            max_depth_reached = max(max_depth_reached, depth)

            if parent_url is not None:
                edge_candidates.append(FetchedEdge(from_=parent_url, to=current_url, reason=reason))

            if depth >= max_depth:
                continue

            for child_url, child_reason in await self._discover_children(document):
                if child_url in visited or child_url in queued:
                    if child_url in visited:
                        edge_candidates.append(FetchedEdge(from_=document.meta.url, to=child_url, reason=child_reason))
                    continue
                if len(documents) + len(queue) >= max_docs:
                    continue
                queue.append((child_url, depth + 1, child_reason, document.meta.url))
                queued.add(child_url)

        fetched_urls = {document.meta.url for document in documents}
        deduped_edges: list[FetchedEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        for edge in edge_candidates:
            key = (edge.from_, edge.to, edge.reason)
            if edge.from_ in fetched_urls and edge.to in fetched_urls and key not in seen_edges:
                deduped_edges.append(edge)
                seen_edges.add(key)

        return FetchGraphContext(
            root_doc_url=root_doc_url,
            docs=documents,
            edges=deduped_edges,
            max_depth_reached=max_depth_reached,
        )

    async def _discover_children(self, document: DocumentContext) -> list[tuple[str, str]]:
        children: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        for link in document.parsed.links:
            normalized = self._normalize_link(document.meta.url, document.repo_key, link)
            if normalized is None:
                continue
            child = normalized
            if child not in seen:
                children.append(child)
                seen.add(child)

        for dependency in extract_skill_dependencies(document.text):
            resolved = await self._resolve_skill_dependency(dependency)
            if resolved is None:
                continue
            child = (resolved, "skill-dependency")
            if child not in seen:
                children.append(child)
                seen.add(child)

        return children

    async def _resolve_skill_dependency(self, dependency: SkillDependency) -> str | None:
        for candidate in dependency_candidate_urls(dependency.owner, dependency.repo, dependency.skill_name):
            if await self._url_exists(candidate):
                return candidate
        return None

    async def _resolve_blob_segments(self, owner: str, repo: str, tail_segments: list[str]) -> str:
        for split_index in range(1, len(tail_segments)):
            ref = "/".join(tail_segments[:split_index])
            path = "/".join(tail_segments[split_index:])
            if not path:
                continue
            raw_url = GitHubLocation(host_kind="blob", owner=owner, repo=repo, ref=ref, path=path).raw_url
            if await self._url_exists(raw_url):
                return raw_url
        raise DocumentNotFound("Could not resolve the provided GitHub blob URL to a raw document.")

    async def _resolve_tree_segments(self, owner: str, repo: str, tail_segments: list[str]) -> str | None:
        for split_index in range(1, len(tail_segments) + 1):
            ref = "/".join(tail_segments[:split_index])
            path = "/".join(tail_segments[split_index:])
            base = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}"
            if path:
                base = f"{base}/{path}"
            for filename in ("SKILL.md", "README.md"):
                candidate = f"{base}/{filename}"
                if await self._url_exists(candidate):
                    return candidate
        return None

    async def _url_exists(self, url: str) -> bool:
        normalized = _strip_fragment_and_query(url)
        cached = self._existence_cache.get(normalized)
        if cached is not None:
            return cached

        try:
            await self._probe_exists(normalized)
        except DocumentNotFound:
            self._existence_cache[normalized] = False
            return False

        self._existence_cache[normalized] = True
        return True

    async def _fetch_document(self, url: str, depth: int) -> DocumentContext:
        text, content_type = await self._fetch_text(url)
        suffix = _path_suffix(url)
        is_markdown = suffix in MARKDOWN_SUFFIXES or "markdown" in content_type
        parsed = parse_markdown(text) if is_markdown else ParsedMarkdown()
        title = parsed.title or PurePosixPath(urlsplit(url).path).name
        location = parse_github_location(url)
        sha_like = location.ref if SHA_LIKE_RE.match(location.ref) else None
        meta = FetchedDoc(
            url=url,
            title=title,
            content_type=content_type,
            char_count=len(text),
            depth=depth,
            sha_like=sha_like,
        )
        return DocumentContext(meta=meta, text=text, parsed=parsed, repo_key=location.repo_key)

    async def _fetch_text(self, url: str) -> tuple[str, str]:
        normalized = _strip_fragment_and_query(url)
        cached = self._content_cache.get(normalized)
        if cached is not None:
            return cached

        response = await self._request("GET", normalized, headers={"Accept": "text/plain, text/markdown;q=0.9, */*;q=0.1"})
        if response.status_code == 404:
            raise DocumentNotFound(f"Document not found: {normalized}")
        if response.status_code >= 400:
            raise UpstreamFetchError(f"GitHub returned HTTP {response.status_code} for {normalized}.")

        content_type = response.headers.get("content-type", "text/plain").split(";")[0].strip().lower()
        text = response.text
        self._content_cache[normalized] = (text, content_type)
        self._existence_cache[normalized] = True
        return text, content_type

    async def _probe_exists(self, url: str) -> None:
        response = await self._request("HEAD", url)
        if response.status_code == 405:
            response = await self._request("GET", url, headers={"Range": "bytes=0-0"})
        if response.status_code == 404:
            raise DocumentNotFound(f"Document not found: {url}")
        if response.status_code >= 400:
            raise UpstreamFetchError(f"GitHub returned HTTP {response.status_code} for {url}.")

    async def _request(self, method: str, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
            self._owns_client = True

        assert self._client is not None
        try:
            response = await self._client.request(method, url, headers=headers)
        except httpx.TimeoutException as exc:
            raise UpstreamFetchError(f"Timed out while fetching {url}.") from exc
        except httpx.RequestError as exc:
            raise UpstreamFetchError(f"Failed to fetch {url}: {exc}.") from exc

        if response.status_code in {403, 429}:
            text = response.text.lower()
            if response.status_code == 429 or "rate limit" in text or response.headers.get("x-ratelimit-remaining") == "0":
                raise UpstreamRateLimited("GitHub rate limit reached while fetching documents.")

        return response

    def _normalize_link(self, base_url: str, current_repo_key: str | None, link: LinkInfo) -> tuple[str, str] | None:
        try:
            normalized = resolve_relative_link(base_url, link.url)
        except InvalidGitHubUrl:
            return None

        if normalized is None:
            return None

        try:
            target = parse_github_location(normalized)
        except InvalidGitHubUrl:
            return None

        suffix = PurePosixPath(target.path).suffix.lower()
        same_repo = current_repo_key == target.repo_key if current_repo_key else False

        if same_repo and suffix in MARKDOWN_SUFFIXES:
            return normalized, "markdown-link"
        if same_repo and suffix in CONFIG_SUFFIXES:
            return normalized, "config-link"
        return None
