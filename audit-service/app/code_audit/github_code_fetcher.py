from __future__ import annotations

import os
from urllib.parse import urlsplit

import httpx

from app.fetcher import AuditServiceError, DocumentNotFound, InvalidGitHubUrl, UpstreamFetchError, UpstreamRateLimited

from .file_selector import classify_file_context, language_for_path, select_relevant_files
from .models import GitHubCodeTarget, RepositoryEntry, ScannedCodeFile


DEFAULT_TIMEOUT = 10.0


class GitHubCodeFetcher:
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
        github_token: str | None = None,
    ):
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None
        self.github_token = github_token if github_token is not None else os.getenv("GITHUB_TOKEN")
        self._raw_text_cache: dict[str, str] = {}

    async def __aenter__(self) -> "GitHubCodeFetcher":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def resolve_target(self, url: str) -> GitHubCodeTarget:
        parts = urlsplit(url)
        if parts.netloc.lower() != "github.com":
            raise InvalidGitHubUrl("Only github.com repo, tree, and blob URLs are supported for code audit.")

        segments = [segment for segment in parts.path.split("/") if segment]
        if len(segments) < 2:
            raise InvalidGitHubUrl("GitHub URL must include owner and repo.")

        owner, repo = segments[:2]
        if len(segments) == 2:
            return GitHubCodeTarget(owner=owner, repo=repo, ref=await self._default_branch(owner, repo), path="", target_kind="repo")

        kind = segments[2]
        if kind not in {"blob", "tree"}:
            raise InvalidGitHubUrl("Supported GitHub code URLs are repo, tree, and blob URLs.")
        if len(segments) < 4:
            raise InvalidGitHubUrl("GitHub tree/blob URLs must include a ref.")

        tail_segments = segments[3:]
        if kind == "blob":
            ref, path = await self._split_blob_ref_and_path(owner, repo, tail_segments)
        else:
            ref, path = await self._split_ref_and_path(owner, repo, tail_segments)
        return GitHubCodeTarget(owner=owner, repo=repo, ref=ref, path=path, target_kind=kind)

    async def fetch_code_files(
        self,
        url: str,
        *,
        max_files: int,
        max_total_chars: int,
        include_tests: bool,
        include_ci: bool,
    ) -> tuple[GitHubCodeTarget, list[ScannedCodeFile]]:
        target = await self.resolve_target(url)
        if target.target_kind == "blob":
            files = await self._fetch_blob_target(target, max_total_chars=max_total_chars)
            return target, files

        entries = await self._collect_entries(target)
        selected = select_relevant_files(
            entries,
            max_files=max_files,
            include_tests=include_tests,
            include_ci=include_ci,
        )
        files: list[ScannedCodeFile] = []
        total_chars = 0
        for entry in selected:
            text = await self._fetch_raw_text(target, entry.path)
            if total_chars + len(text) > max_total_chars:
                if not files:
                    raise AuditServiceError("The first selected code file exceeds max_total_chars.")
                break
            files.append(
                ScannedCodeFile(
                    path=entry.path,
                    url=self._raw_url(target, entry.path),
                    language=language_for_path(entry.path),
                    text=text,
                    context=classify_file_context(entry.path, text),
                )
            )
            total_chars += len(text)
        return target, files

    async def _fetch_blob_target(self, target: GitHubCodeTarget, *, max_total_chars: int) -> list[ScannedCodeFile]:
        text = await self._fetch_raw_text(target, target.path)
        if len(text) > max_total_chars:
            raise AuditServiceError("The selected code file exceeds max_total_chars.")
        return [
            ScannedCodeFile(
                path=target.path,
                url=self._raw_url(target, target.path),
                language=language_for_path(target.path),
                text=text,
                context=classify_file_context(target.path, text),
            )
        ]

    async def _collect_entries(self, target: GitHubCodeTarget) -> list[RepositoryEntry]:
        stack = [target.path]
        files: list[RepositoryEntry] = []

        while stack:
            path = stack.pop()
            items = await self._contents(target.owner, target.repo, target.ref, path)
            if isinstance(items, dict):
                items = [items]
            items = sorted(items, key=lambda item: item["path"])
            for item in items:
                item_type = item.get("type")
                item_path = item.get("path", "")
                if item_type == "dir":
                    stack.append(item_path)
                elif item_type == "file":
                    files.append(RepositoryEntry(path=item_path, type="file", download_url=item.get("download_url")))
        return files

    async def _contents(self, owner: str, repo: str, ref: str, path: str) -> object:
        client = self._client
        assert client is not None
        endpoint = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        response = await client.get(endpoint, params={"ref": ref}, headers=self._api_headers())
        self._raise_for_api_error(response, f"GitHub path not found: {owner}/{repo}:{path}", "listing repository contents")
        return response.json()

    async def _fetch_raw_text(self, target: GitHubCodeTarget, path: str) -> str:
        raw_url = self._raw_url(target, path)
        cached = self._raw_text_cache.get(raw_url)
        if cached is not None:
            return cached
        client = self._client
        assert client is not None
        raw_response = await client.get(raw_url, headers=self._raw_headers())
        self._raise_for_raw_error(raw_response, f"File not found: {target.owner}/{target.repo}:{path}")
        self._raw_text_cache[raw_url] = raw_response.text
        return raw_response.text

    async def _default_branch(self, owner: str, repo: str) -> str:
        client = self._client
        assert client is not None
        response = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=self._api_headers())
        self._raise_for_api_error(response, "GitHub repository not found.", "fetching repository metadata")
        default_branch = response.json().get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise UpstreamFetchError("GitHub repository metadata did not include a default branch.")
        return default_branch

    async def _split_ref_and_path(self, owner: str, repo: str, tail_segments: list[str]) -> tuple[str, str]:
        for split_index in range(1, len(tail_segments) + 1):
            ref = "/".join(tail_segments[:split_index])
            path = "/".join(tail_segments[split_index:])
            try:
                await self._contents(owner, repo, ref, path)
            except DocumentNotFound:
                continue
            return ref, path
        raise DocumentNotFound("Could not resolve the requested GitHub ref/path for code audit.")

    async def _split_blob_ref_and_path(self, owner: str, repo: str, tail_segments: list[str]) -> tuple[str, str]:
        client = self._client
        assert client is not None
        for split_index in range(1, len(tail_segments)):
            ref = "/".join(tail_segments[:split_index])
            path = "/".join(tail_segments[split_index:])
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
            response = await client.get(raw_url, headers=self._raw_headers())
            if response.status_code == 404:
                continue
            self._raise_for_raw_error(response, f"File not found: {owner}/{repo}:{path}")
            self._raw_text_cache[raw_url] = response.text
            return ref, path
        raise DocumentNotFound("Could not resolve the requested GitHub blob ref/path for code audit.")

    def _raw_url(self, target: GitHubCodeTarget, path: str) -> str:
        suffix = f"/{path}" if path else ""
        return f"https://raw.githubusercontent.com/{target.owner}/{target.repo}/{target.ref}{suffix}"

    def _api_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "mcp-sentinel-code-audit",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _raw_headers(self) -> dict[str, str]:
        headers = {"User-Agent": "mcp-sentinel-code-audit"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _raise_for_api_error(self, response: httpx.Response, not_found_detail: str, action: str) -> None:
        if response.status_code == 404:
            raise DocumentNotFound(not_found_detail)
        if response.status_code == 429 or response.status_code == 403:
            raise UpstreamRateLimited("GitHub API rate limited the code audit request.")
        if response.status_code >= 400:
            raise UpstreamFetchError(f"GitHub API returned {response.status_code} while {action}.")

    def _raise_for_raw_error(self, response: httpx.Response, not_found_detail: str) -> None:
        if response.status_code == 404:
            raise DocumentNotFound(not_found_detail)
        if response.status_code == 429 or response.status_code == 403:
            raise UpstreamRateLimited("GitHub raw content rate limited the code audit request.")
        if response.status_code >= 400:
            raise UpstreamFetchError(f"GitHub raw content returned {response.status_code} while fetching file contents.")
