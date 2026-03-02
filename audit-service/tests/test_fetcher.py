from __future__ import annotations

import pytest

from app.fetcher import (
    DocumentNotFound,
    GitHubDocFetcher,
    blob_to_raw_url,
    dependency_candidate_urls,
    extract_skill_dependencies,
    resolve_relative_link,
)


class StubFetcher(GitHubDocFetcher):
    def __init__(self, documents: dict[str, tuple[str, str]], existing: set[str] | None = None):
        super().__init__(timeout=0.1)
        self.documents = documents
        self.existing = existing if existing is not None else set(documents)

    async def _url_exists(self, url: str) -> bool:
        return url in self.existing

    async def _fetch_text(self, url: str) -> tuple[str, str]:
        if url not in self.documents:
            raise DocumentNotFound(f"Missing test document: {url}")
        return self.documents[url]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("existing", "expected"),
    [
        (
            {"https://raw.githubusercontent.com/acme/skills/main/demo/SKILL.md"},
            "https://raw.githubusercontent.com/acme/skills/main/demo/SKILL.md",
        ),
        (
            {"https://raw.githubusercontent.com/acme/skills/main/demo/README.md"},
            "https://raw.githubusercontent.com/acme/skills/main/demo/README.md",
        ),
    ],
)
async def test_tree_url_resolves_skill_then_readme(existing: set[str], expected: str) -> None:
    fetcher = StubFetcher(documents={}, existing=existing)
    resolved = await fetcher.resolve_root_doc_url("https://github.com/acme/skills/tree/main/demo")
    assert resolved == expected


def test_blob_url_converts_to_raw_url() -> None:
    raw_url = blob_to_raw_url("https://github.com/acme/skills/blob/main/demo/SKILL.md")
    assert raw_url == "https://raw.githubusercontent.com/acme/skills/main/demo/SKILL.md"


def test_relative_link_resolution_uses_raw_base_path() -> None:
    resolved = resolve_relative_link(
        "https://raw.githubusercontent.com/acme/skills/main/demo/docs/SKILL.md",
        "../shared/README.md#usage",
    )
    assert resolved == "https://raw.githubusercontent.com/acme/skills/main/demo/shared/README.md"


def test_extracts_skill_dependency_reference() -> None:
    dependencies = extract_skill_dependencies("Run `npx skills add inference-sh/skills@chat-ui` to install it.")
    assert len(dependencies) == 1
    assert dependencies[0].owner == "inference-sh"
    assert dependencies[0].repo == "skills"
    assert dependencies[0].skill_name == "chat-ui"


def test_skill_dependency_resolves_to_expected_raw_urls() -> None:
    assert dependency_candidate_urls("inference-sh", "skills", "chat-ui") == [
        "https://raw.githubusercontent.com/inference-sh/skills/main/skills/chat-ui/SKILL.md",
        "https://raw.githubusercontent.com/inference-sh/skills/main/skills/chat-ui/README.md",
    ]


@pytest.mark.asyncio
async def test_fetch_graph_respects_max_docs_limit() -> None:
    root = "https://raw.githubusercontent.com/acme/skills/main/demo/SKILL.md"
    a_doc = "https://raw.githubusercontent.com/acme/skills/main/demo/a.md"
    b_doc = "https://raw.githubusercontent.com/acme/skills/main/demo/b.md"
    c_doc = "https://raw.githubusercontent.com/acme/skills/main/demo/c.md"
    d_doc = "https://raw.githubusercontent.com/acme/skills/main/demo/d.md"

    fetcher = StubFetcher(
        documents={
            root: ("# Demo\n\n[a](a.md)\n[b](b.md)\n[c](c.md)\n[d](d.md)\n", "text/markdown"),
            a_doc: ("# A\n", "text/markdown"),
            b_doc: ("# B\n", "text/markdown"),
            c_doc: ("# C\n", "text/markdown"),
            d_doc: ("# D\n", "text/markdown"),
        }
    )

    graph = await fetcher.fetch_graph(root, max_depth=2, max_docs=3, max_total_chars=5000)
    fetched_urls = [document.meta.url for document in graph.docs]

    assert fetched_urls == [root, a_doc, b_doc]
    assert len(graph.docs) == 3
    assert {(edge.from_, edge.to) for edge in graph.edges} == {(root, a_doc), (root, b_doc)}
