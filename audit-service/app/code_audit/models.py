from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


CodeFileContext = Literal["server", "mcp", "cli", "ci", "library"]


@dataclass(frozen=True, slots=True)
class GitHubCodeTarget:
    owner: str
    repo: str
    ref: str
    path: str
    target_kind: str

    @property
    def repo_key(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def root_target(self) -> str:
        base = f"{self.owner}/{self.repo}@{self.ref}"
        return f"{base}:{self.path}" if self.path else base


@dataclass(frozen=True, slots=True)
class RepositoryEntry:
    path: str
    type: str
    download_url: str | None = None


@dataclass(frozen=True, slots=True)
class ScannedCodeFile:
    path: str
    url: str
    language: str | None
    text: str
    context: CodeFileContext

    @property
    def char_count(self) -> int:
        return len(self.text)


@dataclass(frozen=True, slots=True)
class CodeAnalysisResult:
    capabilities: list[str]
    findings: list[object]
