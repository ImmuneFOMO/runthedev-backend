from __future__ import annotations

from pathlib import PurePosixPath

from .models import CodeFileContext, RepositoryEntry
from .patterns import (
    CODE_EXTENSIONS,
    CI_CONTEXT_RE,
    CI_PATH_RE,
    CONFIG_EXTENSIONS,
    CLI_CONTEXT_RE,
    ENTRYPOINT_HINT_RE,
    IGNORED_DIRS,
    MCP_CONFIG_RE,
    MCP_CONTEXT_RE,
    MCP_CONTEXT_PATH_RE,
    MCP_REPO_HINT_RE,
    NOISE_DIRS,
    NOISE_FILE_HINT_RE,
    PRIORITY_SEGMENT_RE,
    SERVER_CONTEXT_RE,
    SCRIPT_HINT_RE,
    TEMPLATE_HINT_RE,
    TEST_HINT_RE,
    WORKFLOW_YAML_RE,
)


LANGUAGE_MAP = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
}


def is_ignored_dir(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(part in IGNORED_DIRS for part in parts)


def is_noise_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(part in NOISE_DIRS for part in parts):
        return True
    if NOISE_FILE_HINT_RE.search(path):
        return True
    return False


def is_test_file(path: str) -> bool:
    return TEST_HINT_RE.search(path) is not None


def is_ci_file(path: str) -> bool:
    return CI_PATH_RE.search(path) is not None or WORKFLOW_YAML_RE.search(path) is not None


def is_script_file(path: str) -> bool:
    return SCRIPT_HINT_RE.search(path) is not None


def supported_file(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in CODE_EXTENSIONS


def language_for_path(path: str) -> str | None:
    return LANGUAGE_MAP.get(PurePosixPath(path).suffix.lower())


def classify_file_context(path: str, text: str) -> CodeFileContext:
    if is_ci_file(path) or CI_CONTEXT_RE.search(text):
        return "ci"
    if SERVER_CONTEXT_RE.search(text):
        return "server"
    if MCP_CONFIG_RE.search(path) or MCP_CONTEXT_RE.search(text) or MCP_CONTEXT_PATH_RE.search(path):
        return "mcp"
    if CLI_CONTEXT_RE.search(text) or is_script_file(path):
        return "cli"
    return "library"


def score_entry(path: str) -> tuple[int, str]:
    score = 0
    suffix = PurePosixPath(path).suffix.lower()
    if ENTRYPOINT_HINT_RE.search(PurePosixPath(path).name):
        score += 50
    if PRIORITY_SEGMENT_RE.search(path):
        score += 20
    if MCP_REPO_HINT_RE.search(path):
        score += 20
    if MCP_CONFIG_RE.search(path):
        score += 45
    if SCRIPT_HINT_RE.search(path):
        score += 8
    if TEMPLATE_HINT_RE.search(path):
        score -= 20
    if suffix in {".py", ".ts", ".js", ".tsx"}:
        score += 15
    if suffix in CONFIG_EXTENSIONS:
        score += 5
    if PurePosixPath(path).name.startswith("."):
        score += 4
    score -= path.count("/") * 2
    return (-score, path)


def select_relevant_files(
    entries: list[RepositoryEntry],
    max_files: int,
    include_tests: bool,
    include_ci: bool = False,
) -> list[RepositoryEntry]:
    filtered: list[RepositoryEntry] = []
    for entry in entries:
        if entry.type != "file":
            continue
        if is_ignored_dir(entry.path) or not supported_file(entry.path):
            continue
        if is_noise_path(entry.path):
            continue
        if not include_tests and is_test_file(entry.path):
            continue
        if not include_ci and is_ci_file(entry.path):
            continue
        filtered.append(entry)
    filtered.sort(key=lambda item: score_entry(item.path))
    return filtered[:max_files]
