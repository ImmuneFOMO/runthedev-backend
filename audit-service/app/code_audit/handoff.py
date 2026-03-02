from __future__ import annotations

from collections import defaultdict
import re

from app.models import (
    CodeAIHandoff,
    CodeAIHandoffItem,
    CodeAIHandoffStats,
    CodeAITaintSummary,
    CodeFinding,
)
from .scoring import SUPPORTED_RULES


RULE_PRIORITY = {
    "ssrf-fetch": 0,
    "open-proxy-endpoint": 1,
    "command-execution": 2,
    "prompt-injection-sensitive-wiring": 3,
    "path-traversal": 4,
    "arbitrary-file-read": 5,
    "arbitrary-file-write": 6,
    "arbitrary-file-delete": 7,
    "unsafe-docker-runtime": 8,
    "hardcoded-secret": 9,
    "auth-missing-on-network-service": 10,
}
CONTEXT_PRIORITY = {"mcp": 0, "server": 1, "cli": 2, "library": 3, "unknown": 4}
PATH_AREA_PRIORITY = {"none": 0, "scripts": 1, "tools": 2, "examples": 3, "experiments": 4}
SEVERITY_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
GUARD_PATTERNS = {
    "allowlist": re.compile(r"allowlist|whitelist|trusted_hosts|trusted_domains", re.IGNORECASE),
    "auth": re.compile(r"auth|authorization|api[_-]?key|bearer|jwt|oauth|depends\(", re.IGNORECASE),
    "approval": re.compile(r"approve|approval|permit|authorize", re.IGNORECASE),
    "private_ip_block": re.compile(r"rfc1918|169\.254\.169\.254|127\.0\.0\.1|localhost|private ip", re.IGNORECASE),
    "fixed_host": re.compile(r"https://(?:api\.github\.com|slack\.com/api|maps\.googleapis\.com|api\.search\.brave\.com)|baseURL\s*:\s*[\"']https://", re.IGNORECASE),
}
PATH_CONTAINMENT_GUARD_RE = re.compile(r"is_relative_to|commonpath|startswith\s*\(", re.IGNORECASE)


def build_ai_handoff(findings: list[CodeFinding], capabilities: list[str], *, max_items: int) -> CodeAIHandoff:
    grouped: dict[str, list[CodeFinding]] = defaultdict(list)
    for finding in findings:
        if finding.cluster_role != "primary":
            continue
        if finding.rule_id not in SUPPORTED_RULES:
            continue
        cluster_id = finding.cluster_id or f"{finding.rule_id}:{finding.evidence.file_path}:{finding.evidence.line or 0}"
        grouped[cluster_id].append(finding)

    primary_findings = [cluster_findings[0] for cluster_findings in grouped.values()]
    ordered = sorted(primary_findings, key=_handoff_sort_key)
    selected = ordered[:max_items]
    dropped = ordered[max_items:]

    items = [
        _build_item(primary, grouped[primary.cluster_id or ""], capabilities)
        for primary in selected
    ]

    dropped_by_rule: dict[str, int] = defaultdict(int)
    for finding in dropped:
        dropped_by_rule[finding.rule_id] += 1

    return CodeAIHandoff(
        version="handoff-v1",
        max_items=max_items,
        items=items,
        stats=CodeAIHandoffStats(
            total_findings=len(findings),
            total_clusters=len(grouped),
            selected_clusters=len(items),
            dropped_total=len(dropped),
            dropped_by_rule=dict(sorted(dropped_by_rule.items())),
        ),
    )


def _handoff_sort_key(finding: CodeFinding) -> tuple[int, int, int, int, str, int]:
    path_area = _path_area(finding.evidence.file_path)
    return (
        -SEVERITY_PRIORITY.get(finding.severity, 0),
        RULE_PRIORITY.get(finding.rule_id, 99),
        CONTEXT_PRIORITY.get(finding.context or "unknown", 4),
        PATH_AREA_PRIORITY.get(path_area, 0),
        -(finding.cluster_size or 1),
        finding.evidence.file_path,
        finding.evidence.line or 0,
    )


def _build_item(primary: CodeFinding, cluster_findings: list[CodeFinding], capabilities: list[str]) -> CodeAIHandoffItem:
    context = primary.context if primary.context in {"mcp", "server", "cli", "library"} else "unknown"
    nearby_context = (primary.nearby_context or "")[:900]
    taint_summary = cluster_taint_summary(primary, nearby_context)

    return CodeAIHandoffItem(
        cluster_id=primary.cluster_id or f"{primary.rule_id}:{primary.evidence.file_path}",
        rule_id=primary.rule_id,
        deterministic_severity=primary.severity,  # type: ignore[arg-type]
        context=context,  # type: ignore[arg-type]
        file_path=primary.evidence.file_path,
        primary_line=primary.evidence.line or 0,
        primary_snippet=primary.evidence.snippet[:220],
        nearby_context=nearby_context,
        taint_summary=taint_summary,
        cluster_size=primary.cluster_size or len(cluster_findings),
    )


def cluster_taint_summary(primary: CodeFinding, nearby_context: str) -> CodeAITaintSummary:
    text = f"{primary.evidence.snippet}\n{nearby_context}"
    path_area = _path_area(primary.evidence.file_path)
    if re.search(r"model_output|llm_output|completion|message\.content", text, re.IGNORECASE):
        source = "model_output"
    elif re.search(r"os\.environ|getenv|process\.env|env\[[\"']", text, re.IGNORECASE):
        source = "env"
    elif re.search(r"\.(?:json|ya?ml|toml)\b|mcp\.json|config\b", text, re.IGNORECASE):
        source = "config"
    elif re.search(r"request\.|req\.|payload|query|params|body|tool_input|tool_args|ctx\.arguments", text, re.IGNORECASE):
        source = "user_input"
    else:
        source = "unknown"

    if primary.rule_id in {"command-execution", "prompt-injection-sensitive-wiring"}:
        sink = "shell"
    elif primary.rule_id in {"ssrf-fetch", "open-proxy-endpoint", "auth-missing-on-network-service"}:
        sink = "network"
    elif primary.rule_id in {"arbitrary-file-read", "arbitrary-file-write", "arbitrary-file-delete", "path-traversal"}:
        sink = "filesystem"
    elif primary.rule_id == "unsafe-docker-runtime":
        sink = "docker"
    else:
        sink = "unknown"

    guards_seen = [name for name, pattern in GUARD_PATTERNS.items() if pattern.search(text)]
    if re.search(r"resolve\(|normalize\(|realpath", text, re.IGNORECASE) and PATH_CONTAINMENT_GUARD_RE.search(text):
        guards_seen.append("normalize_path")
    marker_exposed = re.search(r"@app\.|router\.|app\.listen|uvicorn\.run|serveSSE|fetch\(request", text, re.IGNORECASE) is not None
    is_probably_exposed = bool((primary.context in {"mcp", "server"} and path_area == "none") or marker_exposed)
    return CodeAITaintSummary(
        source=source,  # type: ignore[arg-type]
        sink=sink,  # type: ignore[arg-type]
        is_probably_exposed=is_probably_exposed,
        guards_seen=sorted(set(guards_seen)),
        path_area=path_area,  # type: ignore[arg-type]
    )


def _path_area(file_path: str) -> str:
    lowered = file_path.lower()
    if "/experiments/" in lowered or lowered.startswith("experiments/"):
        return "experiments"
    if "/examples/" in lowered or lowered.startswith("examples/"):
        return "examples"
    if "/tools/" in lowered or lowered.startswith("tools/"):
        return "tools"
    if "/scripts/" in lowered or lowered.startswith("scripts/"):
        return "scripts"
    return "none"


def cluster_capabilities(primary: CodeFinding, capabilities: list[str]) -> list[str]:
    relevant: set[str] = set()
    if primary.rule_id in {"ssrf-fetch", "open-proxy-endpoint", "auth-missing-on-network-service"}:
        relevant.add("network")
    if primary.rule_id in {"arbitrary-file-read", "arbitrary-file-write", "arbitrary-file-delete", "path-traversal"}:
        relevant.add("filesystem")
    if primary.rule_id in {"command-execution", "prompt-injection-sensitive-wiring"}:
        relevant.add("shell")
    if primary.rule_id == "unsafe-docker-runtime":
        relevant.add("docker")
    return [cap for cap in capabilities if cap in relevant]
