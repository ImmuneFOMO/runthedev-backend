from __future__ import annotations

from collections import defaultdict
import re

from app.models import CodeFinding, Summary, SummaryCounts

from .models import ScannedCodeFile


SEVERITY_POINTS = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 3,
    "info": 0,
}

FILE_ACCESS_RULES = {
    "arbitrary-file-read",
    "arbitrary-file-write",
    "arbitrary-file-delete",
}
SUPPORTED_RULES = {
    "ssrf-fetch",
    "open-proxy-endpoint",
    "command-execution",
    "arbitrary-file-read",
    "arbitrary-file-write",
    "arbitrary-file-delete",
    "path-traversal",
    "auth-missing-on-network-service",
    "unsafe-docker-runtime",
    "hardcoded-secret",
}
OUT_OF_SCOPE_NOTES = [
    "No full SAST/AST/CFG",
    "No interprocedural taint analysis",
    "No dependency vuln scanning",
    "Auth detection is heuristic/nearby-text",
    "Coverage is limited to supported_rules",
]


def build_code_summary(findings: list[CodeFinding], capabilities: list[str], files: list[ScannedCodeFile]) -> tuple[Summary, list[str]]:
    counts = SummaryCounts()
    raw_counts = SummaryCounts()
    total = 0.0
    grouped: dict[str, int] = defaultdict(int)
    grouped_counts: dict[str, int] = defaultdict(int)
    context_by_path = {file.path: file.context for file in files}

    for finding in findings:
        if finding.severity == "critical":
            raw_counts.critical += 1
        elif finding.severity == "high":
            raw_counts.high += 1
        elif finding.severity == "medium":
            raw_counts.medium += 1
        elif finding.severity == "low":
            raw_counts.low += 1

        if finding.cluster_role == "duplicate":
            continue
        if finding.rule_id not in SUPPORTED_RULES:
            continue

        effective_severity = _effective_severity_for_scoring(finding)
        points = _weighted_points(finding, context_by_path.get(finding.evidence.file_path, "library"), effective_severity)
        total += points
        grouped[finding.title] += points
        if points:
            grouped_counts[finding.title] += 1
        if effective_severity == "critical":
            counts.critical += 1
        elif effective_severity == "high":
            counts.high += 1
        elif effective_severity == "medium":
            counts.medium += 1
        elif effective_severity == "low":
            counts.low += 1

    capability_bonus = min(10, 2 * len(set(capabilities)))
    total += capability_bonus
    if capability_bonus:
        grouped["Dangerous code capabilities"] += capability_bonus
        grouped_counts["Dangerous code capabilities"] = len(set(capabilities))

    ordered = sorted(grouped.items(), key=lambda item: (-item[1], item[0]))
    drivers: list[str] = []
    for title, score in ordered[:3]:
        count = grouped_counts.get(title, 1)
        if count > 1 and title != "Dangerous code capabilities":
            drivers.append(f"{score} pts: {title} across {count} clusters")
        elif title == "Dangerous code capabilities":
            drivers.append(f"{score} pts: {count} dangerous capabilities")
        else:
            drivers.append(f"{score} pts: {title}")

    return Summary(risk_score=max(0, min(int(round(total)), 100)), counts=counts, raw_counts=raw_counts), drivers


def filter_supported_findings(findings: list[CodeFinding]) -> list[CodeFinding]:
    return [finding for finding in findings if finding.rule_id in SUPPORTED_RULES]


def _weighted_points(finding: CodeFinding, context: str, severity: str) -> int:
    points = SEVERITY_POINTS[severity]
    if context not in {"ci", "cli"}:
        return points
    if _sensitive_or_destructive(finding):
        return points
    if points == 0:
        return 0
    return max(1, int(points * 0.25))


def _effective_severity_for_scoring(finding: CodeFinding) -> str:
    severity = finding.severity
    if finding.ai_risk in {"critical", "high", "medium", "low"}:
        severity = finding.ai_risk
    if finding.rule_id == "ssrf-fetch" and _fixed_host_network_wrapper(finding):
        severity = "low"
    return severity


def _fixed_host_network_wrapper(finding: CodeFinding) -> bool:
    text = f"{finding.evidence.snippet}\n{finding.nearby_context or ''}"
    if re.search(
        r"https://(?:slack\.com/api|api\.github\.com|gitlab\.com/api/v4|maps\.googleapis\.com|api\.search\.brave\.com)",
        text,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\b(?:GITHUB_API_URL|GITLAB_API_URL|GOOGLE_MAPS_API_KEY|BRAVE_API_KEY)\b", text):
        return True
    if re.search(r"Authorization:\s*`token|Authorization:\s*`Bearer|botHeaders|searchParams\.append", text, re.IGNORECASE):
        return True
    return False


def _sensitive_or_destructive(finding: CodeFinding) -> bool:
    if finding.rule_id in {"hardcoded-secret", "unsafe-docker-runtime"}:
        return True
    haystack = f"{finding.description}\n{finding.evidence.snippet}"
    return re.search(r"/etc|~/.ssh|\.git\b|chmod|chown|rmtree|unlink|remove|delete|rm\s+-|\.\.", haystack, re.IGNORECASE) is not None
