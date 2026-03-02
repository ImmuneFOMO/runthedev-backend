from __future__ import annotations

from collections import defaultdict

from app.models import (
    CodeAIExampleLocation,
    CodeAITriageResult,
    CodeCluster,
    CodeClusterAI,
    CodeClusterFinal,
    CodeClusterGroups,
    CodeFinding,
)

from .handoff import cluster_capabilities, cluster_taint_summary


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONTEXT_RANK = {"mcp": 0, "server": 1, "cli": 2, "library": 3, "unknown": 4}


def build_cluster_groups(
    findings: list[CodeFinding],
    capabilities: list[str],
    ai_results: list[CodeAITriageResult] | None = None,
) -> CodeClusterGroups:
    grouped: dict[str, list[CodeFinding]] = defaultdict(list)
    for finding in findings:
        cluster_id = finding.cluster_id or f"{finding.rule_id}:{finding.evidence.file_path}:{finding.evidence.line or 0}"
        grouped[cluster_id].append(finding)

    ai_by_cluster = {item.cluster_id: item for item in (ai_results or [])}
    primary: list[CodeCluster] = []
    suppressed: list[CodeCluster] = []
    debug_duplicates: list[CodeCluster] = []

    for cluster_id, cluster_findings in sorted(grouped.items()):
        best = _select_primary(cluster_findings)
        duplicate_findings = [finding for finding in cluster_findings if finding is not best]
        cluster = _build_cluster(best, cluster_findings, capabilities, ai_by_cluster.get(cluster_id))
        if cluster.final.kept:
            primary.append(cluster)
        else:
            suppressed.append(cluster)
        for duplicate in duplicate_findings:
            debug_duplicates.append(_build_cluster(duplicate, cluster_findings, capabilities, ai_by_cluster.get(cluster_id)))

    return CodeClusterGroups(
        primary=primary,
        suppressed=suppressed,
        debug_duplicates=debug_duplicates,
        stats={
            "total_clusters": len(grouped),
            "primary_clusters": len(primary),
            "suppressed_clusters": len(suppressed),
            "duplicate_findings": len(debug_duplicates),
        },
    )


def _select_primary(findings: list[CodeFinding]) -> CodeFinding:
    return sorted(
        findings,
        key=lambda finding: (
            CONTEXT_RANK.get(finding.context or "unknown", 4),
            -SEVERITY_RANK.get(finding.severity, 0),
            -float(finding.confidence),
            -(len(finding.nearby_context or "")),
            finding.evidence.line or 0,
        ),
    )[0]


def _build_cluster(
    primary_finding: CodeFinding,
    cluster_findings: list[CodeFinding],
    capabilities: list[str],
    ai_result: CodeAITriageResult | None,
) -> CodeCluster:
    reason = ai_result.reason if ai_result is not None else None
    kept = True
    why_kept: str | None = None
    why_suppressed: str | None = None
    if ai_result is not None:
        kept = ai_result.action == "keep"
        if kept:
            why_kept = reason or "Kept after AI triage."
        else:
            why_suppressed = reason or "Suppressed after AI triage."

    return CodeCluster(
        cluster_id=primary_finding.cluster_id or f"{primary_finding.rule_id}:{primary_finding.evidence.file_path}",
        rule_id=primary_finding.rule_id,
        deterministic_severity=primary_finding.severity,  # type: ignore[arg-type]
        context=(primary_finding.context if primary_finding.context in {"mcp", "server", "cli", "library"} else "unknown"),  # type: ignore[arg-type]
        file_path=primary_finding.evidence.file_path,
        primary_line=primary_finding.evidence.line or 0,
        primary_snippet=primary_finding.evidence.snippet[:220],
        nearby_context=(primary_finding.nearby_context or "")[:900],
        capabilities=cluster_capabilities(primary_finding, capabilities),
        cluster_size=primary_finding.cluster_size or len(cluster_findings),
        example_locations=_example_locations(cluster_findings),
        taint_summary=cluster_taint_summary(primary_finding, primary_finding.nearby_context or ""),
        ai=(
            CodeClusterAI(
                verdict=_ai_verdict(ai_result),
                risk=ai_result.risk,
                confidence=ai_result.confidence,
                reason=reason,
            )
            if ai_result is not None
            else None
        ),
        final=CodeClusterFinal(
            kept=kept,
            why_kept=why_kept,
            why_suppressed=why_suppressed,
        ),
    )


def _example_locations(findings: list[CodeFinding]) -> list[CodeAIExampleLocation]:
    seen: set[tuple[int, str]] = set()
    examples: list[CodeAIExampleLocation] = []
    for finding in sorted(findings, key=lambda item: (item.evidence.line or 0, item.evidence.snippet)):
        key = (finding.evidence.line or 0, finding.evidence.snippet[:180])
        if key in seen:
            continue
        seen.add(key)
        examples.append(
            CodeAIExampleLocation(
                line=finding.evidence.line or 0,
                snippet=finding.evidence.snippet[:180],
            )
        )
        if len(examples) >= 5:
            break
    return examples


def _ai_verdict(ai_result: CodeAITriageResult | None) -> str | None:
    if ai_result is None:
        return None
    if ai_result.action == "suppress":
        if ai_result.risk == "low":
            return "likely_fp"
        return "fp"
    if ai_result.risk in {"critical", "high"}:
        return "tp"
    return "likely_tp"
