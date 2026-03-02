from __future__ import annotations

import asyncio
import copy
import logging
import os
from datetime import date
from pathlib import PurePosixPath
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv

from .ai_triage import synthesize_overall_from_triage, triage_findings
from .ai_reviewer import AIReviewer
from .code_audit import GitHubCodeFetcher, analyze_codebase
from .code_audit.clusters import build_cluster_groups
from .code_audit.handoff import build_ai_handoff
from .code_audit.scoring import OUT_OF_SCOPE_NOTES, SUPPORTED_RULES, build_code_summary, filter_supported_findings
from .fetcher import AuditServiceError, GitHubDocFetcher
from .models import AIReviewMeta, AIReviewResult, AuditRequest, AuditResponse, CodeAIOverallTriage, CodeAITriage, CodeAITriageResult, CodeAuditReport, CodeAuditRequest, CodeAuditSummaryResponse, CodeCoverageScope, CodeCoverageScoringPolicy, CodeDeploymentGuidance, CodeOverallSafety, CodeScannedFile, CodeSnapshot, ExplainResponse, FetchedGraph, GraphSummary, HealthResponse, Report, SkillAuditSummaryResponse, SkillFullAnalysisItem, SkillSecurityAuditStatus
from .rules import analyze_documents, llm_explanation_stub
from .scoring import build_summary


load_dotenv()

app = FastAPI(title="MCP Skill Doc Auditor", version="0.1.0")
ai_reviewer = AIReviewer()
logger = logging.getLogger(__name__)
TOP_RISK_LABELS = {
    "ssrf-fetch": "Outbound requests may forward user-controlled parameters to external services.",
    "open-proxy-endpoint": "The server may act as a proxy to external services without enough restrictions.",
    "command-execution": "The code may execute shell or system commands from runtime inputs.",
    "arbitrary-file-read": "The code may read caller-influenced files from the local filesystem.",
    "arbitrary-file-write": "The code may write caller-influenced files to the local filesystem.",
    "arbitrary-file-delete": "The code may delete caller-influenced files from the local filesystem.",
    "path-traversal": "Path handling may allow access outside an intended base directory.",
    "auth-missing-on-network-service": "Some exposed endpoints may lack visible authentication checks.",
    "unsafe-docker-runtime": "The runtime may rely on unsafe Docker privileges or host access.",
    "hardcoded-secret": "Embedded secrets or tokens may be present in code or configuration.",
}
SAFE_USAGE_RECOMMENDATIONS = {
    "ssrf-fetch": "Restrict outbound network access to trusted domains only and monitor external requests.",
    "open-proxy-endpoint": "Do not expose proxy-like features directly to the public internet without strict allowlists.",
    "command-execution": "Run it in an isolated container with no shell access to the host and no elevated privileges.",
    "arbitrary-file-read": "Mount only the minimum required files and prefer read-only volumes where possible.",
    "arbitrary-file-write": "Mount only a narrow working directory and avoid granting write access to host-sensitive paths.",
    "arbitrary-file-delete": "Avoid broad filesystem permissions and keep runtime data in disposable isolated directories.",
    "path-traversal": "Use a fixed workspace directory and avoid exposing host filesystem paths to the service.",
    "auth-missing-on-network-service": "Place it behind authentication or a trusted reverse proxy before letting others use it.",
    "unsafe-docker-runtime": "Do not run it with privileged Docker access or host Docker socket mounts.",
    "hardcoded-secret": "Use scoped credentials from a secret manager and rotate any tokens before production use.",
}
SKILL_CATEGORY_MAP = {
    "remote-install-manifest": "EXTERNAL_DOWNLOADS",
    "unpinned-dependency-install": "EXTERNAL_DOWNLOADS",
    "curl-pipe-shell": "REMOTE_CODE_EXECUTION",
    "git-clone-main-then-run": "REMOTE_CODE_EXECUTION",
    "api-proxy-route-with-key": "API_PROXY",
    "private-ip-ssrf-mitigation-missing": "NETWORK_FETCH",
    "ssrf-language": "NETWORK_FETCH",
    "webhook-signature-missing": "WEBHOOK_SECURITY",
    "public-exposure": "NETWORK_EXPOSURE",
    "missing-guardrails-proxy": "API_PROXY",
    "capability-proxy": "API_PROXY",
    "missing-guardrails-shell": "COMMAND_EXECUTION",
    "capability-shell": "COMMAND_EXECUTION",
    "missing-guardrails-filesystem": "FILESYSTEM_ACCESS",
    "capability-filesystem": "FILESYSTEM_ACCESS",
    "missing-guardrails-network": "NETWORK_FETCH",
    "capability-network": "NETWORK_FETCH",
    "missing-guardrails-file-upload": "FILE_UPLOAD",
    "capability-file-upload": "FILE_UPLOAD",
    "file-upload-capability": "FILE_UPLOAD",
    "missing-guardrails-client-side-tools": "CLIENT_SIDE_TOOLS",
    "capability-client-side-tools": "CLIENT_SIDE_TOOLS",
    "client-side-tools-capability": "CLIENT_SIDE_TOOLS",
    "missing-guardrails-browser": "BROWSER_AUTOMATION",
    "missing-guardrails-browser-automation": "BROWSER_AUTOMATION",
    "missing-guardrails-docker": "DOCKER_RUNTIME",
    "missing-guardrails-git": "GIT_OPERATIONS",
    "missing-guardrails-k8s": "KUBERNETES_ACCESS",
    "missing-guardrails-email": "EMAIL_DELIVERY",
    "missing-guardrails-payment": "PAYMENT_ACCESS",
    "missing-guardrails-clipboard": "CLIPBOARD_ACCESS",
    "missing-guardrails-notifications": "NOTIFICATIONS",
    "capability-browser": "BROWSER_AUTOMATION",
    "capability-browser-automation": "BROWSER_AUTOMATION",
    "capability-docker": "DOCKER_RUNTIME",
    "capability-git": "GIT_OPERATIONS",
    "capability-k8s": "KUBERNETES_ACCESS",
    "capability-email": "EMAIL_DELIVERY",
    "capability-payment": "PAYMENT_ACCESS",
    "capability-clipboard": "CLIPBOARD_ACCESS",
    "capability-notifications": "NOTIFICATIONS",
    "env-file-guidance": "SECRETS_HANDLING",
    "secret-placeholder": "SECRETS_HANDLING",
}
SKILL_PROVIDER = "Run The Dev"
SKILL_FAIL_RULES = {
    "remote-install-manifest",
    "curl-pipe-shell",
    "git-clone-main-then-run",
    "api-proxy-route-with-key",
    "private-ip-ssrf-mitigation-missing",
    "ssrf-language",
    "webhook-signature-missing",
    "public-exposure",
}
SKILL_WARN_RULES = {
    "env-file-guidance",
    "secret-placeholder",
}


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


def _build_report(request: AuditRequest, graph: object, analysis: object, summary: object, drivers: list[str]) -> Report:
    return Report(
        input_url=request.url,
        root_doc_url=graph.root_doc_url,
        fetched=FetchedGraph(
            docs=[document.meta for document in graph.docs],
            edges=graph.edges,
        ),
        graph_summary=GraphSummary(
            total_docs=len(graph.docs),
            max_depth_reached=graph.max_depth_reached,
        ),
        summary=summary,
        capabilities=analysis.capabilities,
        drivers=drivers,
        findings=analysis.findings,
    )


def _wrap_audit_response(
    report: Report,
    ai_review: AIReviewResult | None = None,
    meta: AIReviewMeta | None = None,
) -> AuditResponse:
    payload = report.model_dump()
    payload["ai_review"] = ai_review
    payload["meta"] = meta
    return AuditResponse(**payload)


def _build_code_report(
    request: CodeAuditRequest,
    root_target: str,
    files: list[object],
    findings: list[object],
    capabilities: list[str],
    *,
    summary: object,
    drivers: list[str],
    overall_safety: CodeOverallSafety,
    coverage_scope: CodeCoverageScope,
    clusters: object,
    snapshot: CodeSnapshot,
    pre_ai_summary: object | None = None,
    ai_handoff: object | None = None,
    ai_triage: CodeAITriage | None = None,
    ai_suppressed_clusters: list[CodeAITriageResult] | None = None,
) -> CodeAuditReport:
    scanned_files = [
        CodeScannedFile(
            path=file.path,
            url=file.url,
            language=file.language,
            char_count=file.char_count,
            context=file.context,
        )
        for file in files
    ]
    return CodeAuditReport(
        input_url=request.url,
        root_target=root_target,
        scanned_files=scanned_files,
        coverage_scope=coverage_scope,
        summary=summary,
        pre_ai_summary=pre_ai_summary,
        drivers=drivers,
        capabilities=capabilities,
        clusters=clusters,
        findings=findings,
        overall_safety=overall_safety,
        snapshot=snapshot,
        ai_handoff=ai_handoff,
        ai_triage=ai_triage,
        ai_suppressed_clusters=ai_suppressed_clusters or [],
    )


def _skill_priority(report: AuditResponse) -> str:
    findings = list(report.findings)
    if any(finding.rule_id in SKILL_FAIL_RULES and finding.severity in {"critical", "high"} for finding in findings):
        if any(finding.severity == "critical" for finding in findings if finding.rule_id in SKILL_FAIL_RULES):
            return "critical"
        return "high"
    if any(
        finding.rule_id.startswith("missing-guardrails-")
        or finding.rule_id.startswith("capability-")
        or finding.rule_id in SKILL_WARN_RULES
        for finding in findings
    ):
        if any(
            finding.rule_id.startswith("missing-guardrails-") and finding.severity in {"critical", "high", "medium"}
            for finding in findings
        ):
            return "medium"
        if any(finding.rule_id.startswith("capability-") for finding in findings):
            return "low"
    if report.ai_review is not None:
        return report.ai_review.ai_priority
    counts = report.summary.counts
    if counts.critical:
        return "critical"
    if counts.high:
        return "high"
    if counts.medium:
        return "medium"
    return "low"


def _skill_status(priority: str) -> str:
    if priority in {"critical", "high"}:
        return "Fail"
    if priority == "medium":
        return "Warn"
    return "Pass"


def _skill_risk_level(priority: str) -> str:
    if priority == "critical":
        return "CRITICAL"
    if priority == "high":
        return "HIGH"
    if priority == "medium":
        return "CAUTION"
    return "SAFE"


def _code_risk_level(overall_risk: str) -> str:
    if overall_risk == "critical":
        return "CRITICAL"
    if overall_risk == "high":
        return "HIGH"
    if overall_risk == "medium":
        return "CAUTION"
    return "SAFE"


def _format_audited_at() -> str:
    return date.today().strftime("%b %d, %Y").replace(" 0", " ")


def _skill_name(report: AuditResponse) -> str:
    root_doc_path = PurePosixPath(urlparse(report.root_doc_url).path)
    if root_doc_path.name.upper() == "SKILL.MD" and root_doc_path.parent.name:
        return root_doc_path.parent.name
    if report.fetched.docs and report.fetched.docs[0].title:
        return report.fetched.docs[0].title
    return root_doc_path.stem or "skill"


def _skill_category(finding: object) -> str:
    return SKILL_CATEGORY_MAP.get(getattr(finding, "rule_id", ""), "GENERAL_RISK")


def _skill_analysis_text(finding: object) -> str:
    description = str(getattr(finding, "description", "")).strip()
    recommendations = list(getattr(finding, "recommendation", []) or [])
    if recommendations:
        return f"{description} Recommended action: {recommendations[0]}"
    return description


def _select_skill_findings(report: AuditResponse) -> list[object]:
    findings = list(report.findings)
    if report.ai_review is None:
        return sorted(
            findings,
            key=lambda item: (
                -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(item.severity, 0),
                -float(item.confidence),
                item.rule_id,
            ),
        )[:5]

    prioritized_rule_ids = [item.rule_id for item in report.ai_review.top_risks_detailed]
    prioritized: list[object] = []
    seen: set[tuple[str, str]] = set()
    for rule_id in prioritized_rule_ids:
        for finding in findings:
            if finding.rule_id != rule_id:
                continue
            key = (finding.rule_id, finding.evidence.doc_url)
            if key in seen:
                continue
            seen.add(key)
            prioritized.append(finding)
            break
    if len(prioritized) >= 5:
        return prioritized[:5]
    for finding in sorted(
        findings,
        key=lambda item: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(item.severity, 0),
            -float(item.confidence),
            item.rule_id,
        ),
    ):
        key = (finding.rule_id, finding.evidence.doc_url)
        if key in seen:
            continue
        seen.add(key)
        prioritized.append(finding)
        if len(prioritized) >= 5:
            break
    return prioritized


def _build_skill_summary_response(report: AuditResponse) -> SkillAuditSummaryResponse:
    priority = _skill_priority(report)
    status = _skill_status(priority)
    selected_findings = _select_skill_findings(report)
    risk_categories: list[str] = []
    full_analysis: list[SkillFullAnalysisItem] = []
    for finding in selected_findings:
        category = _skill_category(finding)
        if category not in risk_categories:
            risk_categories.append(category)
        full_analysis.append(
            SkillFullAnalysisItem(
                category=category,
                severity=finding.severity.upper(),  # type: ignore[arg-type]
                analysis=_skill_analysis_text(finding),
            )
        )

    safe_usage_recommendations: list[str] = []
    if report.ai_review is not None:
        for item in report.ai_review.ai_must_fix_first:
            if item not in safe_usage_recommendations:
                safe_usage_recommendations.append(item)
            if len(safe_usage_recommendations) >= 5:
                break
    for finding in selected_findings:
        for item in finding.recommendation:
            if item not in safe_usage_recommendations:
                safe_usage_recommendations.append(item)
            if len(safe_usage_recommendations) >= 5:
                break
        if len(safe_usage_recommendations) >= 5:
            break

    return SkillAuditSummaryResponse(
        skill_name=_skill_name(report),
        status=status,  # type: ignore[arg-type]
        audited_by=SKILL_PROVIDER,
        audited_at=_format_audited_at(),
        risk_level=_skill_risk_level(priority),  # type: ignore[arg-type]
        security_audits=[SkillSecurityAuditStatus(provider=SKILL_PROVIDER, status=status)],  # type: ignore[arg-type]
        risk_categories=risk_categories,
        full_analysis=full_analysis,
        safe_usage_recommendations=safe_usage_recommendations,
    )


def _build_code_overall_safety(findings: list[object], ai_overall: CodeAIOverallTriage | None = None, *, filtered_out_count: int = 0) -> CodeOverallSafety:
    source = "ai_combined" if ai_overall is not None else "deterministic"
    if ai_overall is not None:
        risk = ai_overall.risk
        confidence = ai_overall.confidence
    else:
        risk = _highest_finding_risk(findings)
        confidence = _deterministic_overall_confidence(findings)

    verdict_map = {
        "critical": "unsafe",
        "high": "unsafe",
        "medium": "caution",
        "low": "safe",
        "none": "safe",
    }
    verdict = verdict_map[risk]

    primary_count = _primary_cluster_count(findings)

    if not findings:
        if source == "ai_combined" and filtered_out_count:
            summary = "No actionable findings remained after AI filtering."
        else:
            summary = "No actionable findings were retained by the deterministic code audit."
    elif source == "ai_combined":
        summary = f"{primary_count} actionable clusters remained after AI filtering; highest remaining risk is {risk}."
    else:
        summary = f"Deterministic code audit retained {primary_count} actionable clusters; highest risk is {risk}."

    return CodeOverallSafety(
        verdict=verdict,  # type: ignore[arg-type]
        risk=risk,  # type: ignore[arg-type]
        confidence=confidence,
        source=source,  # type: ignore[arg-type]
        summary=summary,
    )


def _build_coverage_scope() -> CodeCoverageScope:
    return CodeCoverageScope(
        version="scope-v1",
        supported_rules=sorted(SUPPORTED_RULES),
        out_of_scope=OUT_OF_SCOPE_NOTES,
        scoring_policy=CodeCoverageScoringPolicy(
            final_risk_uses="ai_kept_clusters_within_supported_rules",
            deterministic_risk_uses="candidate_clusters_within_supported_rules",
        ),
    )


def _build_snapshot(
    summary: object,
    overall_safety: CodeOverallSafety,
    clusters: object,
    drivers: list[str],
) -> CodeSnapshot:
    stats = getattr(clusters, "stats", {}) or {}
    return CodeSnapshot(
        risk_score=summary.risk_score,
        overall_safety=overall_safety.verdict,
        overall_risk=overall_safety.risk,
        primary_clusters=int(stats.get("primary_clusters", 0)),
        kept_clusters=int(stats.get("primary_clusters", 0)),
        suppressed_clusters=int(stats.get("suppressed_clusters", 0)),
        drivers=drivers[:3],
    )


def _cluster_effective_risk(cluster: object) -> str:
    ai = getattr(cluster, "ai", None)
    if ai is not None and getattr(ai, "risk", None) in {"critical", "high", "medium", "low", "none"}:
        return ai.risk
    return getattr(cluster, "deterministic_severity", "low")


def _build_code_summary_response(report: CodeAuditReport) -> CodeAuditSummaryResponse:
    primary_clusters = list(report.clusters.primary)
    security_score = max(0, min(100, 100 - int(report.summary.risk_score)))
    quality_penalty = min(
        95,
        sum({"critical": 24, "high": 14, "medium": 7, "low": 3, "none": 0}.get(_cluster_effective_risk(cluster), 3) for cluster in primary_clusters)
        + min(10, len(set(report.capabilities)) * 2),
    )
    quality_score = max(0, 100 - quality_penalty)
    overall_risk = report.overall_safety.risk
    status_map = {
        "critical": "not_recommended",
        "high": "hardening_required",
        "medium": "usable_with_caution",
        "low": "safe_to_use",
        "none": "safe_to_use",
    }
    deployment_map = {
        "critical": CodeDeploymentGuidance(local_dev="only_in_isolated_env", staging="not_recommended", production="not_recommended"),
        "high": CodeDeploymentGuidance(local_dev="acceptable_with_caution", staging="hardening_required", production="not_recommended"),
        "medium": CodeDeploymentGuidance(local_dev="acceptable", staging="acceptable_with_caution", production="hardening_required"),
        "low": CodeDeploymentGuidance(local_dev="acceptable", staging="acceptable", production="acceptable_with_standard_controls"),
        "none": CodeDeploymentGuidance(local_dev="acceptable", staging="acceptable", production="acceptable_with_standard_controls"),
    }

    rule_counts: dict[str, int] = {}
    for cluster in primary_clusters:
        rule_counts[cluster.rule_id] = rule_counts.get(cluster.rule_id, 0) + 1
    ordered_rules = sorted(
        rule_counts.items(),
        key=lambda item: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}.get(
                max((_cluster_effective_risk(cluster) for cluster in primary_clusters if cluster.rule_id == item[0]), default="none"),
                0,
            ),
            -item[1],
            item[0],
        ),
    )
    top_risks = []
    for rule_id, count in ordered_rules[:3]:
        label = TOP_RISK_LABELS.get(rule_id, rule_id.replace("-", " ").capitalize())
        if count > 1:
            label = f"{label} ({count} clusters)"
        top_risks.append(label)

    recommendations: list[str] = []
    for rule_id, _count in ordered_rules:
        recommendation = SAFE_USAGE_RECOMMENDATIONS.get(rule_id)
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
        if len(recommendations) >= 5:
            break
    if not recommendations:
        recommendations = [
            "Use least-privilege credentials and keep network and filesystem access narrowly scoped.",
            "Prefer isolated environments when trying a new server before wider deployment.",
        ]

    return CodeAuditSummaryResponse(
        audited_by=SKILL_PROVIDER,
        audited_at=_format_audited_at(),
        risk_level=_code_risk_level(overall_risk),  # type: ignore[arg-type]
        security_score=security_score,
        quality_score=quality_score,
        overall_risk=overall_risk,  # type: ignore[arg-type]
        status=status_map[overall_risk],  # type: ignore[arg-type]
        top_risks=top_risks,
        safe_usage_recommendations=recommendations,
        deployment_guidance=deployment_map[overall_risk],
    )


def _highest_finding_risk(findings: list[object]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    highest = max((finding.severity for finding in findings), key=lambda item: order.get(item, 0), default="info")
    if highest == "info":
        return "none"
    return highest


def _deterministic_overall_confidence(findings: list[object]) -> float:
    if not findings:
        return 0.9
    confidences = sorted((float(finding.confidence) for finding in findings), reverse=True)[:3]
    return round(sum(confidences) / len(confidences), 2)


def _primary_cluster_count(findings: list[object]) -> int:
    return sum(1 for finding in findings if getattr(finding, "cluster_role", None) != "duplicate")


def _apply_ai_cluster_actions(
    findings: list[object],
    raw_results: list[dict[str, object]],
) -> tuple[list[object], list[object], list[CodeAITriageResult], list[CodeAITriageResult], list[dict[str, object]], int]:
    results_by_cluster = {str(item["cluster_id"]): item for item in raw_results}
    suppressed_cluster_ids = {
        cluster_id
        for cluster_id, item in results_by_cluster.items()
        if item.get("action") == "suppress"
    }

    kept_findings: list[object] = []
    suppressed_findings: list[object] = []
    primary_indices_by_cluster: dict[str, int] = {}

    for finding in findings:
        cluster_id = getattr(finding, "cluster_id", None)
        result = results_by_cluster.get(cluster_id) if cluster_id is not None else None
        if result is not None:
            finding.ai_verdict = result["action"]
            finding.ai_risk = result["risk"]
            finding.ai_confidence = result["confidence"]
            if cluster_id in suppressed_cluster_ids:
                finding.suppression_reason = result.get("reason") or "Suppressed as AI-triaged likely false positive."
        if cluster_id in suppressed_cluster_ids:
            suppressed_findings.append(copy.deepcopy(finding))
            continue
        if finding.cluster_role == "primary" and cluster_id:
            primary_indices_by_cluster[cluster_id] = len(kept_findings)
        kept_findings.append(finding)

    ai_triage_results = [
        CodeAITriageResult(
            finding_index=primary_indices_by_cluster.get(str(item["cluster_id"])) if item.get("action") == "keep" else None,
            cluster_id=str(item["cluster_id"]),
            action=item["action"],  # type: ignore[arg-type]
            risk=item["risk"],  # type: ignore[arg-type]
            confidence=item["confidence"],  # type: ignore[arg-type]
            reason=item.get("reason"),  # type: ignore[arg-type]
        )
        for item in raw_results
    ]
    ai_suppressed_clusters = [item for item in ai_triage_results if item.action == "suppress"]
    kept_raw_results = [
        item for item in raw_results
        if item.get("action") == "keep" and str(item["cluster_id"]) in primary_indices_by_cluster
    ]
    return (
        kept_findings,
        suppressed_findings,
        ai_triage_results,
        ai_suppressed_clusters,
        kept_raw_results,
        len(suppressed_cluster_ids),
    )


@app.post("/audit", response_model=AuditResponse)
async def audit(request: AuditRequest) -> AuditResponse:
    return await _run_skill_audit(request)


@app.post("/audit/skill/summary", response_model=SkillAuditSummaryResponse)
async def audit_summary(request: AuditRequest) -> SkillAuditSummaryResponse:
    report = await _run_skill_audit(request)
    return _build_skill_summary_response(report)


@app.post("/audit/explain", response_model=ExplainResponse)
async def audit_explain(report: Report) -> ExplainResponse:
    review_result = await ai_reviewer.review(report)
    return ExplainResponse(
        rule_report=report,
        ai_review=review_result.ai_review,
        meta=review_result.meta,
    )


@app.post("/audit/code", response_model=CodeAuditReport)
async def audit_code(request: CodeAuditRequest) -> CodeAuditReport:
    return await _run_code_audit(request)


@app.post("/audit/code/summary", response_model=CodeAuditSummaryResponse)
async def audit_code_summary(request: CodeAuditRequest) -> CodeAuditSummaryResponse:
    report = await _run_code_audit(request)
    return _build_code_summary_response(report)


async def _run_skill_audit(request: AuditRequest) -> AuditResponse:
    try:
        async with GitHubDocFetcher() as fetcher:
            graph = await fetcher.fetch_graph(
                input_url=request.url,
                max_depth=request.max_depth,
                max_docs=request.max_docs,
                max_total_chars=request.max_total_chars,
            )
    except AuditServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    analysis = analyze_documents(graph.docs)
    llm_explanation_stub(analysis.findings)
    summary, drivers = build_summary(analysis.findings, analysis.capabilities)
    report = _build_report(request, graph, analysis, summary, drivers)
    if not request.ai_explain:
        return _wrap_audit_response(report)

    review_result = await ai_reviewer.review(report)
    return _wrap_audit_response(
        report,
        ai_review=review_result.ai_review,
        meta=review_result.meta,
    )


async def _run_code_audit(request: CodeAuditRequest) -> CodeAuditReport:
    try:
        async with GitHubCodeFetcher() as fetcher:
            target, files = await fetcher.fetch_code_files(
                request.url,
                max_files=request.max_files,
                max_total_chars=request.max_total_chars,
                include_tests=False,
                include_ci=False,
            )
    except AuditServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    analysis = analyze_codebase(files)
    response_findings = list(analysis.findings)
    supported_candidate_findings = filter_supported_findings(response_findings)
    ai_triage: CodeAITriage | None = None
    filtered_out_count = 0
    suppressed_findings: list[object] = []
    ai_suppressed_clusters: list[CodeAITriageResult] = []
    pre_ai_summary, _ = build_code_summary(supported_candidate_findings, analysis.capabilities, files)
    ai_handoff = build_ai_handoff(
        supported_candidate_findings,
        analysis.capabilities,
        max_items=10 if target.target_kind == "blob" else 30,
    )
    mistral_api_key = os.getenv("MISTRAL_API_KEY")
    if request.ai_classify and mistral_api_key:
        model = os.getenv("MISTRAL_MODEL", "mistral-small-latest")
        if not ai_handoff.items:
            logger.info("Code audit AI triage skipped: no clusters to triage")
        else:
            logger.info(
                "Code audit AI triage requested: findings=%s clusters=%s model=%s",
                len(response_findings),
                len(ai_handoff.items),
                model,
            )
            triage_payload = await asyncio.to_thread(
                triage_findings,
                [item.model_dump() for item in ai_handoff.items],
                model,
                8,
                True,
            )
            raw_results = list(triage_payload.get("results", []))
            ai_triage_results: list[CodeAITriageResult] = []
            kept_raw_results: list[dict[str, object]] = []
            if raw_results:
                (
                    response_findings,
                    suppressed_findings,
                    ai_triage_results,
                    ai_suppressed_clusters,
                    kept_raw_results,
                    filtered_out_count,
                ) = _apply_ai_cluster_actions(response_findings, raw_results)
                if filtered_out_count:
                    logger.info(
                        "Code audit AI triage filtered likely false positives from response: filtered_out=%s kept=%s",
                        filtered_out_count,
                        len(response_findings),
                    )
            else:
                logger.warning(
                    "Code audit AI triage attempted on %s clusters but produced no usable results",
                    len(ai_handoff.items),
                )
            overall = synthesize_overall_from_triage(response_findings, kept_raw_results) if kept_raw_results else None
            if overall is None and filtered_out_count and raw_results:
                overall = CodeAIOverallTriage(
                    verdict="likely_fp",
                    risk="none",
                    confidence=round(sum(float(item["confidence"]) for item in raw_results) / len(raw_results), 2),
                    recommendations=[],
                )
            if raw_results or overall or filtered_out_count:
                overall_triage = None
                if overall is not None:
                    if isinstance(overall, CodeAIOverallTriage):
                        overall_triage = overall
                    else:
                        overall_triage = CodeAIOverallTriage(
                            verdict=overall["verdict"],  # type: ignore[arg-type]
                            risk=overall["risk"],  # type: ignore[arg-type]
                            confidence=overall["confidence"],
                            recommendations=overall["recommendations"],
                        )
                ai_triage = CodeAITriage(
                    model=model,
                    batch_size=8,
                    results=ai_triage_results,
                    filtered_out_count=filtered_out_count,
                    suppressed_findings=suppressed_findings,
                    overall=overall_triage,
                )
                logger.info(
                    "Code audit AI triage attached: results=%s overall=%s filtered_out=%s",
                    len(ai_triage_results),
                    overall_triage is not None,
                    filtered_out_count,
                )
    elif request.ai_classify:
        logger.warning("Code audit AI triage requested but MISTRAL_API_KEY is not available in process env")

    supported_kept_findings = filter_supported_findings(response_findings)
    summary, drivers = build_code_summary(supported_kept_findings, analysis.capabilities, files)
    coverage_scope = _build_coverage_scope()
    cluster_groups = build_cluster_groups(
        supported_kept_findings + filter_supported_findings(suppressed_findings),
        analysis.capabilities,
        ai_triage.results if ai_triage is not None else None,
    )
    overall_safety = _build_code_overall_safety(
        supported_kept_findings,
        ai_triage.overall if ai_triage is not None else None,
        filtered_out_count=filtered_out_count,
    )
    snapshot = _build_snapshot(summary, overall_safety, cluster_groups, drivers)
    return _build_code_report(
        request,
        target.root_target,
        files,
        response_findings,
        analysis.capabilities,
        summary=summary,
        drivers=drivers,
        overall_safety=overall_safety,
        coverage_scope=coverage_scope,
        clusters=cluster_groups,
        snapshot=snapshot,
        pre_ai_summary=pre_ai_summary,
        ai_handoff=ai_handoff,
        ai_triage=ai_triage,
        ai_suppressed_clusters=ai_suppressed_clusters,
    )
