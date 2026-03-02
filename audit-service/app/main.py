from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath

from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv

from .ai_reviewer import AIReviewer
from .fetcher import AuditServiceError, GitHubDocFetcher, InvalidGitHubUrl, parse_github_location
from .models import AuditRequest, ExplainResponse, FetchGraphContext, FetchedGraph, GraphSummary, HealthResponse, MarketplaceAuditDetail, MarketplaceAuditResponse, Report, Summary
from .rules import AnalysisResult, analyze_documents, llm_explanation_stub
from .scoring import build_summary


load_dotenv()

app = FastAPI(title="MCP Skill Doc Auditor", version="0.1.0")
ai_reviewer = AIReviewer()


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


def _build_report(request: AuditRequest, graph: FetchGraphContext, analysis: AnalysisResult, summary: Summary, drivers: list[str]) -> Report:
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


def _format_calendar_date(moment: datetime) -> str:
    return f"{moment.strftime('%b')} {moment.day}, {moment.year}"


def _derive_source_identity(report: Report) -> tuple[str, str, str]:
    try:
        location = parse_github_location(report.input_url)
    except InvalidGitHubUrl:
        location = parse_github_location(report.root_doc_url)

    path = PurePosixPath(location.path)
    name = path.parent.name or path.stem or location.repo
    if path.name.lower() not in {"skill.md", "readme.md", "readme.markdown"}:
        name = path.stem or name
    source_id = f"{location.owner}/{location.repo}/{name}"
    repository_url = f"https://github.com/{location.owner}/{location.repo}"
    return source_id, name, repository_url


def _top_severity(report: Report) -> str:
    counts = report.summary.counts
    if counts.critical:
        return "critical"
    if counts.high:
        return "high"
    if counts.medium:
        return "medium"
    if counts.low:
        return "low"
    return "safe"


def _marketplace_status_and_risk(report: Report) -> tuple[str, str]:
    top = _top_severity(report)
    if top == "critical":
        return "Fail", "CRITICAL"
    if top == "high":
        return "Fail", "HIGH"
    if top == "medium":
        return "Warn", "MEDIUM"
    if top == "low":
        return "Pass", "LOW"
    return "Pass", "SAFE"


def _rule_label(rule_id: str) -> str:
    return rule_id.replace("-", "_").upper()


def _marketplace_full_analysis(report: Report, risk_level: str) -> str:
    if not report.findings:
        return (
            "[DOC_AUDIT] (SAFE):\n"
            "No risky install, secret exposure, prompt-injection, capability guardrail, or public-exposure patterns were detected "
            "in the fetched markdown corpus."
        )

    lines: list[str] = []
    for finding in report.findings[:8]:  # Limit to first 8 findings for marketplace display
        lines.append(f"[{_rule_label(finding.rule_id)}] ({finding.severity.upper()}):")
        lines.append(f"{finding.description} Evidence: {finding.evidence.snippet}")
    if report.capabilities:
        lines.append(f"[CAPABILITIES] ({risk_level}):")
        lines.append(f"Documented capabilities: {', '.join(report.capabilities)}.")
    return "\n".join(lines)


def _build_marketplace_response(report: Report) -> MarketplaceAuditResponse:
    source_id, name, repository_url = _derive_source_identity(report)
    status, risk_level = _marketplace_status_and_risk(report)
    now = datetime.now(tz=timezone.utc)
    audit_date = _format_calendar_date(now)
    analyzed_at = now.strftime("%b %d, %Y, %I:%M %p").replace(" 0", " ")

    return MarketplaceAuditResponse(
        source_id=source_id,
        name=name,
        audit_summary={"Gen Agent Trust Hub": status},
        audit_agent_trust_hub_detail=MarketplaceAuditDetail(
            status=status,
            metadata={
                "Analyzed": analyzed_at,
                "Risk Level": risk_level,
            },
            audit_date=audit_date,
            audit_info=f"Audited by Gen Agent Trust Hub on {audit_date}",
            risk_level=risk_level,
            full_analysis=_marketplace_full_analysis(report, risk_level),
        ),
        repository_url=repository_url,
    )


@app.post("/audit", response_model=Report)
async def audit(request: AuditRequest) -> Report:
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

    return _build_report(request, graph, analysis, summary, drivers)


@app.post("/audit/marketplace", response_model=MarketplaceAuditResponse)
async def audit_marketplace(request: AuditRequest) -> MarketplaceAuditResponse:
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
    return _build_marketplace_response(report)


@app.post("/audit/explain", response_model=ExplainResponse)
async def audit_explain(report: Report) -> ExplainResponse:
    review_result = await ai_reviewer.review(report)
    return ExplainResponse(
        rule_report=report,
        ai_review=review_result.ai_review,
        meta=review_result.meta,
    )
