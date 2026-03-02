from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]
FileOpType = Literal["read", "write", "delete"]


class FetchedDoc(BaseModel):
    url: str
    title: str | None = None
    content_type: str
    char_count: int
    depth: int
    sha_like: str | None = None


class FetchedEdge(BaseModel):
    from_: str = Field(alias="from")
    to: str
    reason: str

    model_config = {"populate_by_name": True}


class FetchedGraph(BaseModel):
    docs: list[FetchedDoc]
    edges: list[FetchedEdge]


class SummaryCounts(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0
    critical: int = 0


class Summary(BaseModel):
    risk_score: int
    counts: SummaryCounts
    raw_counts: SummaryCounts | None = None


class GraphSummary(BaseModel):
    total_docs: int
    max_depth_reached: int


class Evidence(BaseModel):
    doc_url: str
    section: str | None = None
    snippet: str


class Finding(BaseModel):
    severity: Severity
    rule_id: str
    title: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: Evidence
    recommendation: list[str]


class Report(BaseModel):
    input_url: str
    root_doc_url: str
    fetched: FetchedGraph
    graph_summary: GraphSummary
    summary: Summary
    capabilities: list[str]
    drivers: list[str]
    findings: list[Finding]


class AIRiskDetail(BaseModel):
    rule_id: str
    count: int = Field(ge=1)
    label: str
    why: str
    related_capabilities: list[str] = Field(default_factory=list)


class AIReviewResult(BaseModel):
    ai_summary: str
    ai_priority: Literal["low", "medium", "high", "critical"]
    top_true_risks: list[str]
    top_risks_detailed: list[AIRiskDetail] = Field(default_factory=list)
    likely_false_positive_candidates: list[str]
    ai_attack_path: str | None = None
    ai_must_fix_first: list[str]
    confidence: float = Field(ge=0.0, le=1.0)


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class AIReviewMeta(BaseModel):
    reviewer_used: Literal["mistral", "openrouter", "noop"]
    fallback_reason: str | None = None
    token_usage: TokenUsage = Field(default_factory=TokenUsage)


class ExplainResponse(BaseModel):
    rule_report: Report
    ai_review: AIReviewResult
    meta: AIReviewMeta


class AuditRequest(BaseModel):
    url: str
    max_depth: int = Field(default=2, ge=0, le=5)
    max_docs: int = Field(default=30, ge=1, le=100)
    max_total_chars: int = Field(default=500000, ge=1000, le=2_000_000)
    ai_explain: bool = False


class AuditResponse(Report):
    ai_review: AIReviewResult | None = None
    meta: AIReviewMeta | None = None


class SkillSecurityAuditStatus(BaseModel):
    provider: str
    status: Literal["Pass", "Warn", "Fail"]


class SkillFullAnalysisItem(BaseModel):
    category: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    analysis: str


class SkillAuditSummaryResponse(BaseModel):
    skill_name: str
    status: Literal["Pass", "Warn", "Fail"]
    audited_by: str
    audited_at: str
    risk_level: Literal["SAFE", "CAUTION", "HIGH", "CRITICAL"]
    security_audits: list[SkillSecurityAuditStatus] = Field(default_factory=list)
    risk_categories: list[str] = Field(default_factory=list)
    full_analysis: list[SkillFullAnalysisItem] = Field(default_factory=list)
    safe_usage_recommendations: list[str] = Field(default_factory=list)


class CodeAuditRequest(BaseModel):
    url: str
    max_files: int = Field(default=40, ge=1, le=100)
    max_total_chars: int = Field(default=400000, ge=1000, le=2_000_000)
    ai_classify: bool = False


class HealthResponse(BaseModel):
    status: str = "ok"


@dataclass(slots=True)
class HeadingInfo:
    level: int
    text: str
    line: int
    start_offset: int


@dataclass(slots=True)
class CodeBlockInfo:
    language: str | None
    content: str
    line: int
    section: str | None


@dataclass(slots=True)
class LinkInfo:
    url: str
    text: str
    line: int
    section: str | None


@dataclass(slots=True)
class ParsedMarkdown:
    title: str | None = None
    headings: list[HeadingInfo] = field(default_factory=list)
    code_blocks: list[CodeBlockInfo] = field(default_factory=list)
    links: list[LinkInfo] = field(default_factory=list)

    def section_for_line(self, line: int) -> str | None:
        section: str | None = None
        for heading in self.headings:
            if heading.line > line:
                break
            section = heading.text
        return section

    def section_for_offset(self, offset: int) -> str | None:
        section: str | None = None
        for heading in self.headings:
            if heading.start_offset > offset:
                break
            section = heading.text
        return section


@dataclass(slots=True)
class DocumentContext:
    meta: FetchedDoc
    text: str
    parsed: ParsedMarkdown
    repo_key: str | None


@dataclass(slots=True)
class FetchGraphContext:
    root_doc_url: str
    docs: list[DocumentContext]
    edges: list[FetchedEdge]
    max_depth_reached: int


class CodeScannedFile(BaseModel):
    path: str
    url: str
    language: str | None = None
    char_count: int
    context: str


class CodeEvidence(BaseModel):
    file_path: str
    line: int | None = None
    snippet: str


class CodeFinding(BaseModel):
    severity: Severity
    rule_id: str
    title: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: CodeEvidence
    recommendation: list[str]
    op_type: FileOpType | None = None
    cluster_id: str | None = None
    cluster_size: int | None = Field(default=None, ge=1)
    cluster_role: Literal["primary", "duplicate"] | None = None
    context: str | None = None
    nearby_context: str | None = None
    ai_verdict: str | None = None
    ai_risk: str | None = None
    ai_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    suppression_reason: str | None = None


class CodeAITriageResult(BaseModel):
    finding_index: int | None = Field(default=None, ge=0)
    cluster_id: str
    action: Literal["keep", "suppress"]
    risk: Literal["critical", "high", "medium", "low", "none"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str | None = None


class CodeAIOverallTriage(BaseModel):
    verdict: Literal["tp", "likely_tp", "uncertain", "likely_fp", "fp"]
    risk: Literal["critical", "high", "medium", "low", "none"]
    confidence: float = Field(ge=0.0, le=1.0)
    recommendations: list[str] = Field(default_factory=list)


class CodeAITriage(BaseModel):
    model: str
    batch_size: int = Field(ge=1)
    results: list[CodeAITriageResult] = Field(default_factory=list)
    filtered_out_count: int = Field(default=0, ge=0)
    suppressed_findings: list[CodeFinding] = Field(default_factory=list)
    overall: CodeAIOverallTriage | None = None


class CodeOverallSafety(BaseModel):
    verdict: Literal["safe", "caution", "unsafe", "critical"]
    risk: Literal["critical", "high", "medium", "low", "none"]
    confidence: float = Field(ge=0.0, le=1.0)
    source: Literal["deterministic", "ai_combined"]
    summary: str


class CodeAITaintSummary(BaseModel):
    source: Literal["user_input", "env", "config", "model_output", "unknown"]
    sink: Literal["filesystem", "network", "shell", "docker", "unknown"]
    is_probably_exposed: bool
    guards_seen: list[str] = Field(default_factory=list)
    path_area: Literal["none", "scripts", "tools", "experiments", "examples"] = "none"


class CodeAIExampleLocation(BaseModel):
    line: int
    snippet: str


class CodeAIHandoffItem(BaseModel):
    cluster_id: str
    rule_id: str
    deterministic_severity: Literal["critical", "high", "medium", "low"]
    context: Literal["mcp", "server", "cli", "library", "unknown"]
    file_path: str
    primary_line: int
    primary_snippet: str
    nearby_context: str
    taint_summary: CodeAITaintSummary
    cluster_size: int = Field(ge=1)


class CodeAIHandoffStats(BaseModel):
    total_findings: int = Field(ge=0)
    total_clusters: int = Field(ge=0)
    selected_clusters: int = Field(ge=0)
    dropped_total: int = Field(ge=0)
    dropped_by_rule: dict[str, int] = Field(default_factory=dict)


class CodeAIHandoff(BaseModel):
    version: str
    max_items: int = Field(ge=1)
    items: list[CodeAIHandoffItem] = Field(default_factory=list)
    stats: CodeAIHandoffStats


class CodeClusterAI(BaseModel):
    verdict: Literal["tp", "likely_tp", "likely_fp", "fp", "needs_review"] | None = None
    risk: Literal["critical", "high", "medium", "low", "none"] | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reason: str | None = None


class CodeClusterFinal(BaseModel):
    kept: bool
    why_kept: str | None = None
    why_suppressed: str | None = None


class CodeCluster(BaseModel):
    cluster_id: str
    rule_id: str
    deterministic_severity: Literal["critical", "high", "medium", "low"]
    context: Literal["mcp", "server", "cli", "library", "unknown"]
    file_path: str
    primary_line: int
    primary_snippet: str
    nearby_context: str
    capabilities: list[str] = Field(default_factory=list)
    cluster_size: int = Field(ge=1)
    example_locations: list[CodeAIExampleLocation] = Field(default_factory=list)
    taint_summary: CodeAITaintSummary
    ai: CodeClusterAI | None = None
    final: CodeClusterFinal


class CodeClusterGroups(BaseModel):
    primary: list[CodeCluster] = Field(default_factory=list)
    suppressed: list[CodeCluster] = Field(default_factory=list)
    debug_duplicates: list[CodeCluster] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)


class CodeCoverageScoringPolicy(BaseModel):
    final_risk_uses: str
    deterministic_risk_uses: str


class CodeCoverageScope(BaseModel):
    version: str
    supported_rules: list[str]
    out_of_scope: list[str]
    scoring_policy: CodeCoverageScoringPolicy


class CodeSnapshot(BaseModel):
    risk_score: int
    overall_safety: Literal["safe", "caution", "unsafe", "critical"]
    overall_risk: Literal["critical", "high", "medium", "low", "none"]
    primary_clusters: int = Field(ge=0)
    kept_clusters: int = Field(ge=0)
    suppressed_clusters: int = Field(ge=0)
    drivers: list[str] = Field(default_factory=list)


class CodeDeploymentGuidance(BaseModel):
    local_dev: str
    staging: str
    production: str


class CodeAuditSummaryResponse(BaseModel):
    audited_by: str
    audited_at: str
    risk_level: Literal["SAFE", "CAUTION", "HIGH", "CRITICAL"]
    security_score: int = Field(ge=0, le=100)
    quality_score: int = Field(ge=0, le=100)
    overall_risk: Literal["critical", "high", "medium", "low", "none"]
    status: Literal["safe_to_use", "usable_with_caution", "hardening_required", "not_recommended"]
    top_risks: list[str] = Field(default_factory=list)
    safe_usage_recommendations: list[str] = Field(default_factory=list)
    deployment_guidance: CodeDeploymentGuidance


class CodeAuditReport(BaseModel):
    input_url: str
    root_target: str
    scanned_files: list[CodeScannedFile]
    coverage_scope: CodeCoverageScope
    summary: Summary
    pre_ai_summary: Summary | None = None
    drivers: list[str]
    capabilities: list[str]
    clusters: CodeClusterGroups
    findings: list[CodeFinding]
    overall_safety: CodeOverallSafety
    snapshot: CodeSnapshot
    ai_handoff: CodeAIHandoff | None = None
    ai_triage: CodeAITriage | None = None
    ai_suppressed_clusters: list[CodeAITriageResult] = Field(default_factory=list)
