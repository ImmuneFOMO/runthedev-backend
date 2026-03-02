from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


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


class MarketplaceAuditDetail(BaseModel):
    status: Literal["Pass", "Warn", "Fail"]
    metadata: dict[str, str]
    audit_date: str
    audit_info: str
    risk_level: Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    full_analysis: str


class MarketplaceAuditResponse(BaseModel):
    source_id: str
    name: str
    audit_summary: dict[str, str]
    audit_rank: int | None = None
    audit_agent_trust_hub_api: str | None = None
    audit_socket_api: str | None = None
    audit_snyk_api: str | None = None
    audit_agent_trust_hub_detail: MarketplaceAuditDetail
    audit_socket_detail: dict[str, str] | None = None
    audit_snyk_detail: MarketplaceAuditDetail | None = None
    repository_url: str


class AuditRequest(BaseModel):
    url: str
    max_depth: int = Field(default=2, ge=0, le=5)
    max_docs: int = Field(default=30, ge=1, le=100)
    max_total_chars: int = Field(default=500000, ge=1000, le=2_000_000)


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
