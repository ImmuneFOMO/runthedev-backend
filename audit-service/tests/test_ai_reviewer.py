from __future__ import annotations

import re

import pytest

from app.ai_reviewer import AIReviewer, NoOpReviewer, _build_evidence_bundle, _coerce_ai_review_result, _extract_token_usage, _sanitize_ai_review
from app.models import AIReviewResult, Evidence, FetchedDoc, FetchedGraph, Finding, GraphSummary, Report, Summary, SummaryCounts, TokenUsage


def make_report(
    findings: list[Finding],
    *,
    capabilities: list[str] | None = None,
    risk_score: int = 20,
    counts: SummaryCounts | None = None,
    drivers: list[str] | None = None,
) -> Report:
    return Report(
        input_url="https://github.com/example/repo/blob/main/skills/demo/SKILL.md",
        root_doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo/SKILL.md",
        fetched=FetchedGraph(
            docs=[
                FetchedDoc(
                    url="https://raw.githubusercontent.com/example/repo/main/skills/demo/SKILL.md",
                    title="Demo",
                    content_type="text/plain",
                    char_count=100,
                    depth=0,
                    sha_like=None,
                )
            ],
            edges=[],
        ),
        graph_summary=GraphSummary(total_docs=1, max_depth_reached=0),
        summary=Summary(risk_score=risk_score, counts=counts or SummaryCounts(high=1)),
        capabilities=capabilities or ["proxy"],
        drivers=drivers or ["20 pts: API proxy route with environment key"],
        findings=findings,
    )


def make_finding(
    *,
    severity: str = "medium",
    rule_id: str,
    title: str,
    description: str,
    confidence: float,
    snippet: str,
    section: str = "Setup",
    recommendation: list[str] | None = None,
    doc_url: str = "https://raw.githubusercontent.com/example/repo/main/skills/demo/SKILL.md",
) -> Finding:
    return Finding(
        severity=severity,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=title,
        description=description,
        confidence=confidence,
        evidence=Evidence(
            doc_url=doc_url,
            section=section,
            snippet=snippet,
        ),
        recommendation=recommendation or ["Add guardrails."],
    )


@pytest.mark.asyncio
async def test_noop_reviewer_returns_structured_result() -> None:
    reviewer = NoOpReviewer()
    report = make_report(
        [
            make_finding(
                severity="high",
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
                recommendation=["Require authentication on the route.", "Add rate limiting."],
            )
        ]
    )

    result = await reviewer.review(report)

    assert isinstance(result.ai_review, AIReviewResult)
    assert result.ai_review.ai_priority == "high"
    assert result.ai_review.confidence == 0.4
    assert result.ai_review.top_true_risks == ["API proxy route with environment key"]
    assert result.ai_review.ai_must_fix_first == ["Require authentication on the route.", "Add rate limiting."]
    assert result.token_usage == TokenUsage()


@pytest.mark.asyncio
async def test_noop_reviewer_marks_low_confidence_findings_as_false_positive_candidates() -> None:
    reviewer = NoOpReviewer()
    report = make_report(
        [
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="Remote install documented.",
                confidence=0.6,
                snippet="npx tool add https://example.com/manifest.json",
                section="Install",
                recommendation=["Pin install manifests."],
            )
        ]
    )

    result = await reviewer.review(report)

    assert result.ai_review.likely_false_positive_candidates == ["Remote install manifest or script execution"]


@pytest.mark.asyncio
async def test_ai_reviewer_reports_noop_meta_when_no_provider_is_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    reviewer = AIReviewer()
    report = make_report([])
    result = await reviewer.review(report)

    assert result.meta.reviewer_used == "noop"
    assert result.meta.fallback_reason is None
    assert result.ai_review.confidence == 0.4
    assert result.meta.token_usage == TokenUsage()


def test_extract_token_usage_prefers_usage_metadata() -> None:
    class FakeResponse:
        usage_metadata = {"input_tokens": 123, "output_tokens": 45, "total_tokens": 168}

    assert _extract_token_usage(FakeResponse()) == TokenUsage(
        input_tokens=123,
        output_tokens=45,
        total_tokens=168,
    )


def test_extract_token_usage_supports_response_metadata_shape() -> None:
    class FakeResponse:
        response_metadata = {
            "token_usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70}
        }

    assert _extract_token_usage(FakeResponse()) == TokenUsage(
        input_tokens=50,
        output_tokens=20,
        total_tokens=70,
    )


def test_coerce_ai_review_result_handles_alternate_provider_schema() -> None:
    payload = """
    {
      "most_exploitable_issue": {
        "rule_id": "api-proxy-route-with-key",
        "severity": "medium",
        "confidence": 0.9,
        "description": "An API route proxies requests and directly injects process.env.API_KEY into the response."
      },
      "likely_false_positives": [],
      "plausible_attack_path": [
        "1. Attacker discovers the proxy endpoint.",
        "2. Attacker abuses the endpoint to extract or misuse the upstream key."
      ],
      "recommendations": [
        "Remove any logic that exposes the raw API key.",
        "Add authentication to the proxy route."
      ],
      "overall_priority": "high"
    }
    """

    result = _coerce_ai_review_result(payload)

    assert result.ai_priority == "high"
    assert result.confidence == 0.9
    assert result.top_true_risks == [
        "An API route proxies requests and directly injects process.env.API_KEY into the response."
    ]
    assert result.ai_attack_path is not None


def test_sanitize_false_positive_candidates_never_returns_empty_list() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
                recommendation=["Require authentication on the route."],
            )
        ],
        counts=SummaryCounts(medium=1),
    )
    review = AIReviewResult(
        ai_summary="The audit evidence indicates a medium severity finding.",
        ai_priority="medium",
        top_true_risks=["API risk"],
        likely_false_positive_candidates=["The API key is properly managed and secured in the environment variable"],
        ai_attack_path="An attacker could potentially abuse the route if not properly secured.",
        ai_must_fix_first=[],
        confidence=0.9,
    )

    result = _sanitize_ai_review(report, review)

    assert result.likely_false_positive_candidates == ["none"]
    assert "No likely false positives stood out" in result.ai_summary
    assert result.ai_attack_path is None


def test_sanitize_formats_top_true_risks_with_rule_id_and_count() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="Remote install documented.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://example.com/agent.json",
                section="Install",
                recommendation=["Pin install manifests."],
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-a/SKILL.md",
            ),
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="Remote install documented.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://example.com/chat.json",
                section="Install",
                recommendation=["Pin install manifests."],
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-b/SKILL.md",
            ),
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
                recommendation=["Require authentication on the route."],
            ),
        ],
        capabilities=["proxy"],
        counts=SummaryCounts(medium=3),
    )
    review = AIReviewResult(
        ai_summary="This report shows risk.",
        ai_priority="high",
        top_true_risks=["security issues", "API risk"],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=["Pin install manifests."],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    pattern = re.compile(r'^[a-z0-9\-]+ \(x\d+\): .+ — .+\. related_capabilities=\[.*\]$')
    assert pattern.match(result.top_true_risks[0])
    assert pattern.match(result.top_true_risks[1])
    assert "[capabilities:" not in result.top_true_risks[0]
    assert ". [capabilities" not in result.top_true_risks[0]
    assert result.top_true_risks[0].startswith("remote-install-manifest (x2):")
    assert result.top_true_risks[1].startswith("api-proxy-route-with-key (x1):")
    assert result.top_risks_detailed[0].rule_id == "remote-install-manifest"
    assert result.top_risks_detailed[0].count == 2
    assert "network" in result.top_risks_detailed[0].related_capabilities
    assert "supply-chain" in result.top_risks_detailed[0].related_capabilities
    assert result.top_risks_detailed[1].related_capabilities == ["network", "proxy"]


def test_count_override_uses_full_report_counts_for_display() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="unpinned-dependency-install",
                title="Unpinned dependency install",
                description="The docs rely on a floating latest dependency reference.",
                confidence=0.8,
                snippet=f"shadcn@latest #{index}",
                doc_url=f"https://raw.githubusercontent.com/example/repo/main/skills/dependency-{index}/SKILL.md",
            )
            for index in range(5)
        ]
        + [
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="Remote install documented.",
                confidence=0.9,
                snippet=f"npx shadcn@latest add https://example.com/{index}.json",
                doc_url=f"https://raw.githubusercontent.com/example/repo/main/skills/demo-{index}/SKILL.md",
            )
            for index in range(4)
        ]
        + [
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
            )
        ],
        capabilities=["proxy"],
        counts=SummaryCounts(medium=10),
    )
    review = AIReviewResult(
        ai_summary="This report shows risk.",
        ai_priority="medium",
        top_true_risks=[],
        top_risks_detailed=[
            {
                "rule_id": "remote-install-manifest",
                "count": 2,
                "label": "Remote manifest supply-chain risk",
                "why": "The docs load remote manifests.",
                "related_capabilities": [],
            }
        ],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    remote_manifest = next(item for item in result.top_risks_detailed if item.rule_id == "remote-install-manifest")
    assert remote_manifest.count == 4
    assert any(risk.startswith("remote-install-manifest (x4):") for risk in result.top_true_risks)


def test_implied_capabilities_add_supply_chain_for_unpinned_dependency_install() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="unpinned-dependency-install",
                title="Unpinned dependency install",
                description="The docs install a dependency without pinning a version.",
                confidence=0.8,
                snippet="npm install demo-package",
            )
        ],
        capabilities=[],
        counts=SummaryCounts(medium=1),
    )
    review = AIReviewResult(
        ai_summary="This report shows risk.",
        ai_priority="medium",
        top_true_risks=[],
        top_risks_detailed=[
            {
                "rule_id": "unpinned-dependency-install",
                "count": 1,
                "label": "Unpinned dependency install",
                "why": "The docs install a dependency without pinning a version.",
                "related_capabilities": [],
            }
        ],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    assert result.top_risks_detailed[0].related_capabilities == ["supply-chain"]


def test_deterministic_ranking_prioritizes_proxy_over_unpinned_dependency() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="unpinned-dependency-install",
                title="Unpinned dependency install",
                description="The docs install a dependency without pinning a version.",
                confidence=0.8,
                snippet="npm install demo-package",
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-a/SKILL.md",
            ),
            make_finding(
                rule_id="unpinned-dependency-install",
                title="Unpinned dependency install",
                description="The docs rely on a floating latest dependency reference.",
                confidence=0.8,
                snippet="shadcn@latest",
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-b/SKILL.md",
            ),
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
            ),
        ],
        capabilities=["proxy"],
        counts=SummaryCounts(medium=3),
    )
    review = AIReviewResult(
        ai_summary="This report shows risk.",
        ai_priority="medium",
        top_true_risks=[],
        top_risks_detailed=[
            {
                "rule_id": "unpinned-dependency-install",
                "count": 2,
                "label": "Unpinned dependency install",
                "why": "The docs install a dependency without pinning a version.",
                "related_capabilities": [],
            },
            {
                "rule_id": "api-proxy-route-with-key",
                "count": 1,
                "label": "Proxy route with upstream credential handling",
                "why": "The docs describe a proxy route backed by an environment key without explicit access controls.",
                "related_capabilities": [],
            },
        ],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    assert result.top_risks_detailed[0].rule_id == "api-proxy-route-with-key"
    assert result.top_risks_detailed[1].rule_id == "unpinned-dependency-install"


def test_attack_path_is_null_for_remote_manifest_only_without_exec_evidence() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="The docs install or load configuration directly from a remote URL.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://ui.example.sh/r/agent.json",
                section="Quick Start",
                recommendation=["Prefer pinned commits, checksums, or versioned releases for install manifests."],
            )
        ],
        counts=SummaryCounts(medium=1),
    )
    review = AIReviewResult(
        ai_summary="Remote install is the main risk.",
        ai_priority="medium",
        top_true_risks=["remote-install-manifest (x1): Remote install risk — Generic reason. [capabilities: none]"],
        likely_false_positive_candidates=[],
        ai_attack_path="An attacker could exploit the remote install manifest to execute arbitrary code in the target application.",
        ai_must_fix_first=[],
        confidence=0.9,
    )

    result = _sanitize_ai_review(report, review)

    assert result.ai_attack_path is None
    assert "No direct code-execution primitive was observed in the provided snippets" in result.ai_summary


def test_must_fix_first_is_actionable_and_capped_at_three_items() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
            ),
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="Remote install documented.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://example.com/agent.json",
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-b/SKILL.md",
            ),
        ],
        capabilities=["proxy"],
        counts=SummaryCounts(medium=2),
    )
    review = AIReviewResult(
        ai_summary="The audit evidence indicates several medium findings.",
        ai_priority="medium",
        top_true_risks=[],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[
            "Do not expose env keys.",
            "Add logging.",
            "Something vague.",
            "Another generic idea.",
        ],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    assert 1 <= len(result.ai_must_fix_first) <= 3
    assert "Require authentication and authorization on the proxy route." in result.ai_must_fix_first
    assert all("env key" not in item.casefold() for item in result.ai_must_fix_first)


def test_confidence_is_capped_when_missing_guardrails_dominate() -> None:
    findings = [
        make_finding(
            rule_id="missing-guardrails-client-side-tools",
            title="Missing guardrails for documented client-side-tools",
            description="Client-side tools guardrails missing.",
            confidence=0.5,
            snippet="client-side tools",
        ),
        make_finding(
            rule_id="missing-guardrails-file-upload",
            title="Missing guardrails for documented file-upload",
            description="File upload guardrails missing.",
            confidence=0.5,
            snippet="allowFiles",
        ),
        make_finding(
            rule_id="missing-guardrails-proxy",
            title="Missing guardrails for documented proxy",
            description="Proxy guardrails missing.",
            confidence=0.5,
            snippet="proxy route",
        ),
        make_finding(
            rule_id="api-proxy-route-with-key",
            title="API proxy route with environment key",
            description="Proxy route documented with environment key.",
            confidence=0.9,
            snippet="Create an API route that uses process.env.API_KEY.",
            recommendation=["Require authentication on the route."],
        ),
    ]
    report = make_report(
        findings,
        capabilities=["proxy", "client-side-tools", "file-upload"],
        risk_score=50,
        counts=SummaryCounts(medium=4),
    )
    review = AIReviewResult(
        ai_summary="The audit evidence indicates several medium findings.",
        ai_priority="high",
        top_true_risks=["security issues"],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[],
        confidence=0.95,
    )

    result = _sanitize_ai_review(report, review)

    assert result.confidence <= 0.75
    assert result.ai_priority == "medium"


def test_confidence_is_capped_at_point_eight_when_no_high_or_critical_findings() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
            ),
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="The docs install or load configuration directly from a remote URL.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://example.com/agent.json",
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-b/SKILL.md",
            ),
        ],
        counts=SummaryCounts(medium=2),
    )
    review = AIReviewResult(
        ai_summary="This report shows risk.",
        ai_priority="medium",
        top_true_risks=[],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[],
        confidence=0.95,
    )

    result = _sanitize_ai_review(report, review)

    assert result.confidence <= 0.80


def test_top_risk_rendering_normalizes_double_punctuation() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="The docs install or load configuration directly from a remote URL.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://example.com/agent.json",
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-a/SKILL.md",
            )
        ],
        counts=SummaryCounts(medium=1),
    )
    review = AIReviewResult(
        ai_summary="This report shows risk.",
        ai_priority="medium",
        top_true_risks=[],
        top_risks_detailed=[
            {
                "rule_id": "remote-install-manifest",
                "count": 1,
                "label": "Remote install manifest or script execution.",
                "why": "The docs install or load configuration directly from a remote URL, posing a supply-chain risk..",
                "related_capabilities": ["network", "supply-chain"],
            }
        ],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    assert ".." not in result.top_true_risks[0]
    assert "risk.." not in result.top_true_risks[0]


def test_proxy_fix_is_included_when_proxy_is_top_two_risks() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="Remote install documented.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://example.com/agent.json",
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-a/SKILL.md",
            ),
            make_finding(
                rule_id="remote-install-manifest",
                title="Remote install manifest or script execution",
                description="Remote install documented.",
                confidence=0.9,
                snippet="npx shadcn@latest add https://example.com/chat.json",
                doc_url="https://raw.githubusercontent.com/example/repo/main/skills/demo-b/SKILL.md",
            ),
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.9,
                snippet="Create an API route that uses process.env.API_KEY.",
            ),
            make_finding(
                rule_id="unpinned-dependency-install",
                title="Unpinned dependency install",
                description="The docs install a dependency without pinning a version.",
                confidence=0.8,
                snippet="npm install demo-package",
            ),
        ],
        capabilities=["proxy"],
        counts=SummaryCounts(medium=4),
    )
    review = AIReviewResult(
        ai_summary="This report shows risk.",
        ai_priority="medium",
        top_true_risks=[],
        likely_false_positive_candidates=[],
        ai_attack_path=None,
        ai_must_fix_first=[],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    assert "Require authentication and authorization on the proxy route." in result.ai_must_fix_first


def test_false_positive_candidates_only_allow_low_confidence_low_severity_findings() -> None:
    report = make_report(
        [
            make_finding(
                rule_id="missing-guardrails-client-side-tools",
                title="Missing guardrails for documented client-side-tools",
                description="Client-side tools guardrails missing.",
                confidence=0.5,
                snippet="client-side tools",
            ),
            make_finding(
                severity="low",
                rule_id="capability-client-side-tools",
                title="Documented capability: client-side-tools",
                description="Client-side tools are documented.",
                confidence=0.5,
                snippet="client-side tools",
                recommendation=["Document the trust boundary."],
            ),
        ],
        capabilities=["client-side-tools"],
        counts=SummaryCounts(medium=1, low=1),
    )
    review = AIReviewResult(
        ai_summary="Top likely risk: Missing guardrails for documented client-side-tools.",
        ai_priority="medium",
        top_true_risks=["Missing guardrails for documented client-side-tools"],
        likely_false_positive_candidates=[
            "Missing guardrails for documented client-side-tools",
            "Documented capability: client-side-tools",
        ],
        ai_attack_path=None,
        ai_must_fix_first=["Describe the approval model."],
        confidence=0.8,
    )

    result = _sanitize_ai_review(report, review)

    assert result.likely_false_positive_candidates == ["Documented capability: client-side-tools"]


def test_build_evidence_bundle_caps_findings_and_snippet_length() -> None:
    long_snippet = "npx shadcn@latest add https://ui.example.sh/r/agent.json " * 20
    findings = [
        make_finding(
            rule_id="remote-install-manifest",
            title="Remote install manifest or script execution",
            description="Remote install documented.",
            confidence=0.9,
            snippet=long_snippet,
            doc_url=f"https://raw.githubusercontent.com/example/repo/main/skills/demo-{index}/SKILL.md",
        )
        for index in range(4)
    ]
    findings.extend(
        [
            make_finding(
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="Proxy route documented with environment key.",
                confidence=0.95,
                snippet=long_snippet,
            ),
            make_finding(
                rule_id="missing-guardrails-proxy",
                title="Missing guardrails for documented proxy",
                description="Proxy guardrails missing.",
                confidence=0.7,
                snippet=long_snippet,
            ),
            make_finding(
                rule_id="missing-guardrails-file-upload",
                title="Missing guardrails for documented file-upload",
                description="Upload guardrails missing.",
                confidence=0.6,
                snippet=long_snippet,
            ),
            make_finding(
                severity="low",
                rule_id="file-upload-capability",
                title="File upload capability documented",
                description="Uploads documented.",
                confidence=0.5,
                snippet=long_snippet,
            ),
        ]
    )
    report = make_report(
        findings,
        capabilities=["proxy", "file-upload"],
        counts=SummaryCounts(medium=7, low=1),
    )

    bundle = _build_evidence_bundle(report)

    assert len(bundle["findings"]) <= 7
    assert all(item["severity"] in {"medium", "high", "critical"} for item in bundle["findings"])
    assert all(len(item["evidence"]["snippet"]) <= 240 for item in bundle["findings"])
    assert all("recommendation" not in item for item in bundle["findings"])
    assert all("description" in item for item in bundle["findings"])
