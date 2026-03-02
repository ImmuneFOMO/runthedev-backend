from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from app.fetcher import GitHubDocFetcher
from app.main import app
from app.models import AIReviewMeta, AIReviewResult, AIRiskDetail, Evidence, FetchedDoc, Finding, TokenUsage


def _fake_graph() -> SimpleNamespace:
    return SimpleNamespace(
        root_doc_url="https://raw.githubusercontent.com/acme/demo/main/skills/find-skills/SKILL.md",
        docs=[
            SimpleNamespace(
                meta=FetchedDoc(
                    url="https://raw.githubusercontent.com/acme/demo/main/skills/find-skills/SKILL.md",
                    title="Find Skills",
                    content_type="text/plain",
                    char_count=2400,
                    depth=0,
                    sha_like=None,
                )
            )
        ],
        edges=[],
        max_depth_reached=0,
    )


def _make_finding(
    *,
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    snippet: str,
    recommendation: list[str],
) -> Finding:
    return Finding(
        severity=severity,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=title,
        description=description,
        confidence=0.9,
        evidence=Evidence(
            doc_url="https://raw.githubusercontent.com/acme/demo/main/skills/find-skills/SKILL.md",
            section="Quick Start",
            snippet=snippet,
        ),
        recommendation=recommendation,
    )


def test_audit_endpoint_can_inline_ai_review(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_graph(
        self: GitHubDocFetcher,
        *,
        input_url: str,
        max_depth: int,
        max_docs: int,
        max_total_chars: int,
    ):
        return _fake_graph()

    monkeypatch.setattr(GitHubDocFetcher, "fetch_graph", fake_fetch_graph)
    monkeypatch.setattr(
        "app.main.analyze_documents",
        lambda _docs: SimpleNamespace(
            findings=[
                _make_finding(
                    severity="high",
                    rule_id="remote-install-manifest",
                    title="Remote install manifest or script execution",
                    description="The docs install or load configuration directly from a remote URL.",
                    snippet="npx shadcn@latest add https://example.com/skill.json",
                    recommendation=["Prefer pinned versions."],
                )
            ],
            capabilities=["proxy"],
        ),
    )

    async def fake_review(_report):
        return SimpleNamespace(
            ai_review=AIReviewResult(
                ai_summary="Remote install guidance is the main concern.",
                ai_priority="high",
                top_true_risks=["Remote install manifest or script execution"],
                top_risks_detailed=[
                    AIRiskDetail(
                        rule_id="remote-install-manifest",
                        count=1,
                        label="remote install manifest",
                        why="Remote installs should be pinned.",
                        related_capabilities=["supply-chain"],
                    )
                ],
                likely_false_positive_candidates=["none"],
                ai_attack_path=None,
                ai_must_fix_first=["Prefer pinned versions."],
                confidence=0.8,
            ),
            meta=AIReviewMeta(
                reviewer_used="mistral",
                fallback_reason=None,
                token_usage=TokenUsage(input_tokens=100, output_tokens=20, total_tokens=120),
            ),
        )

    monkeypatch.setattr("app.main.ai_reviewer.review", fake_review)

    client = TestClient(app)
    response = client.post(
        "/audit",
        json={
            "url": "https://github.com/acme/demo/blob/main/skills/find-skills/SKILL.md",
            "ai_explain": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ai_review"]["ai_priority"] == "high"
    assert payload["meta"]["reviewer_used"] == "mistral"
    assert payload["summary"]["counts"]["high"] == 1


def test_audit_summary_endpoint_returns_compact_skill_view(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_graph(
        self: GitHubDocFetcher,
        *,
        input_url: str,
        max_depth: int,
        max_docs: int,
        max_total_chars: int,
    ):
        return _fake_graph()

    monkeypatch.setattr(GitHubDocFetcher, "fetch_graph", fake_fetch_graph)
    monkeypatch.setattr(
        "app.main.analyze_documents",
        lambda _docs: SimpleNamespace(
            findings=[
                _make_finding(
                    severity="high",
                    rule_id="remote-install-manifest",
                    title="Remote install manifest or script execution",
                    description="The docs install from a remote manifest.",
                    snippet="npx shadcn@latest add https://example.com/skill.json",
                    recommendation=["Prefer pinned versions."],
                ),
                _make_finding(
                    severity="medium",
                    rule_id="capability-shell",
                    title="Documented capability: shell",
                    description="Shell command execution is documented.",
                    snippet="Run commands with npx skills add",
                    recommendation=["Use least privilege."],
                ),
            ],
            capabilities=["proxy", "shell"],
        ),
    )

    async def fake_review(_report):
        return SimpleNamespace(
            ai_review=AIReviewResult(
                ai_summary="External downloads and command execution need caution.",
                ai_priority="high",
                top_true_risks=[
                    "Remote install manifest or script execution",
                    "Documented capability: shell",
                ],
                top_risks_detailed=[
                    AIRiskDetail(
                        rule_id="remote-install-manifest",
                        count=1,
                        label="remote install manifest",
                        why="Downloads code from external sources.",
                        related_capabilities=["supply-chain"],
                    ),
                    AIRiskDetail(
                        rule_id="capability-shell",
                        count=1,
                        label="shell execution",
                        why="Runs commands on the host.",
                        related_capabilities=["shell"],
                    ),
                ],
                likely_false_positive_candidates=["none"],
                ai_attack_path=None,
                ai_must_fix_first=[
                    "Prefer pinned versions.",
                    "Use least privilege.",
                ],
                confidence=0.82,
            ),
            meta=AIReviewMeta(
                reviewer_used="mistral",
                fallback_reason=None,
                token_usage=TokenUsage(input_tokens=120, output_tokens=25, total_tokens=145),
            ),
        )

    monkeypatch.setattr("app.main.ai_reviewer.review", fake_review)

    client = TestClient(app)
    response = client.post(
        "/audit/skill/summary",
        json={
            "url": "https://github.com/acme/demo/blob/main/skills/find-skills/SKILL.md",
            "ai_explain": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["skill_name"] == "find-skills"
    assert payload["status"] == "Fail"
    assert payload["audited_by"] == "Run The Dev"
    assert payload["risk_level"] == "HIGH"
    assert payload["security_audits"] == [{"provider": "Run The Dev", "status": "Fail"}]
    assert payload["risk_categories"] == ["EXTERNAL_DOWNLOADS", "COMMAND_EXECUTION"]
    assert payload["full_analysis"][0]["category"] == "EXTERNAL_DOWNLOADS"
    assert "Prefer pinned versions." in payload["safe_usage_recommendations"]


def test_audit_summary_downgrades_capability_only_skill_risks(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_graph(
        self: GitHubDocFetcher,
        *,
        input_url: str,
        max_depth: int,
        max_docs: int,
        max_total_chars: int,
    ):
        return _fake_graph()

    monkeypatch.setattr(GitHubDocFetcher, "fetch_graph", fake_fetch_graph)
    monkeypatch.setattr(
        "app.main.analyze_documents",
        lambda _docs: SimpleNamespace(
            findings=[
                _make_finding(
                    severity="high",
                    rule_id="missing-guardrails-k8s",
                    title="Missing guardrails for documented k8s",
                    description="The docs describe k8s capability but do not mention allowlists, sandboxing, permissions, authentication, or origin restrictions.",
                    snippet="Run kubectl commands against the cluster",
                    recommendation=["Describe the approval or permission model explicitly."],
                ),
                _make_finding(
                    severity="low",
                    rule_id="capability-k8s",
                    title="Documented capability: k8s",
                    description="Kubernetes or cluster administration capability is documented.",
                    snippet="kubectl get pods",
                    recommendation=["Document the intended trust boundary for this capability."],
                ),
            ],
            capabilities=["k8s"],
        ),
    )

    async def fake_review(_report):
        return SimpleNamespace(
            ai_review=AIReviewResult(
                ai_summary="Kubernetes capability is documented, but guardrails are not described.",
                ai_priority="high",
                top_true_risks=[
                    "Missing guardrails for documented k8s",
                    "Documented capability: k8s",
                ],
                top_risks_detailed=[
                    AIRiskDetail(
                        rule_id="missing-guardrails-k8s",
                        count=1,
                        label="k8s guardrails",
                        why="Permissions and access restrictions are not documented.",
                        related_capabilities=["k8s"],
                    )
                ],
                likely_false_positive_candidates=["none"],
                ai_attack_path=None,
                ai_must_fix_first=[
                    "Describe the approval or permission model explicitly.",
                    "Document the intended trust boundary for this capability.",
                ],
                confidence=0.8,
            ),
            meta=AIReviewMeta(
                reviewer_used="mistral",
                fallback_reason=None,
                token_usage=TokenUsage(input_tokens=90, output_tokens=18, total_tokens=108),
            ),
        )

    monkeypatch.setattr("app.main.ai_reviewer.review", fake_review)

    client = TestClient(app)
    response = client.post(
        "/audit/skill/summary",
        json={
            "url": "https://github.com/acme/demo/blob/main/skills/find-skills/SKILL.md",
            "ai_explain": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "Warn"
    assert payload["risk_level"] == "CAUTION"
    assert payload["risk_categories"] == ["KUBERNETES_ACCESS"]
