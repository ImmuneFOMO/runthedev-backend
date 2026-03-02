from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.ai_classifier import (
    _parse_overall_response,
    _parse_response,
    ClassificationResult,
    classify_findings,
    classify_overall_audit,
    synthesize_overall_from_finding_results,
)
from app.models import CodeEvidence, CodeFinding


def make_finding(rule_id: str, file_path: str, snippet: str, *, severity: str = "medium", context: str = "server", nearby: str = "") -> CodeFinding:
    return CodeFinding(
        severity=severity,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=rule_id,
        description="desc",
        confidence=0.8,
        evidence=CodeEvidence(file_path=file_path, line=10, snippet=snippet),
        recommendation=["fix"],
        context=context,
        nearby_context=nearby,
    )


def test_parse_response_requires_tabs_and_four_fields() -> None:
    parsed = _parse_response(
        "0\tlikely_fp\tlow\t0.75\n1 likely_fp low 0.20\n2\tuncertain\tmedium\t0.50\textra",
        [3, 7],
    )

    assert parsed == [(3, "likely_fp", "low", 0.75)]


def test_invalid_lines_ignored() -> None:
    parsed = _parse_response(
        "0\tbad\tlow\t0.90\n1\tlikely_fp\tinvalid\t0.60\n0\tuncertain\tmedium\tnope\n1\tuncertain\tmedium\t0.40",
        [4, 9],
    )

    assert parsed == [(9, "uncertain", "medium", 0.4)]


def test_parse_response_accepts_pipe_delimited_lines() -> None:
    parsed = _parse_response(
        "0 | likely_fp | low | 0.75\n1 | uncertain | medium | 0.40",
        [3, 7],
    )

    assert parsed == [(3, "likely_fp", "low", 0.75), (7, "uncertain", "medium", 0.4)]


def test_parse_response_accepts_fenced_output_and_double_space_separators() -> None:
    parsed = _parse_response(
        "```text\n0  likely_tp  medium  0.66\n1  likely_fp  none  0.91\n```",
        [8, 11],
    )

    assert parsed == [(8, "likely_tp", "medium", 0.66), (11, "likely_fp", "none", 0.91)]


def test_parse_response_accepts_json_array_fallback() -> None:
    parsed = _parse_response(
        '[{"id": 0, "verdict": "likely_fp", "risk": "low", "confidence": 0.75}, {"id": 1, "verdict": "uncertain", "risk": "medium", "confidence": 0.4}]',
        [3, 7],
    )

    assert parsed == [(3, "likely_fp", "low", 0.75), (7, "uncertain", "medium", 0.4)]


def test_parse_response_accepts_fenced_json_results_object() -> None:
    parsed = _parse_response(
        '```json\n{"results":[{"finding_index":0,"verdict":"likely_tp","risk":"high","confidence":0.81}]}\n```',
        [5],
    )

    assert parsed == [(5, "likely_tp", "high", 0.81)]


def test_parse_response_normalizes_common_vocab_variants_and_percent_confidence() -> None:
    parsed = _parse_response(
        '0\tLIKELY_FALSE\tSAFE\t75%\n1\t"likely true"\t"HIGH"\t"0.80"\n2\ttrue_positive\tcritical\t100',
        [2, 4, 9],
    )

    assert parsed == [
        (2, "likely_fp", "none", 0.75),
        (4, "likely_tp", "high", 0.8),
        (9, "tp", "critical", 1.0),
    ]


def test_parse_response_accepts_qualitative_confidence_labels() -> None:
    parsed = _parse_response(
        "0\tlikely_tp\thigh\thigh\n1\tuncertain\tmedium\tmedium\n2\tlikely_fp\tlow\tlow",
        [1, 3, 8],
    )

    assert parsed == [
        (1, "likely_tp", "high", 0.85),
        (3, "uncertain", "medium", 0.6),
        (8, "likely_fp", "low", 0.35),
    ]


def test_parse_response_infers_missing_risk_from_finding_when_row_has_three_fields() -> None:
    parsed = _parse_response(
        "0\tlikely_fp\t0.75\n1\tlikely_tp\t0.80",
        [0, 1],
        findings=[
            make_finding("path-traversal", "a.py", "import '../x'", severity="medium"),
            make_finding("ssrf-fetch", "b.py", "requests.get(url)", severity="high"),
        ],
    )

    assert parsed == [
        (0, "likely_fp", "none", 0.75),
        (1, "likely_tp", "high", 0.8),
    ]


def test_parse_overall_response_accepts_tab_format() -> None:
    result = _parse_overall_response(
        "likely_tp\thigh\t0.82\trestrict file paths | add auth on dangerous tools | add allowlists"
    )

    assert result is not None
    assert result.verdict == "likely_tp"
    assert result.risk == "high"
    assert result.confidence == 0.82
    assert result.recommendations == [
        "restrict file paths",
        "add auth on dangerous tools",
        "add allowlists",
    ]


def test_parse_overall_response_accepts_json_fallback() -> None:
    result = _parse_overall_response(
        '{"verdict":"LIKELY_FALSE","risk":"SAFE","confidence":"75%","recommendations":["keep path sandboxing","keep auth checks"]}'
    )

    assert result is not None
    assert result.verdict == "likely_fp"
    assert result.risk == "none"
    assert result.confidence == 0.75
    assert result.recommendations == ["keep path sandboxing", "keep auth checks"]


def test_dedupe_reuses_classification(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_prompts: list[str] = []

    @dataclass
    class FakeResponse:
        content: str
        status_code: int = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"choices": [{"message": {"content": self.content}}]}

    def fake_post(*_args: object, **kwargs: object) -> FakeResponse:
        payload = kwargs["json"]  # type: ignore[index]
        captured_prompts.append(payload["messages"][1]["content"])  # type: ignore[index]
        return FakeResponse("0\tlikely_fp\tlow\t0.80")

    monkeypatch.setattr("app.ai_classifier.requests.post", fake_post)

    findings = [
        make_finding("arbitrary-file-read", "api.py", "open(user_path)"),
        make_finding("arbitrary-file-read", "api.py", "open(user_path)"),
    ]

    results = classify_findings(findings, "test-key", batch_size=8)

    assert [item.finding_index for item in results] == [0, 1]
    assert all(item.verdict == "likely_fp" for item in results)
    assert captured_prompts
    assert captured_prompts[0].count("arbitrary-file-read|") == 1


def test_cap_to_25_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    call_count = 0

    @dataclass
    class FakeResponse:
        content: str
        status_code: int = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"choices": [{"message": {"content": self.content}}]}

    def fake_post(*_args: object, **kwargs: object) -> FakeResponse:
        nonlocal call_count
        call_count += 1
        prompt = kwargs["json"]["messages"][1]["content"]  # type: ignore[index]
        lines = [line for line in prompt.splitlines() if line and line[0].isdigit() and "|" in line]
        return FakeResponse("\n".join(f"{idx}\tuncertain\tmedium\t0.50" for idx in range(len(lines))))

    monkeypatch.setattr("app.ai_classifier.requests.post", fake_post)

    findings = [
        make_finding("arbitrary-file-read", f"file-{index}.py", f"open(path_{index})", severity="medium")
        for index in range(30)
    ]

    results = classify_findings(findings, "test-key", batch_size=8)

    assert len(results) == 25
    assert call_count == 4


def test_fallback_on_failure_returns_empty_results(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("timeout")

    monkeypatch.setattr("app.ai_classifier.requests.post", fake_post)

    results = classify_findings([make_finding("ssrf-fetch", "api.py", "requests.get(url)")], "test-key")

    assert results == []


def test_classify_overall_audit_returns_repo_level_result(monkeypatch: pytest.MonkeyPatch) -> None:
    @dataclass
    class FakeResponse:
        content: str
        status_code: int = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"choices": [{"message": {"content": self.content}}]}

    def fake_post(*_args: object, **_kwargs: object) -> FakeResponse:
        return FakeResponse("likely_tp\thigh\t0.83\trestrict file paths | add approval gates")

    monkeypatch.setattr("app.ai_classifier.requests.post", fake_post)

    result = classify_overall_audit(
        [
            make_finding("arbitrary-file-read", "server.py", "open(file_path)", severity="high", context="mcp"),
            make_finding("ssrf-fetch", "server.py", "requests.get(url)", severity="medium", context="mcp"),
        ],
        ["filesystem", "network"],
        "test-key",
        max_findings=4,
    )

    assert result is not None
    assert result.verdict == "likely_tp"
    assert result.risk == "high"
    assert result.confidence == 0.83
    assert result.recommendations == ["restrict file paths", "add approval gates"]


def test_synthesize_overall_from_finding_results_returns_fallback_summary() -> None:
    findings = [
        make_finding("arbitrary-file-read", "server.py", "open(file_path)", severity="high", context="mcp"),
        make_finding("arbitrary-file-write", "utils.py", "open(output_path)", severity="medium", context="mcp"),
        make_finding("arbitrary-file-read", "server.py", "file_path.open()", severity="medium", context="mcp"),
    ]
    results = [
        ClassificationResult(finding_index=0, verdict="likely_tp", risk="high", confidence=0.75),
        ClassificationResult(finding_index=1, verdict="likely_tp", risk="high", confidence=0.75),
        ClassificationResult(finding_index=2, verdict="likely_tp", risk="high", confidence=0.75),
    ]

    overall = synthesize_overall_from_finding_results(findings, results)

    assert overall is not None
    assert overall.verdict == "likely_tp"
    assert overall.risk == "high"
    assert overall.confidence == 0.75
    assert overall.recommendations == [
        "Restrict file paths to a dedicated base directory and normalize them before use",
        "Restrict writes to a dedicated base directory and block sensitive paths",
    ]
