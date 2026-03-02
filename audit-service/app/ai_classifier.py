from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import math
import re

import requests

from .models import CodeFinding


logger = logging.getLogger(__name__)

VALID_VERDICTS = {"tp", "likely_tp", "uncertain", "likely_fp"}
VALID_RISKS = {"critical", "high", "medium", "low", "none"}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
MAX_FINDINGS = 25
MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
SYSTEM_PROMPT = (
    "Classify code-audit findings. Output only one line per id. "
    "Format: <id>\\t<verdict>\\t<risk>\\t<confidence>. "
    "Verdict: tp|likely_tp|uncertain|likely_fp. "
    "Risk: critical|high|medium|low|none. "
    "Confidence must be numeric 0.00..1.00 only. "
    "No prose, no markdown, no JSON, no extra lines."
)
USER_PROMPT_PREFIX = (
    "Rules: tp if untrusted input clearly reaches dangerous runtime sink without visible checks. "
    "likely_fp if CLI/tooling/local script, safe repo-local path, temp/build output, ${ENV}, process.env, secrets.X, or placeholder. "
    "If context=cli and no network exposure, downgrade one level and verdict at most likely_tp. "
    "For file access elevate only with untrusted filename/path plus no base-dir restriction. "
    "For SSRF/open-proxy critical only if user URL and no allowlist/private-IP blocking. "
    "For hardcoded-secret tp only for likely live literals like ghp_, AKIA, sk_live_, not env references. "
    "Confidence must be a decimal between 0.00 and 1.00, never words like high/medium/low. "
    "Input lines follow as id|rule|context|file|snippet|nearby."
)
STRICT_FORMAT_REMINDER = "Reminder: return exactly one tab-separated line per id and nothing else."
LINE_PATTERN = re.compile(
    r"^\s*`*([^|\t]+?)`*\s*(?:\t+|\s*\|\s*|\s{2,})"
    r"(.+?)\s*(?:\t+|\s*\|\s*|\s{2,})"
    r"(.+?)\s*(?:\t+|\s*\|\s*|\s{2,})"
    r"(.+?)\s*$"
)
INTEGER_PATTERN = re.compile(r"\d+")


@dataclass(slots=True)
class ClassificationResult:
    finding_index: int
    verdict: str
    risk: str
    confidence: float


@dataclass(slots=True)
class OverallClassificationResult:
    verdict: str
    risk: str
    confidence: float
    recommendations: list[str]


OVERALL_SYSTEM_PROMPT = (
    "Assess one MCP/server code audit as a whole. Output exactly one line. "
    "Format: <verdict>\\t<risk>\\t<confidence>\\t<rec1> | <rec2> | <rec3>. "
    "Verdict: tp|likely_tp|uncertain|likely_fp. "
    "Risk: critical|high|medium|low|none. "
    "Confidence must be numeric 0.00..1.00 only. "
    "Recommendations must be short imperative phrases. "
    "No prose, no markdown, no JSON, no numbering."
)
OVERALL_USER_PROMPT_PREFIX = (
    "Judge the whole repo from bounded deterministic findings only. "
    "Treat MCP/server code as remotely reachable unless evidence suggests CLI/local tooling. "
    "Downgrade for unclear reachability. "
    "Recommendations should be minimal safety actions such as base-dir restriction, auth, approval gates, allowlists, sandboxing, webhook verification, or secret removal. "
    "Input follows."
)


def classify_findings(
    findings: list[CodeFinding],
    mistral_api_key: str,
    model: str = "mistral-small-latest",
    batch_size: int = 8,
) -> list[ClassificationResult]:
    if not mistral_api_key or not findings:
        logger.info(
            "AI triage skipped before classification: api_key_present=%s findings=%s",
            bool(mistral_api_key),
            len(findings),
        )
        return []

    try:
        selected = _select_findings(findings, cap=MAX_FINDINGS)
        if not selected:
            logger.info("AI triage selected no findings after dedupe/cap")
            return []

        grouped = _group_duplicate_indices(findings)
        results: list[ClassificationResult] = []
        total_unique = len(selected)
        logger.info(
            "AI triage classifying %s unique findings across %s batches (input=%s deduped=%s cap=%s model=%s batch_size=%s)",
            total_unique,
            math.ceil(total_unique / batch_size),
            len(findings),
            len(grouped),
            MAX_FINDINGS,
            model,
            batch_size,
        )

        for start in range(0, total_unique, batch_size):
            batch_indices = selected[start : start + batch_size]
            parsed = _classify_batch(
                findings,
                batch_indices,
                mistral_api_key,
                model,
                strict_retry=False,
                batch_number=(start // batch_size) + 1,
                total_batches=math.ceil(total_unique / batch_size),
            )
            for rep_index, verdict, risk, confidence in parsed:
                for finding_index in grouped[_fingerprint(findings[rep_index])]:
                    results.append(
                        ClassificationResult(
                            finding_index=finding_index,
                            verdict=verdict,
                            risk=risk,
                            confidence=confidence,
                        )
                    )

        results.sort(key=lambda item: item.finding_index)
        logger.info(
            "AI triage finished: mapped_results=%s unique_results=%s",
            len(results),
            len({(item.finding_index, item.verdict, item.risk, item.confidence) for item in results}),
        )
        return results
    except Exception as exc:  # pragma: no cover - guarded by tests via stubbed failure
        logger.warning("AI triage fallback triggered: %s", exc)
        return []


def classify_overall_audit(
    findings: list[CodeFinding],
    capabilities: list[str],
    mistral_api_key: str,
    model: str = "mistral-small-latest",
    max_findings: int = 6,
) -> OverallClassificationResult | None:
    if not mistral_api_key or not findings:
        logger.info(
            "AI overall triage skipped before classification: api_key_present=%s findings=%s",
            bool(mistral_api_key),
            len(findings),
        )
        return None

    try:
        selected = _select_findings(findings, cap=max_findings)
        if not selected:
            logger.info("AI overall triage selected no findings after dedupe/cap")
            return None

        logger.info(
            "AI overall triage classifying repo summary: findings=%s selected=%s capabilities=%s model=%s",
            len(findings),
            len(selected),
            len(capabilities),
            model,
        )
        content = _send_overall_request(findings, selected, capabilities, mistral_api_key, model)
        result = _parse_overall_response(content)
        if result is None:
            logger.warning("AI overall triage produced no usable result")
            return None
        logger.info(
            "AI overall triage attached: risk=%s confidence=%.2f recommendations=%s",
            result.risk,
            result.confidence,
            len(result.recommendations),
        )
        return result
    except Exception as exc:  # pragma: no cover - guarded by tests via stubbed failure
        logger.warning("AI overall triage fallback triggered: %s", exc)
        return None


def synthesize_overall_from_finding_results(
    findings: list[CodeFinding],
    results: list[ClassificationResult],
) -> OverallClassificationResult | None:
    if not results:
        return None

    risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    verdict_order = {"likely_fp": 0, "uncertain": 1, "likely_tp": 2, "tp": 3}

    top_result = max(
        results,
        key=lambda item: (
            risk_order.get(item.risk, 0),
            verdict_order.get(item.verdict, 0),
            item.confidence,
            -item.finding_index,
        ),
    )

    verdict = top_result.verdict
    risk = top_result.risk
    top_confidences = sorted((item.confidence for item in results), reverse=True)[:3]
    confidence = round(sum(top_confidences) / len(top_confidences), 2)

    recommendations: list[str] = []
    seen_rule_ids: set[str] = set()
    for result in sorted(
        results,
        key=lambda item: (
            -risk_order.get(item.risk, 0),
            -verdict_order.get(item.verdict, 0),
            -item.confidence,
            item.finding_index,
        ),
    ):
        finding = findings[result.finding_index]
        if finding.rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(finding.rule_id)
        recommendation = _overall_recommendation_for_rule(finding.rule_id)
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
        if len(recommendations) >= 3:
            break

    return OverallClassificationResult(
        verdict=verdict,
        risk=risk,
        confidence=confidence,
        recommendations=recommendations,
    )


def _classify_batch(
    findings: list[CodeFinding],
    batch_indices: list[int],
    api_key: str,
    model: str,
    *,
    strict_retry: bool,
    batch_number: int,
    total_batches: int,
) -> list[tuple[int, str, str, float]]:
    try:
        logger.info(
            "AI triage batch start: batch=%s/%s batch_size=%s strict_retry=%s",
            batch_number,
            total_batches,
            len(batch_indices),
            strict_retry,
        )
        content = _send_batch_request(findings, batch_indices, api_key, model, strict=strict_retry)
    except Exception as exc:
        logger.warning(
            "AI triage batch request failed: batch=%s/%s strict_retry=%s error=%s",
            batch_number,
            total_batches,
            strict_retry,
            exc,
        )
        if not strict_retry:
            logger.info("AI triage batch retrying with strict format reminder: batch=%s/%s", batch_number, total_batches)
            return _classify_batch(
                findings,
                batch_indices,
                api_key,
                model,
                strict_retry=True,
                batch_number=batch_number,
                total_batches=total_batches,
            )
        return []
    parsed = _parse_response(content, batch_indices, findings=findings)
    expected = set(batch_indices)
    received = {item[0] for item in parsed}
    logger.info(
        "AI triage batch parsed: batch=%s/%s strict_retry=%s expected=%s parsed=%s",
        batch_number,
        total_batches,
        strict_retry,
        len(expected),
        len(received),
    )
    if received == expected:
        return parsed
    if not strict_retry:
        logger.info(
            "AI triage batch missing parsed rows; retrying with strict format reminder: batch=%s/%s missing=%s",
            batch_number,
            total_batches,
            len(expected - received),
        )
        retry = _classify_batch(
            findings,
            batch_indices,
            api_key,
            model,
            strict_retry=True,
            batch_number=batch_number,
            total_batches=total_batches,
        )
        if retry:
            return retry
    logger.warning(
        "AI triage batch returning partial/empty parse result: batch=%s/%s strict_retry=%s expected=%s parsed=%s",
        batch_number,
        total_batches,
        strict_retry,
        len(expected),
        len(received),
    )
    return parsed


def _send_batch_request(
    findings: list[CodeFinding],
    batch_indices: list[int],
    api_key: str,
    model: str,
    *,
    strict: bool,
) -> str:
    user_prompt = _build_user_prompt(findings, batch_indices, strict=strict)
    logger.info(
        "AI triage HTTP request: model=%s strict=%s findings=%s prompt_chars=%s",
        model,
        strict,
        len(batch_indices),
        len(user_prompt),
    )
    response = requests.post(
        MISTRAL_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "temperature": 0,
            "max_tokens": max(64, 24 * len(batch_indices)),
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        },
        timeout=15,
    )
    logger.info(
        "AI triage HTTP response: status_code=%s strict=%s findings=%s",
        response.status_code,
        strict,
        len(batch_indices),
    )
    response.raise_for_status()
    payload = response.json()
    content = str(payload["choices"][0]["message"]["content"])
    logger.info(
        "AI triage HTTP content received: response_chars=%s response_lines=%s",
        len(content),
        len(content.splitlines()),
    )
    return content


def _send_overall_request(
    findings: list[CodeFinding],
    selected_indices: list[int],
    capabilities: list[str],
    api_key: str,
    model: str,
) -> str:
    user_prompt = _build_overall_user_prompt(findings, selected_indices, capabilities)
    logger.info(
        "AI overall triage HTTP request: model=%s findings=%s prompt_chars=%s",
        model,
        len(selected_indices),
        len(user_prompt),
    )
    response = requests.post(
        MISTRAL_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "temperature": 0,
            "max_tokens": 160,
            "messages": [
                {"role": "system", "content": OVERALL_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        },
        timeout=15,
    )
    logger.info("AI overall triage HTTP response: status_code=%s", response.status_code)
    response.raise_for_status()
    payload = response.json()
    content = str(payload["choices"][0]["message"]["content"])
    logger.info(
        "AI overall triage HTTP content received: response_chars=%s response_lines=%s",
        len(content),
        len(content.splitlines()),
    )
    return content


def _build_user_prompt(findings: list[CodeFinding], batch_indices: list[int], *, strict: bool) -> str:
    lines = [_serialize_finding(local_id, findings[finding_index]) for local_id, finding_index in enumerate(batch_indices)]
    prompt = f"{USER_PROMPT_PREFIX}\n"
    if strict:
        prompt += f"{STRICT_FORMAT_REMINDER}\n"
    prompt += "\n".join(lines)
    return prompt


def _build_overall_user_prompt(findings: list[CodeFinding], selected_indices: list[int], capabilities: list[str]) -> str:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary_line = (
        f"summary|critical={counts['critical']}|high={counts['high']}|medium={counts['medium']}|"
        f"low={counts['low']}|capabilities={','.join(capabilities) or 'none'}"
    )
    finding_lines = []
    for local_id, finding_index in enumerate(selected_indices):
        finding = findings[finding_index]
        context = _sanitize_field(finding.context or "unknown", 16)
        file_path = _sanitize_field(finding.evidence.file_path, 100)
        snippet = _sanitize_field(finding.evidence.snippet, 180)
        finding_lines.append(
            f"{local_id}|{finding.severity}|{finding.rule_id}|{context}|{file_path}|{snippet}"
        )
    return f"{OVERALL_USER_PROMPT_PREFIX}\n{summary_line}\n" + "\n".join(finding_lines)


def _serialize_finding(local_id: int, finding: CodeFinding) -> str:
    context = _sanitize_field(finding.context or "unknown", 16)
    file_path = _sanitize_field(finding.evidence.file_path, 120)
    snippet = _sanitize_field(finding.evidence.snippet, 220)
    nearby = _sanitize_field(finding.nearby_context or "", 600)
    return f"{local_id}|{finding.rule_id}|{context}|{file_path}|{snippet}|{nearby}"


def _parse_response(
    content: str,
    batch_indices: list[int],
    *,
    findings: list[CodeFinding] | None = None,
) -> list[tuple[int, str, str, float]]:
    parsed: list[tuple[int, str, str, float]] = []
    invalid_wrong_fields = 0
    invalid_vocab = 0
    invalid_number = 0
    invalid_range = 0
    non_data_lines = 0
    format_hints = {
        "tabs": 0,
        "pipes": 0,
        "double_space": 0,
        "fenced": 0,
    }
    sample_shapes: list[str] = []
    rejected_tokens: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            non_data_lines += 1
            continue
        if line.startswith("```"):
            format_hints["fenced"] += 1
            non_data_lines += 1
            continue
        if "\t" in line:
            format_hints["tabs"] += 1
        if "|" in line:
            format_hints["pipes"] += 1
        if "  " in line:
            format_hints["double_space"] += 1

        parts = line.rstrip().split("\t")
        if len(parts) == 4:
            raw_id, raw_verdict, raw_risk, raw_confidence = parts
        elif len(parts) == 3:
            raw_id, raw_verdict, raw_confidence = parts
            raw_risk = ""
        else:
            match = LINE_PATTERN.match(line)
            if not match:
                invalid_wrong_fields += 1
                if len(sample_shapes) < 2:
                    sample_shapes.append(_describe_line_shape(line))
                continue
            raw_id, raw_verdict, raw_risk, raw_confidence = match.groups()

        verdict = _normalize_verdict(raw_verdict)
        risk = _normalize_risk(raw_risk)
        inferred_risk: str | None = None
        if risk is None and len(parts) == 3 and findings is not None:
            try:
                local_id = _parse_local_id(raw_id)
            except ValueError:
                local_id = -1
            if 0 <= local_id < len(batch_indices):
                inferred_risk = _infer_risk_from_finding(findings[batch_indices[local_id]], verdict)
                risk = inferred_risk
        if verdict is None or risk is None:
            invalid_vocab += 1
            if len(rejected_tokens) < 3:
                rejected_tokens.append(
                    f"verdict={_token_preview(raw_verdict)},"
                    f"risk={_token_preview(raw_risk)},"
                    f"confidence={_token_preview(raw_confidence)}"
                )
            continue
        try:
            local_id = _parse_local_id(raw_id)
            confidence = _parse_confidence(raw_confidence)
        except ValueError:
            invalid_number += 1
            if len(rejected_tokens) < 3:
                rejected_tokens.append(
                    f"id={_token_preview(raw_id)},confidence={_token_preview(raw_confidence)}"
                )
            continue
        if local_id < 0 or local_id >= len(batch_indices):
            invalid_range += 1
            if len(rejected_tokens) < 3:
                rejected_tokens.append(f"id={_token_preview(raw_id)}")
            continue
        if not (0.0 <= confidence <= 1.0):
            invalid_range += 1
            if len(rejected_tokens) < 3:
                rejected_tokens.append(f"confidence={_token_preview(raw_confidence)}")
            continue
        parsed.append((batch_indices[local_id], verdict, risk, round(confidence, 2)))
    if not parsed:
        parsed = _parse_json_like_response(content, batch_indices)
        if parsed:
            logger.warning(
                "AI triage salvaged malformed model output via JSON-like fallback: parsed=%s total_lines=%s",
                len(parsed),
                len(content.splitlines()),
            )
    logger.info(
        "AI triage parse stats: total_lines=%s valid=%s invalid_wrong_fields=%s invalid_vocab=%s invalid_number=%s invalid_range=%s non_data_lines=%s format_hints=%s sample_shapes=%s",
        len(content.splitlines()),
        len(parsed),
        invalid_wrong_fields,
        invalid_vocab,
        invalid_number,
        invalid_range,
        non_data_lines,
        format_hints,
        sample_shapes,
    )
    if not parsed:
        logger.warning(
            "AI triage produced no parseable rows: total_lines=%s invalid_vocab=%s invalid_number=%s invalid_range=%s non_data_lines=%s format_hints=%s sample_shapes=%s rejected_tokens=%s",
            len(content.splitlines()),
            invalid_vocab,
            invalid_number,
            invalid_range,
            non_data_lines,
            format_hints,
            sample_shapes,
            rejected_tokens,
        )
    return parsed


def _parse_overall_response(content: str) -> OverallClassificationResult | None:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("```"):
            continue
        parts = line.split("\t", 3)
        if len(parts) == 4:
            raw_verdict, raw_risk, raw_confidence, raw_recommendations = parts
            verdict = _normalize_verdict(raw_verdict)
            risk = _normalize_risk(raw_risk)
            if verdict is None or risk is None:
                continue
            try:
                confidence = _parse_confidence(raw_confidence)
            except ValueError:
                continue
            if not (0.0 <= confidence <= 1.0):
                continue
            return OverallClassificationResult(
                verdict=verdict,
                risk=risk,
                confidence=round(confidence, 2),
                recommendations=_parse_recommendations(raw_recommendations),
            )

    payload = _load_json_like_payload(content)
    if isinstance(payload, dict):
        verdict = _normalize_verdict(str(payload.get("verdict", "")))
        risk = _normalize_risk(str(payload.get("risk", "")))
        raw_confidence = payload.get("confidence")
        if verdict is None or risk is None or raw_confidence is None:
            return None
        try:
            confidence = _parse_confidence(str(raw_confidence))
        except ValueError:
            return None
        raw_recommendations = payload.get("recommendations", [])
        return OverallClassificationResult(
            verdict=verdict,
            risk=risk,
            confidence=round(confidence, 2),
            recommendations=_normalize_recommendations(raw_recommendations),
        )

    logger.warning(
        "AI overall triage produced no parseable line: total_lines=%s sample_shapes=%s",
        len(content.splitlines()),
        [_describe_line_shape(line.strip()) for line in content.splitlines() if line.strip()][:2],
    )
    return None


def _select_findings(findings: list[CodeFinding], cap: int) -> list[int]:
    grouped = _group_duplicate_indices(findings)
    ordered: list[int] = []
    seen: set[tuple[str, str, str]] = set()
    for index in sorted(
        range(len(findings)),
        key=lambda item: (
            -SEVERITY_ORDER.get(findings[item].severity, 0),
            -findings[item].confidence,
            findings[item].evidence.file_path,
            findings[item].evidence.line or 0,
            findings[item].rule_id,
        ),
    ):
        fingerprint = _fingerprint(findings[index])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        ordered.append(index)
        if len(ordered) >= cap:
            break
    return ordered


def _group_duplicate_indices(findings: list[CodeFinding]) -> dict[tuple[str, str, str], list[int]]:
    grouped: dict[tuple[str, str, str], list[int]] = {}
    for index, finding in enumerate(findings):
        grouped.setdefault(_fingerprint(finding), []).append(index)
    return grouped


def _fingerprint(finding: CodeFinding) -> tuple[str, str, str]:
    return (finding.rule_id, finding.evidence.file_path, finding.evidence.snippet)


def _sanitize_field(value: str, limit: int) -> str:
    compact = " ".join(value.replace("\t", " ").replace("\n", " ").replace("|", "/").split())
    return compact[:limit]


def _describe_line_shape(line: str) -> str:
    lowered = line.lower()
    tokens = len(line.split())
    has_tab = "\t" in line
    has_pipe = "|" in line
    has_colon = ":" in line
    has_digit = any(ch.isdigit() for ch in line)
    has_verdict = any(term in lowered for term in VALID_VERDICTS)
    has_risk = any(term in lowered for term in VALID_RISKS)
    return (
        f"len={len(line)}"
        f",tokens={tokens}"
        f",prefix={repr(line[:16])}"
        f",has_tab={has_tab}"
        f",has_pipe={has_pipe}"
        f",has_colon={has_colon}"
        f",has_digit={has_digit}"
        f",has_verdict={has_verdict}"
        f",has_risk={has_risk}"
    )


def _normalize_verdict(value: str) -> str | None:
    token = _canonical_token(value)
    mapping = {
        "tp": "tp",
        "truepositive": "tp",
        "true_positive": "tp",
        "true positive": "tp",
        "likelytp": "likely_tp",
        "likely_tp": "likely_tp",
        "likelytrue": "likely_tp",
        "likely_true": "likely_tp",
        "likely true": "likely_tp",
        "uncertain": "uncertain",
        "unknown": "uncertain",
        "ambiguous": "uncertain",
        "likelyfp": "likely_fp",
        "likely_fp": "likely_fp",
        "likelyfalse": "likely_fp",
        "likely_false": "likely_fp",
        "likely false": "likely_fp",
        "falsepositive": "likely_fp",
        "false_positive": "likely_fp",
        "false positive": "likely_fp",
        "benign": "likely_fp",
        "safe": "likely_fp",
    }
    return mapping.get(token)


def _normalize_risk(value: str) -> str | None:
    token = _canonical_token(value)
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "med": "medium",
        "low": "low",
        "none": "none",
        "safe": "none",
        "benign": "none",
        "info": "none",
        "informational": "none",
    }
    return mapping.get(token)


def _infer_risk_from_finding(finding: CodeFinding, verdict: str | None) -> str | None:
    if verdict == "likely_fp":
        return "none"
    if verdict == "uncertain":
        return "medium"
    if verdict in {"tp", "likely_tp"}:
        if finding.severity == "info":
            return "low"
        return finding.severity
    return None


def _canonical_token(value: str) -> str:
    stripped = value.strip().strip("`'\"")
    compact = " ".join(stripped.split()).lower()
    return compact


def _parse_local_id(value: str) -> int:
    stripped = value.strip().strip("`'\"")
    match = INTEGER_PATTERN.search(stripped)
    if not match:
        raise ValueError("invalid finding index")
    return int(match.group(0))


def _parse_confidence(value: str) -> float:
    stripped = value.strip().strip("`'\"")
    lowered = stripped.lower()
    qualitative = {
        "very_high": 0.95,
        "very high": 0.95,
        "high": 0.85,
        "medium": 0.6,
        "moderate": 0.6,
        "med": 0.6,
        "low": 0.35,
        "very_low": 0.15,
        "very low": 0.15,
    }
    if lowered in qualitative:
        return qualitative[lowered]
    percent = stripped.endswith("%")
    if percent:
        stripped = stripped[:-1].strip()
    confidence = float(stripped)
    if percent or confidence > 1.0:
        confidence = confidence / 100.0
    return confidence


def _parse_recommendations(value: str) -> list[str]:
    return _normalize_recommendations([part.strip() for part in value.split("|")])


def _normalize_recommendations(value: object) -> list[str]:
    if isinstance(value, str):
        items = [item.strip() for item in re.split(r"[|;]", value)]
    elif isinstance(value, list):
        items = [str(item).strip() for item in value]
    else:
        return []

    normalized: list[str] = []
    for item in items:
        if not item:
            continue
        cleaned = item.strip().strip("`'\"- ").rstrip(".")
        if not cleaned:
            continue
        normalized.append(" ".join(cleaned.split())[:140])
        if len(normalized) >= 3:
            break
    return normalized


def _overall_recommendation_for_rule(rule_id: str) -> str | None:
    mapping = {
        "arbitrary-file-read": "Restrict file paths to a dedicated base directory and normalize them before use",
        "arbitrary-file-write": "Restrict writes to a dedicated base directory and block sensitive paths",
        "arbitrary-file-delete": "Restrict deletions to an allowlisted base directory and require explicit approval",
        "path-traversal": "Canonicalize paths and enforce a resolved path check against a fixed base directory",
        "command-execution": "Allowlist commands and require approval before executing shell or subprocess actions",
        "ssrf-fetch": "Allowlist outbound destinations and block private or internal IP ranges",
        "open-proxy-endpoint": "Require auth and restrict upstream destinations for proxy-like handlers",
        "hardcoded-secret": "Remove hardcoded secrets and load them from environment or a secret manager",
        "missing-webhook-verification": "Verify webhook signatures before processing requests",
        "unsafe-docker-runtime": "Avoid privileged containers and docker socket or host-root mounts",
        "tool-approval-missing": "Add approval or authorization checks around dangerous MCP tools",
        "prompt-injection-sensitive-wiring": "Do not pipe model or user output directly into shell, file, or network sinks",
        "auth-missing-on-network-service": "Require authentication on exposed HTTP routes and dangerous actions",
    }
    return mapping.get(rule_id)


def _token_preview(value: str) -> str:
    compact = " ".join(value.strip().split())
    return compact[:24]


def _parse_json_like_response(content: str, batch_indices: list[int]) -> list[tuple[int, str, str, float]]:
    payload = _load_json_like_payload(content)
    if payload is None:
        return []

    candidates: list[object]
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            candidates = payload["results"]
        else:
            candidates = [payload]
    else:
        return []

    parsed: list[tuple[int, str, str, float]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        raw_id = item.get("id", item.get("finding_index"))
        verdict = item.get("verdict")
        risk = item.get("risk")
        raw_confidence = item.get("confidence")
        if not isinstance(verdict, str) or not isinstance(risk, str):
            continue
        if verdict not in VALID_VERDICTS or risk not in VALID_RISKS:
            continue
        try:
            local_id = int(raw_id)
            confidence = float(raw_confidence)
        except (TypeError, ValueError):
            continue
        if local_id < 0 or local_id >= len(batch_indices):
            continue
        if not (0.0 <= confidence <= 1.0):
            continue
        parsed.append((batch_indices[local_id], verdict, risk, round(confidence, 2)))
    return parsed


def _load_json_like_payload(content: str) -> object | None:
    stripped = content.strip()
    if not stripped:
        return None
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            stripped = "\n".join(lines[1:-1]).strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None
