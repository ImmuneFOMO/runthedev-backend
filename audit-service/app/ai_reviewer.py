from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .models import AIReviewMeta, AIReviewResult, AIRiskDetail, Finding, Report, TokenUsage

try:
    from langchain_core.output_parsers import PydanticOutputParser
    from langchain_core.prompts import ChatPromptTemplate
except ImportError:  # pragma: no cover
    PydanticOutputParser = None  # type: ignore[assignment]
    ChatPromptTemplate = None  # type: ignore[assignment]

try:
    from langchain_mistralai import ChatMistralAI
except ImportError:  # pragma: no cover
    ChatMistralAI = None  # type: ignore[assignment]

try:
    from langchain_openai import ChatOpenAI
except ImportError:  # pragma: no cover
    ChatOpenAI = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)
SYSTEM_PROMPT = (
    "You are a senior application security auditor. Be conservative. Do not overclaim. "
    "Only infer what is supported by evidence. Use only the supplied audit evidence. "
    "Do not invent facts, false positives, attack steps, or deployment assumptions. "
    "Remote manifest fetching without execution primitives is a supply-chain or remote-content integrity risk, not arbitrary code execution."
)
USER_PROMPT_TEMPLATE = """Given this rule-based audit evidence:

{bundle_json}

Produce STRICT JSON only matching this exact schema:
{format_instructions}

Hard rules:
- Use ONLY the supplied evidence.
- Do NOT speculate about attacks or secret exposure unless directly supported by the evidence.
- Group duplicate or systemic issues by `rule_id`.
- `top_risks_detailed` must be structured; do not embed ad-hoc capability tags in free text.
- `likely_false_positive_candidates` must contain only exact finding titles or exact rule_ids from the provided findings, or be [].
- `ai_attack_path` must be null if the evidence is insufficient for a plausible attack path.
- Do NOT claim arbitrary code execution unless evidence includes an execution primitive such as:
  `curl | bash`, `wget | sh`, `eval`, `exec`, `spawn`, `os.system`, `subprocess`, `PowerShell`, `chmod +x`, or `sh -c`.
- For remote manifests fetched via install tools, treat them as supply-chain risk: tampering, compromised components added, or unverified remote content.
- If you mention execution for a remote manifest case, it must be conditional and clearly implementation-dependent.
- `ai_must_fix_first` must contain the first 1-3 concrete remediations tied directly to the evidence.
- If there is only one medium finding and limited evidence, stay conservative.
- No markdown. No extra keys. Keep the response concise.

Tasks:
1. Identify the single most realistically exploitable issue in context.
2. Group duplicate or systemic issues by `rule_id`.
3. Identify likely false positives or doc-absence weak signals from the provided findings only.
4. Describe one plausible attack path if and only if the evidence supports one; otherwise return null.
5. Recommend the first 1-3 fixes only.
6. Assign overall priority consistent with the finding severities and justify it briefly in `ai_summary`.
"""
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
FINDING_POINTS = {"critical": 35, "high": 20, "medium": 10, "low": 3, "info": 0}
GENERIC_RISK_PATTERNS = (
    "security issues",
    "security risk",
    "api risk",
    "general risk",
    "vulnerability",
    "potential vulnerability",
    "risk category",
    "main risk",
)
GENERIC_SUMMARY_PREFIXES = (
    "the audit evidence indicates",
    "the evidence suggests",
    "this report shows",
)
VAGUE_ATTACK_PHRASES = (
    "could potentially",
    "might be able to",
    "guess the api key",
    "if not properly secured",
)
EXECUTION_PATTERNS = (
    r"curl\s*\|\s*bash",
    r"wget\s*\|\s*sh",
    r"\beval\b",
    r"\bexec\b",
    r"\bspawn\b",
    r"\bsubprocess\b",
    r"os\.system",
    r"\bpowershell\b",
    r"chmod\s+\+x",
    r"sh\s+-c",
)
CODE_EXECUTION_CLAIMS = (
    "arbitrary code execution",
    "execute arbitrary code",
    "remote code execution",
    "run arbitrary code",
)
GENERIC_FALSE_POSITIVE_MARKERS = (
    "properly managed",
    "secured",
    "safe",
    "none likely",
)
CAPABILITY_ORDER = (
    "proxy",
    "network",
    "supply-chain",
    "client-side-tools",
    "file-upload",
    "browser",
    "filesystem",
    "shell",
)
RULE_CAPABILITY_MAP = {
    "unpinned-dependency-install": ["supply-chain"],
    "remote-install-manifest": ["network", "supply-chain"],
    "curl-pipe-shell": ["shell", "supply-chain"],
    "git-clone-main-then-run": ["shell", "supply-chain"],
    "api-proxy-route-with-key": ["proxy", "network"],
    "webhook-signature-missing": ["network"],
    "private-ip-ssrf-mitigation-missing": ["network"],
    "ssrf-language": ["network"],
    "public-exposure": ["network"],
    "missing-guardrails-proxy": ["proxy"],
    "capability-proxy": ["proxy"],
    "missing-guardrails-file-upload": ["file-upload"],
    "capability-file-upload": ["file-upload"],
    "file-upload-capability": ["file-upload"],
    "missing-guardrails-client-side-tools": ["client-side-tools"],
    "capability-client-side-tools": ["client-side-tools"],
    "client-side-tools-capability": ["client-side-tools"],
    "missing-guardrails-shell": ["shell"],
    "capability-shell": ["shell"],
    "missing-guardrails-filesystem": ["filesystem"],
    "capability-filesystem": ["filesystem"],
    "missing-guardrails-network": ["network"],
    "capability-network": ["network"],
    "missing-guardrails-browser": ["browser"],
    "capability-browser": ["browser"],
}
RULE_RANKING_WEIGHTS = {
    "curl-pipe-shell": 100,
    "docker-privileged-host-mount": 95,
    "data-exfiltration-instructions": 90,
    "remote-install-manifest": 75,
    "api-proxy-route-with-key": 70,
    "public-exposure": 65,
    "private-ip-ssrf-mitigation-missing": 65,
    "ssrf-language": 60,
    "webhook-signature-missing": 55,
    "unpinned-dependency-install": 30,
    "env-file-guidance": 10,
    "secret-placeholder": 10,
}
SEVERITY_MULTIPLIERS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
    "info": 0.25,
}
SUPPLY_CHAIN_RULE_IDS = {
    "unpinned-dependency-install",
    "remote-install-manifest",
    "curl-pipe-shell",
    "git-clone-main-then-run",
}


@dataclass(slots=True)
class ReviewExecutionResult:
    ai_review: AIReviewResult
    meta: AIReviewMeta


@dataclass(slots=True)
class ProviderReviewResult:
    ai_review: AIReviewResult
    token_usage: TokenUsage


class Reviewer(Protocol):
    reviewer_name: str

    async def review(self, report: Report) -> ProviderReviewResult:
        ...


class AIReviewer:
    async def review(self, report: Report) -> ReviewExecutionResult:
        reviewer = _build_reviewer()
        fallback_reason: str | None = None

        try:
            provider_result = await reviewer.review(report)
            return ReviewExecutionResult(
                ai_review=_sanitize_ai_review(report, provider_result.ai_review),
                meta=AIReviewMeta(
                    reviewer_used=reviewer.reviewer_name,  # type: ignore[arg-type]
                    token_usage=provider_result.token_usage,
                ),
            )
        except Exception as exc:
            fallback_reason = f"{reviewer.reviewer_name} reviewer failed: {exc}"
            logger.warning("AI reviewer fallback triggered: %s", fallback_reason)

        fallback = NoOpReviewer()
        provider_result = await fallback.review(report)
        return ReviewExecutionResult(
            ai_review=_sanitize_ai_review(report, provider_result.ai_review),
            meta=AIReviewMeta(
                reviewer_used="noop",
                fallback_reason=fallback_reason,
                token_usage=provider_result.token_usage,
            ),
        )


class NoOpReviewer:
    reviewer_name = "noop"

    async def review(self, report: Report) -> ProviderReviewResult:
        prioritized = _top_findings(report)
        highest = prioritized[0] if prioritized else None
        priority = _priority_from_findings(report.findings)
        summary = (
            f"Highest priority issue: {highest.title}."
            if highest is not None
            else "No medium-or-higher findings were present in the rule-based report."
        )
        attack_path = _default_attack_path(highest)
        must_fix = highest.recommendation[:3] if highest is not None else []
        false_positive_candidates = [finding.title for finding in report.findings if finding.confidence <= 0.6][:3]
        top_risks = [finding.title for finding in prioritized[:3]]
        if not top_risks and highest is not None:
            top_risks = [highest.title]

        return ProviderReviewResult(
            ai_review=AIReviewResult(
                ai_summary=summary,
                ai_priority=priority,
                top_true_risks=top_risks,
                top_risks_detailed=[],
                likely_false_positive_candidates=false_positive_candidates,
                ai_attack_path=attack_path,
                ai_must_fix_first=must_fix,
                confidence=0.4,
            ),
            token_usage=TokenUsage(),
        )


class _LangChainReviewerBase:
    reviewer_name = "noop"

    def __init__(self, llm: Any):
        self.llm = llm
        if PydanticOutputParser is None or ChatPromptTemplate is None:
            raise RuntimeError("LangChain dependencies are not installed.")
        self.parser = PydanticOutputParser(pydantic_object=AIReviewResult)
        self.prompt = ChatPromptTemplate.from_messages(
            [
                ("system", SYSTEM_PROMPT),
                ("user", USER_PROMPT_TEMPLATE),
            ]
        )

    async def review(self, report: Report) -> ProviderReviewResult:
        bundle = _build_evidence_bundle(report)
        prompt = self.prompt.format_prompt(
            bundle_json=json.dumps(bundle, ensure_ascii=True, indent=2),
            format_instructions=self.parser.get_format_instructions(),
        )
        response = await self.llm.ainvoke(prompt.to_messages())
        token_usage = _extract_token_usage(response)
        content = _normalize_llm_content(response.content if hasattr(response, "content") else response)
        payload = _extract_json_payload(content)
        try:
            ai_review = self.parser.parse(payload)
        except Exception:
            ai_review = _coerce_ai_review_result(payload)
        return ProviderReviewResult(ai_review=ai_review, token_usage=token_usage)


class LangChainMistralReviewer(_LangChainReviewerBase):
    reviewer_name = "mistral"

    def __init__(self) -> None:
        if ChatMistralAI is None:
            raise RuntimeError("langchain_mistralai is not installed.")
        model = os.getenv("MISTRAL_MODEL", "mistral-small-latest")
        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "15"))
        llm = ChatMistralAI(
            model=model,
            temperature=0.2,
            max_tokens=800,
            timeout=timeout,
        )
        super().__init__(llm)


class LangChainOpenRouterReviewer(_LangChainReviewerBase):
    reviewer_name = "openrouter"

    def __init__(self) -> None:
        if ChatOpenAI is None:
            raise RuntimeError("langchain_openai is not installed.")
        model = os.getenv("OPENROUTER_MODEL", "mistralai/mistral-small-3.1-24b-instruct")
        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "15"))
        llm = ChatOpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            model=model,
            temperature=0.2,
            max_tokens=800,
            timeout=timeout,
            model_kwargs={"response_format": {"type": "json_object"}},
        )
        super().__init__(llm)


def _build_reviewer() -> Reviewer:
    if os.getenv("MISTRAL_API_KEY"):
        return LangChainMistralReviewer()
    if os.getenv("OPENROUTER_API_KEY"):
        return LangChainOpenRouterReviewer()
    return NoOpReviewer()


def _extract_json_payload(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("Reviewer did not return JSON.")
    return stripped[start : end + 1]


def _extract_token_usage(response: Any) -> TokenUsage:
    usage = getattr(response, "usage_metadata", None)
    if isinstance(usage, dict):
        input_tokens = _safe_int(usage.get("input_tokens"))
        output_tokens = _safe_int(usage.get("output_tokens"))
        total_tokens = _safe_int(usage.get("total_tokens"))
        if input_tokens or output_tokens or total_tokens:
            return TokenUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens or (input_tokens + output_tokens),
            )

    response_metadata = getattr(response, "response_metadata", None)
    if isinstance(response_metadata, dict):
        token_usage = response_metadata.get("token_usage")
        if isinstance(token_usage, dict):
            input_tokens = _safe_int(token_usage.get("prompt_tokens") or token_usage.get("input_tokens"))
            output_tokens = _safe_int(token_usage.get("completion_tokens") or token_usage.get("output_tokens"))
            total_tokens = _safe_int(token_usage.get("total_tokens"))
            return TokenUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens or (input_tokens + output_tokens),
            )

    return TokenUsage()


def _safe_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return 0


def _normalize_llm_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                    continue
            text = getattr(item, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "\n".join(part for part in parts if part).strip()
    return str(content)


def _coerce_ai_review_result(payload: str) -> AIReviewResult:
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("Reviewer payload was not a JSON object.")

    if {"ai_summary", "ai_priority", "top_true_risks", "likely_false_positive_candidates", "ai_must_fix_first", "confidence"}.issubset(data.keys()):
        return AIReviewResult.model_validate(data)

    most_exploitable = data.get("most_exploitable_issue") or {}
    recommendations = data.get("recommendations") or []
    false_positives = data.get("likely_false_positives") or []
    attack_path = data.get("plausible_attack_path")
    if isinstance(attack_path, list):
        attack_path = " ".join(str(item) for item in attack_path)

    top_true_risks: list[str] = []
    if isinstance(most_exploitable, dict):
        description = most_exploitable.get("description")
        rule_id = most_exploitable.get("rule_id")
        if isinstance(description, str) and description.strip():
            top_true_risks.append(description.strip())
        elif isinstance(rule_id, str) and rule_id.strip():
            top_true_risks.append(rule_id.strip())

    summary = None
    if isinstance(most_exploitable, dict):
        description = most_exploitable.get("description")
        if isinstance(description, str) and description.strip():
            summary = description.strip()

    return AIReviewResult(
        ai_summary=summary or "AI reviewer identified the most exploitable issue from the supplied evidence.",
        ai_priority=_normalize_priority(data.get("overall_priority")),
        top_true_risks=top_true_risks,
        top_risks_detailed=[],
        likely_false_positive_candidates=[str(item) for item in false_positives[:5]],
        ai_attack_path=attack_path if isinstance(attack_path, str) and attack_path.strip() else None,
        ai_must_fix_first=[str(item) for item in recommendations[:3]],
        confidence=_normalize_confidence(data, most_exploitable),
    )


def _normalize_priority(value: Any) -> str:
    if isinstance(value, str) and value.lower() in {"low", "medium", "high", "critical"}:
        return value.lower()
    return "medium"


def _normalize_confidence(data: dict[str, Any], most_exploitable: Any) -> float:
    if isinstance(data.get("confidence"), (int, float)):
        return max(0.0, min(float(data["confidence"]), 1.0))
    if isinstance(most_exploitable, dict) and isinstance(most_exploitable.get("confidence"), (int, float)):
        return max(0.0, min(float(most_exploitable["confidence"]), 1.0))
    return 0.7


def _top_findings(report: Report) -> list[Finding]:
    ranked = sorted(
        report.findings,
        key=lambda finding: (-SEVERITY_ORDER[finding.severity], -FINDING_POINTS[finding.severity], -finding.confidence),
    )
    medium_or_higher = [finding for finding in ranked if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER["medium"]]
    return medium_or_higher or ranked


def _build_evidence_bundle(report: Report) -> dict[str, Any]:
    selected = _select_evidence_findings(report)
    grouped = _group_findings_by_rule(selected)
    findings = []
    for finding in selected:
        findings.append(
            {
                "title": finding.title,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "description": _short_description(finding.description),
                "confidence": finding.confidence,
                "evidence": {
                    "section": finding.evidence.section,
                    "snippet": _short_context(finding.evidence.snippet),
                },
            }
        )
    return {
        "summary": {
            "risk_score": report.summary.risk_score,
            "severity_counts": report.summary.counts.model_dump(),
            "drivers": report.drivers[:3],
        },
        "capabilities": report.capabilities,
        "graph_summary": report.graph_summary.model_dump(),
        "systemic_summary": [
            {
                "rule_id": rule_id,
                "count": len(items),
                "related_capabilities": _related_capabilities_for_rule(rule_id, report.capabilities),
            }
            for rule_id, items in grouped[:2]
        ],
        "findings": findings,
    }


def _priority_from_findings(findings: list[Finding]) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return "critical"
    if any(finding.severity == "high" for finding in findings):
        return "high"
    if any(finding.severity == "medium" for finding in findings):
        return "medium"
    return "low"


def _default_attack_path(finding: Finding | None) -> str | None:
    if finding is None:
        return None
    if finding.severity in {"critical", "high", "medium"}:
        return f"A realistic attack path would start by abusing the condition described by {finding.rule_id} and pivoting through the documented workflow."
    return None


def _sanitize_ai_review(report: Report, review: AIReviewResult) -> AIReviewResult:
    selected_findings = _select_evidence_findings(report)
    top_findings = selected_findings or _top_findings(report)
    canonical_refs = _finding_reference_map(report)
    grouped = _group_findings_by_rule(top_findings)
    false_positive_allowed = _allowed_false_positive_refs(report)
    false_positives = _normalize_false_positive_candidates(
        review.likely_false_positive_candidates,
        canonical_refs,
        false_positive_allowed,
    )
    top_risks_detailed = _deterministic_top_risks(report, top_findings, review.top_risks_detailed)
    top_true_risks = [_render_top_risk(detail) for detail in top_risks_detailed]
    attack_path = _normalize_attack_path(report, review.ai_attack_path, top_findings)
    must_fix = _normalize_must_fix(review.ai_must_fix_first, grouped, top_risks_detailed)
    requested_priority = _normalize_priority(review.ai_priority)
    priority = _cap_priority_to_evidence(report, requested_priority, grouped)
    summary = _normalize_summary(review.ai_summary, top_findings)
    confidence = _calibrated_confidence(report, top_findings)
    if not false_positives:
        false_positives = ["none"]
        summary = f"{summary} No likely false positives stood out among the reviewed findings."
    if not _has_execution_evidence(top_findings):
        attack_path = None
        summary = _append_clause(
            summary,
            "No direct code-execution primitive was observed in the provided snippets; impact is primarily supply-chain / content tampering.",
        )
    elif attack_path is None:
        summary = _append_clause(summary, "Attack path depends on implementation; the docs alone do not prove a concrete exploit chain.")
    if requested_priority == "critical" and priority == "high":
        summary = _append_clause(summary, "Priority was capped at high because the rule report contains no critical findings.")
    if requested_priority == "high" and priority == "medium":
        summary = _append_clause(summary, "Priority stays medium because the rule report does not show repeated high-confidence severe findings.")

    return AIReviewResult(
        ai_summary=summary,
        ai_priority=priority,  # type: ignore[arg-type]
        top_true_risks=top_true_risks,
        top_risks_detailed=top_risks_detailed,
        likely_false_positive_candidates=false_positives,
        ai_attack_path=attack_path,
        ai_must_fix_first=must_fix,
        confidence=confidence,
    )


def _finding_reference_map(report: Report) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for finding in report.findings:
        mapping[finding.title.casefold()] = finding.title
        mapping[finding.rule_id.casefold()] = finding.rule_id
    return mapping


def _allowed_false_positive_refs(report: Report) -> set[str]:
    allowed: set[str] = set()
    for finding in report.findings:
        if finding.confidence <= 0.5 and finding.severity == "low":
            allowed.add(finding.title)
            allowed.add(finding.rule_id)
    return allowed


def _normalize_false_positive_candidates(
    candidates: list[str],
    canonical_refs: dict[str, str],
    allowed_refs: set[str],
) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.strip().casefold() == "none":
            continue
        if any(marker in candidate.casefold() for marker in GENERIC_FALSE_POSITIVE_MARKERS):
            continue
        key = candidate.strip().casefold()
        canonical = canonical_refs.get(key)
        if canonical is None or canonical in seen or canonical not in allowed_refs:
            continue
        normalized.append(canonical)
        seen.add(canonical)
    return normalized


def _normalize_attack_path(report: Report, value: str | None, findings: list[Finding]) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.split()).strip()
    if not cleaned:
        return None
    lowered = cleaned.casefold()
    if any(phrase in lowered for phrase in VAGUE_ATTACK_PHRASES):
        return None
    if not _has_execution_evidence(findings):
        return None
    if any(claim in lowered for claim in CODE_EXECUTION_CLAIMS) and not _has_execution_evidence(findings):
        return None
    if _only_remote_manifest_risk(findings):
        return None
    return cleaned


def _normalize_must_fix(
    items: list[str],
    grouped_findings: list[tuple[str, list[Finding]]],
    top_risks_detailed: list[AIRiskDetail],
) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    top_rule_ids = [detail.rule_id for detail in top_risks_detailed[:2]]
    proxy_required = any(rule_id == "api-proxy-route-with-key" for rule_id in top_rule_ids)

    if proxy_required:
        proxy_recommendation = _curated_remediations_for_rule("api-proxy-route-with-key")[0]
        key = proxy_recommendation.casefold()
        normalized.append(proxy_recommendation)
        seen.add(key)

    for rule_id in top_rule_ids:
        for recommendation in _curated_remediations_for_rule(rule_id):
            key = recommendation.casefold()
            if key in seen:
                continue
            normalized.append(recommendation)
            seen.add(key)
            if len(normalized) == 3:
                return normalized
    for item in items:
        cleaned = " ".join(item.split()).strip()
        if not cleaned or _is_weak_remediation(cleaned):
            continue
        key = cleaned.casefold()
        if key in seen:
            continue
        normalized.append(cleaned)
        seen.add(key)
        if len(normalized) == 3:
            break
    if normalized:
        return normalized
    for _rule_id, findings in grouped_findings[:1]:
        for finding in findings:
            for recommendation in finding.recommendation:
                cleaned = " ".join(recommendation.split()).strip()
                if not cleaned or _is_weak_remediation(cleaned):
                    continue
                key = cleaned.casefold()
                if key in seen:
                    continue
                normalized.append(cleaned)
                seen.add(key)
                if len(normalized) == 3:
                    return normalized
    return normalized


def _cap_priority_to_evidence(report: Report, priority: str, grouped: list[tuple[str, list[Finding]]]) -> str:
    normalized = _normalize_priority(priority)
    critical_count = sum(1 for finding in report.findings if finding.severity == "critical")
    high_count = sum(1 for finding in report.findings if finding.severity == "high")
    if critical_count == 0 and high_count == 0:
        if normalized == "critical":
            return "high"
        if normalized == "high" and not _allows_high_without_high_findings(grouped):
            return "medium"
    return normalized


def _normalize_summary(summary: str, top_findings: list[Finding]) -> str:
    cleaned = " ".join(summary.split()).strip()
    if cleaned and not cleaned.casefold().startswith(GENERIC_SUMMARY_PREFIXES):
        return cleaned
    if top_findings:
        top_finding = top_findings[0]
        return f"Top likely risk: {top_finding.title}. {top_finding.description}"
    return cleaned or "AI reviewer found no medium-or-higher issues to prioritize."


def _is_generic_risk(value: str) -> bool:
    lowered = value.casefold()
    if lowered in GENERIC_RISK_PATTERNS:
        return True
    if any(pattern in lowered for pattern in GENERIC_RISK_PATTERNS):
        return True
    if re.fullmatch(r"(api|security|system|application)\s+risk", lowered):
        return True
    if len(lowered.split()) <= 2 and "risk" in lowered:
        return True
    return False


def _select_evidence_findings(report: Report) -> list[Finding]:
    top_findings = [finding for finding in _top_findings(report) if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER["medium"]]
    if not top_findings:
        return []
    grouped = _group_findings_by_rule(top_findings)
    selected: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    if grouped:
        _, systemic_findings = grouped[0]
        for finding in systemic_findings:
            key = (finding.rule_id, finding.evidence.doc_url)
            if key in seen:
                continue
            selected.append(finding)
            seen.add(key)
            if len(selected) >= 7:
                return selected

    used_rule_ids = {finding.rule_id for finding in selected}
    additional = sorted(
        [finding for finding in top_findings if finding.rule_id not in used_rule_ids],
        key=lambda finding: (-finding.confidence, -SEVERITY_ORDER[finding.severity], finding.rule_id),
    )
    for finding in additional:
        key = (finding.rule_id, finding.evidence.doc_url)
        if key in seen:
            continue
        selected.append(finding)
        seen.add(key)
        used_rule_ids.add(finding.rule_id)
        if len([item for item in selected if item.rule_id != selected[0].rule_id]) >= 3 or len(selected) >= 7:
            break

    return selected


def _group_findings_by_rule(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.rule_id, []).append(finding)
    return sorted(
        grouped.items(),
        key=lambda item: (
            -len(item[1]),
            -max(FINDING_POINTS[finding.severity] for finding in item[1]),
            item[0],
        ),
    )


def _short_context(snippet: str) -> str:
    compact = " ".join(snippet.split())
    return compact[:240]


def _short_description(description: str) -> str:
    compact = " ".join(description.split())
    return compact[:140]


def _related_capabilities_for_rule(rule_id: str, capabilities: list[str]) -> list[str]:
    combined: list[str] = []
    for capability in RULE_CAPABILITY_MAP.get(rule_id, []):
        if capability not in combined:
            combined.append(capability)
    for capability in capabilities:
        if capability in rule_id and capability not in combined:
            combined.append(capability)
    for capability in capabilities:
        if capability in combined:
            continue
        if capability in RULE_CAPABILITY_MAP.get(rule_id, []):
            combined.append(capability)
    order_map = {capability: index for index, capability in enumerate(CAPABILITY_ORDER)}
    return sorted(combined, key=lambda capability: (order_map.get(capability, len(order_map)), capability))


def _merge_related_capabilities(rule_id: str, report_capabilities: list[str], llm_capabilities: list[str]) -> list[str]:
    merged = set(RULE_CAPABILITY_MAP.get(rule_id, []))
    merged.update(llm_capabilities)
    merged.update(capability for capability in report_capabilities if capability in rule_id)
    if rule_id in SUPPLY_CHAIN_RULE_IDS and "supply-chain" not in merged:
        merged.add("supply-chain")
    return sorted(merged)


def _rule_weight(rule_id: str) -> int:
    if rule_id.startswith("missing-guardrails-"):
        return 50
    return RULE_RANKING_WEIGHTS.get(rule_id, 40)


def _max_severity(findings: list[Finding]) -> str:
    return max(findings, key=lambda finding: SEVERITY_ORDER[finding.severity]).severity


def _effective_rule_score(rule_id: str, findings: list[Finding]) -> tuple[float, int]:
    severity = _max_severity(findings)
    return (_rule_weight(rule_id) * SEVERITY_MULTIPLIERS[severity], len(findings))


def _deterministic_top_risks(
    report: Report,
    findings: list[Finding],
    llm_details: list[AIRiskDetail],
) -> list[AIRiskDetail]:
    grouped_map: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped_map.setdefault(finding.rule_id, []).append(finding)
    full_grouped_map: dict[str, list[Finding]] = {}
    for finding in report.findings:
        full_grouped_map.setdefault(finding.rule_id, []).append(finding)

    llm_map = {detail.rule_id: detail for detail in llm_details if detail.rule_id in grouped_map}
    details: list[AIRiskDetail] = []
    for rule_id, rule_findings in grouped_map.items():
        llm_detail = llm_map.get(rule_id)
        display_findings = full_grouped_map.get(rule_id, rule_findings)
        details.append(
            AIRiskDetail(
                rule_id=rule_id,
                count=len(display_findings),
                label=_normalize_sentence(
                    llm_detail.label if llm_detail and llm_detail.label.strip() else _risk_label(rule_id, rule_findings),
                    terminal_period=False,
                ),
                why=_normalize_sentence(
                    llm_detail.why if llm_detail and llm_detail.why.strip() else _risk_reason(rule_id, rule_findings)
                ),
                related_capabilities=_merge_related_capabilities(
                    rule_id,
                    report.capabilities,
                    llm_detail.related_capabilities if llm_detail else [],
                ),
            )
        )

    details.sort(
        key=lambda detail: (
            -_effective_rule_score(detail.rule_id, grouped_map[detail.rule_id])[0],
            -detail.count,
            detail.rule_id,
        )
    )
    return details[:3]


def _build_top_risks_detailed(
    report: Report,
    grouped: list[tuple[str, list[Finding]]],
) -> list[AIRiskDetail]:
    details: list[AIRiskDetail] = []
    for rule_id, findings in grouped[:3]:
        details.append(
            AIRiskDetail(
                rule_id=rule_id,
                count=len(findings),
                label=_risk_label(rule_id, findings),
                why=_risk_reason(rule_id, findings),
                related_capabilities=_related_capabilities_for_rule(rule_id, report.capabilities),
            )
        )
    return details


def _render_top_risk(detail: AIRiskDetail) -> str:
    return (
        f"{detail.rule_id} (x{detail.count}): {detail.label} — {_normalize_sentence(detail.why)} "
        f"related_capabilities={json.dumps(detail.related_capabilities)}"
    )


def _curated_remediations_for_rule(rule_id: str) -> list[str]:
    if rule_id in {"api-proxy-route-with-key", "missing-guardrails-proxy"}:
        return [
            "Require authentication and authorization on the proxy route.",
            "Enforce origin allowlists and rate limiting on proxy traffic.",
            "Restrict upstream hostnames to an explicit allowlist.",
        ]
    if rule_id == "remote-install-manifest":
        return [
            "Pin remote manifests to immutable versions, commits, or checksums.",
            "Use a trusted registry or verified release channel for installable components.",
            "Verify manifest integrity before adding remote components to the project.",
        ]
    if rule_id == "missing-guardrails-client-side-tools":
        return [
            "Require explicit user approval before client-side tools run.",
            "Scope client-side tools to an allowlisted set of actions.",
        ]
    return []


def _is_weak_remediation(value: str) -> bool:
    lowered = value.casefold()
    return "env key" in lowered or "environment key" in lowered


def _risk_label(rule_id: str, findings: list[Finding]) -> str:
    if rule_id == "remote-install-manifest":
        return "Remote manifest supply-chain risk" if not _has_execution_evidence(findings) else "Remote install execution risk"
    if rule_id == "api-proxy-route-with-key":
        return "Proxy route with upstream credential handling"
    return findings[0].title


def _risk_reason(rule_id: str, findings: list[Finding]) -> str:
    if rule_id == "remote-install-manifest" and not _has_execution_evidence(findings):
        return "Multiple docs instruct loading remote manifests without pinning or verification, which can introduce compromised components"
    if rule_id == "api-proxy-route-with-key":
        return "The docs describe a proxy route backed by an environment key without explicit access controls"
    return findings[0].description.rstrip(".")


def _normalize_sentence(value: str, *, terminal_period: bool = True) -> str:
    cleaned = " ".join(value.split()).strip()
    cleaned = re.sub(r"[.]{2,}", ".", cleaned)
    cleaned = re.sub(r"\s+([.,;:])", r"\1", cleaned)
    cleaned = cleaned.rstrip(" .")
    if terminal_period and cleaned:
        cleaned = f"{cleaned}."
    return cleaned


def _has_execution_evidence(findings: list[Finding]) -> bool:
    for finding in findings:
        haystack = f"{finding.title} {finding.description} {finding.evidence.snippet}".casefold()
        if any(re.search(pattern, haystack) for pattern in EXECUTION_PATTERNS):
            return True
    return False


def _only_remote_manifest_risk(findings: list[Finding]) -> bool:
    rule_ids = {finding.rule_id for finding in findings}
    return bool(rule_ids) and rule_ids == {"remote-install-manifest"}


def _allows_high_without_high_findings(grouped: list[tuple[str, list[Finding]]]) -> bool:
    for rule_id, findings in grouped:
        medium_findings = [finding for finding in findings if finding.severity == "medium"]
        if len(medium_findings) < 2:
            continue
        if rule_id.startswith("missing-guardrails"):
            continue
        if any(finding.evidence.snippet.strip() and finding.confidence >= 0.6 for finding in medium_findings):
            return True
    return False


def _append_clause(summary: str, clause: str) -> str:
    cleaned_summary = summary.rstrip()
    if cleaned_summary.endswith(clause):
        return cleaned_summary
    separator = "" if cleaned_summary.endswith(".") else "."
    return f"{cleaned_summary}{separator} {clause}".strip()


def _calibrated_confidence(report: Report, findings: list[Finding]) -> float:
    if not findings:
        return 0.4
    average = sum(finding.confidence for finding in findings) / len(findings)
    missing_guardrails = [finding for finding in findings if finding.rule_id.startswith("missing-guardrails")]
    confidence = average
    if (len(missing_guardrails) / len(findings)) > 0.4:
        confidence = min(confidence, 0.75)
    if all(finding.severity not in {"high", "critical"} for finding in report.findings):
        confidence = min(confidence, 0.80)
    return max(0.35, min(round(confidence, 2), 0.90))
