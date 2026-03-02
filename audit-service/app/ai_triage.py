from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import requests

from .models import CodeFinding


logger = logging.getLogger(__name__)

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
VALID_ACTIONS = {"keep", "suppress"}
VALID_RISKS = {"low", "medium", "high", "critical"}
SYSTEM_PROMPT = (
    "You are a security triage classifier. Output JSON only. "
    "Code under tools/, scripts/, examples/, or experiments is usually lower exposure unless clearly runtime-facing."
)
USER_PROMPT_PREFIX = (
    "Return a JSON array. One object per id. Keys only: id, action, risk, confidence, reason. "
    "action: keep|suppress. risk: low|medium|high|critical. "
    "confidence: 0..1. reason max 180 chars. Input:"
)


def triage_findings(findings: list[dict[str, Any]], model: str, max_batch: int, budget_mode: bool) -> dict[str, Any]:
    api_key = os.getenv("MISTRAL_API_KEY", "")
    if not api_key or not findings:
        return {
            "results": [],
            "suppressed_cluster_ids": set(),
            "group_count": 0,
            "classified_group_count": 0,
        }

    items = [item if isinstance(item, dict) else item.model_dump() for item in findings]
    groups = _group_items(items)
    selected_groups = groups[:30] if budget_mode else groups
    results: list[dict[str, Any]] = []
    for start in range(0, len(selected_groups), max_batch):
        batch = selected_groups[start : start + max_batch]
        try:
            results.extend(_classify_batch(batch, api_key, model))
        except requests.RequestException as exc:
            logger.warning(
                "AI triage batch request failed: batch_start=%s batch_size=%s error=%s",
                start,
                len(batch),
                exc.__class__.__name__,
            )
            return {
                "results": [],
                "suppressed_cluster_ids": set(),
                "group_count": len(groups),
                "classified_group_count": len(selected_groups),
            }
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning(
                "AI triage batch failed unexpectedly: batch_start=%s batch_size=%s error=%s",
                start,
                len(batch),
                exc.__class__.__name__,
            )
            return {
                "results": [],
                "suppressed_cluster_ids": set(),
                "group_count": len(groups),
                "classified_group_count": len(selected_groups),
            }

    suppressed_cluster_ids = {
        item["cluster_id"]
        for item in results
        if item["action"] == "suppress" and float(item["confidence"]) >= 0.65
    }
    return {
        "results": results,
        "suppressed_cluster_ids": suppressed_cluster_ids,
        "group_count": len(groups),
        "classified_group_count": len(selected_groups),
    }


def synthesize_overall_from_triage(findings: list[CodeFinding], results: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not results:
        return None
    action_order = {"suppress": 0, "keep": 1}
    by_cluster = {finding.cluster_id: finding for finding in findings if finding.cluster_role == "primary"}
    top = max(
        results,
        key=lambda item: (
            _effective_overall_risk_score(item, by_cluster.get(item["cluster_id"])),
            action_order.get(item["action"], 0),
            float(item["confidence"]),
            item["cluster_id"],
        ),
    )
    confidences = sorted((float(item["confidence"]) for item in results), reverse=True)[:3]
    return {
        "verdict": "likely_tp" if top["action"] == "keep" else "likely_fp",
        "risk": _effective_overall_risk_label(top["risk"], by_cluster.get(top["cluster_id"])),
        "confidence": round(sum(confidences) / len(confidences), 2),
        "recommendations": _recommendations_from_findings(findings, results),
    }


def _group_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in items:
        cluster_id = str(item.get("cluster_id") or item.get("hash") or item.get("file_path"))
        current = grouped.get(cluster_id)
        if current is None:
            grouped[cluster_id] = item
            continue
        if _sort_key(item) < _sort_key(current):
            grouped[cluster_id] = item
    ordered = sorted(grouped.values(), key=_sort_key)
    return ordered


def _sort_key(item: dict[str, Any]) -> tuple[int, str, str, int, str]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    context_order = {"mcp": 0, "server": 1, "cli": 2, "library": 3, "unknown": 4}
    path_area_order = {"none": 0, "scripts": 1, "tools": 2, "examples": 3, "experiments": 4}
    taint_summary = item.get("taint_summary", {}) if isinstance(item.get("taint_summary"), dict) else {}
    return (
        severity_order.get(str(item.get("deterministic_severity", "low")), 9),
        str(item.get("rule_id", "")),
        str(item.get("context", "")),
        path_area_order.get(str(taint_summary.get("path_area", "none")), 0),
        -int(item.get("cluster_size", 1)),
        str(item.get("cluster_id", "")),
    )


def _effective_overall_risk_score(item: dict[str, Any], finding: CodeFinding | None) -> int:
    risk_label = _effective_overall_risk_label(str(item["risk"]), finding)
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(risk_label, 0)


def _effective_overall_risk_label(risk: str, finding: CodeFinding | None) -> str:
    if finding is None:
        return risk
    if risk == "critical" and not _is_critical_cluster(finding):
        risk = "high"
    if finding.rule_id == "auth-missing-on-network-service" and risk == "critical":
        return "high"
    if finding.rule_id == "tool-approval-missing" and risk in {"critical", "high"}:
        return "medium"
    if finding.rule_id != "command-execution":
        return risk
    if _is_low_exposure_command_exec(finding):
        if risk == "critical":
            return "high"
        if risk == "high":
            return "medium"
    return risk


def _is_low_exposure_command_exec(finding: CodeFinding) -> bool:
    lowered = finding.evidence.file_path.lower()
    low_exposure_path = any(
        token in lowered
        for token in ("/tools/", "tools/", "/scripts/", "scripts/", "/examples/", "examples/", "/experiments/", "experiments/")
    )
    if not low_exposure_path:
        return False
    haystack = f"{finding.evidence.snippet}\n{finding.nearby_context or ''}"
    return re.search(r"@app\.|router\.|app\.listen|uvicorn\.run|serveSSE|fetch\(request|request\.|req\.", haystack, re.IGNORECASE) is None


def _is_critical_cluster(finding: CodeFinding) -> bool:
    if finding.context not in {"mcp", "server"}:
        return False
    if finding.rule_id in {"ssrf-fetch", "open-proxy-endpoint"}:
        return _strong_url_taint(finding) and not _network_guards_present(finding)
    if finding.rule_id in {"command-execution", "prompt-injection-sensitive-wiring"}:
        return (_strong_taint_evidence(finding) or not _generic_guards_present(finding)) and not _is_low_exposure_command_exec(finding)
    if finding.rule_id in {"arbitrary-file-write", "arbitrary-file-delete", "arbitrary-file-read"}:
        return _strong_taint_evidence(finding) and not _path_guards_present(finding)
    if finding.rule_id == "unsafe-docker-runtime":
        return True
    return False


def _finding_haystack(finding: CodeFinding) -> str:
    return f"{finding.evidence.snippet}\n{finding.nearby_context or ''}"


def _strong_taint_evidence(finding: CodeFinding) -> bool:
    text = _finding_haystack(finding)
    return re.search(
        r"user_url|target_url|payload\[['\"](?:url|path|command)['\"]\]|request\.(?:url|json|body|query_params|path_params)|req\.(?:body|query|params)|ctx\.arguments|tool_(?:args|input)|params\.get\s*\(",
        text,
        re.IGNORECASE,
    ) is not None


def _strong_url_taint(finding: CodeFinding) -> bool:
    text = _finding_haystack(finding)
    return re.search(
        r"user_url|target_url|payload\[['\"]url['\"]\]|request\.url|req\.(?:query|body|params).*(?:url|target)|params\.get\s*\(\s*['\"]url['\"]|new URL\s*\(\s*request\.url",
        text,
        re.IGNORECASE,
    ) is not None


def _network_guards_present(finding: CodeFinding) -> bool:
    text = _finding_haystack(finding)
    return re.search(r"allowlist|trusted_hosts|trusted_domains|rfc1918|169\.254\.169\.254|127\.0\.0\.1|localhost|private ip", text, re.IGNORECASE) is not None


def _path_guards_present(finding: CodeFinding) -> bool:
    text = _finding_haystack(finding)
    return re.search(r"is_relative_to|commonpath|startswith\s*\(|allowlist of extensions|suffix(?:es)?\s+allowlist", text, re.IGNORECASE) is not None


def _generic_guards_present(finding: CodeFinding) -> bool:
    text = _finding_haystack(finding)
    return re.search(r"allowlist|approval|authorize|auth|bearer|jwt|oauth", text, re.IGNORECASE) is not None


def _classify_batch(batch: list[dict[str, Any]], api_key: str, model: str) -> list[dict[str, Any]]:
    payload_items = []
    id_to_cluster: dict[int, str] = {}
    for item_id, item in enumerate(batch):
        payload_items.append(
            {
                "id": item_id,
                "rule_id": item["rule_id"],
                "severity": item["deterministic_severity"],
                "context": item["context"],
                "file_path": item["file_path"],
                "snippet": str(item["primary_snippet"])[:220],
                "nearby_context": str(item["nearby_context"])[:700],
                "taint_summary": item.get("taint_summary", {}),
            }
        )
        id_to_cluster[item_id] = str(item["cluster_id"])
    content = _send_request(payload_items, api_key, model)
    parsed = _parse_response(content)
    results: list[dict[str, Any]] = []
    for item in parsed:
        cluster_id = id_to_cluster.get(int(item["id"]))
        if cluster_id is None:
            continue
        results.append(
            {
                "cluster_id": cluster_id,
                "action": item["action"],
                "risk": item["risk"],
                "confidence": item["confidence"],
                "reason": item["reason"],
            }
        )
    return results


def _send_request(items: list[dict[str, Any]], api_key: str, model: str) -> str:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{USER_PROMPT_PREFIX}\n{json.dumps(items, separators=(',', ':'))}"},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    response = requests.post(
        MISTRAL_API_URL,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=body,
        timeout=15,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def _parse_response(content: str) -> list[dict[str, Any]]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE | re.DOTALL).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("AI triage JSON parse failed")
        return []

    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        items = payload["results"]
    elif isinstance(payload, list):
        items = payload
    else:
        return []

    parsed: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            item_id = int(item["id"])
            raw_action = item.get("action")
            if raw_action is None and item.get("verdict") is not None:
                verdict = str(item["verdict"]).strip().lower()
                raw_action = "suppress" if verdict in {"fp", "likely_fp"} else "keep"
            action = str(raw_action).strip().lower()
            risk = str(item["risk"]).strip().lower()
            confidence = float(item["confidence"])
            reason = str(item.get("reason", "")).strip()[:180]
        except (KeyError, TypeError, ValueError):
            continue
        if action not in VALID_ACTIONS or risk not in VALID_RISKS or not (0.0 <= confidence <= 1.0):
            continue
        parsed.append(
            {
                "id": item_id,
                "action": action,
                "risk": risk,
                "confidence": round(confidence, 2),
                "reason": reason,
            }
        )
    return parsed


def _recommendations_from_findings(findings: list[CodeFinding], results: list[dict[str, Any]]) -> list[str]:
    by_cluster = {finding.cluster_id: finding for finding in findings if finding.cluster_role == "primary"}
    ordered = sorted(results, key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item["risk"], 9), -float(item["confidence"]), item["cluster_id"]))
    recommendations: list[str] = []
    seen_rules: set[str] = set()
    for item in ordered:
        if item["action"] != "keep":
            continue
        finding = by_cluster.get(item["cluster_id"])
        if finding is None or finding.rule_id in seen_rules:
            continue
        seen_rules.add(finding.rule_id)
        recommendation = finding.recommendation[0] if finding.recommendation else ""
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
        if len(recommendations) >= 3:
            break
    return recommendations
