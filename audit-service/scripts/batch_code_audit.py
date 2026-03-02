#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import time
from typing import Any

import httpx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch-submit GitHub repo/tree/blob URLs to the /audit/code endpoint."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a text file (one URL per line) or JSON file containing a list of URLs.",
    )
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:8000/audit/code",
        help="Code audit endpoint URL.",
    )
    parser.add_argument(
        "--output",
        default="batch_code_audit_results.json",
        help="Path to write the aggregated JSON results.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Number of concurrent code audit requests.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=40,
        help="Value for max_files.",
    )
    parser.add_argument(
        "--max-total-chars",
        type=int,
        default=400000,
        help="Value for max_total_chars.",
    )
    parser.add_argument(
        "--ai-classify",
        action="store_true",
        help="Enable optional AI post-triage for /audit/code.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="Per-request timeout in seconds.",
    )
    return parser.parse_args()


def load_urls(path: Path) -> list[str]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []

    if path.suffix.lower() == ".json":
        parsed = json.loads(raw)
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise ValueError("JSON input must be a list of URL strings.")
        return [item.strip() for item in parsed if item.strip()]

    urls: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def _report_snapshot(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {})
    overall_safety = report.get("overall_safety", {})
    ai_triage = report.get("ai_triage", {})
    ai_handoff = report.get("ai_handoff", {})
    clusters = report.get("clusters", {})
    primary_clusters = clusters.get("primary", []) if isinstance(clusters, dict) else []
    suppressed_clusters = clusters.get("suppressed", []) if isinstance(clusters, dict) else []
    drivers = report.get("drivers", [])
    return {
        "risk_score": summary.get("risk_score"),
        "overall_safety": overall_safety.get("verdict"),
        "overall_risk": overall_safety.get("risk"),
        "primary_clusters": len(primary_clusters) if isinstance(primary_clusters, list) else None,
        "suppressed_clusters": len(suppressed_clusters) if isinstance(suppressed_clusters, list) else None,
        "filtered_out_count": ai_triage.get("filtered_out_count") if isinstance(ai_triage, dict) else None,
        "ai_handoff_clusters": ai_handoff.get("stats", {}).get("total_clusters") if isinstance(ai_handoff, dict) else None,
        "ai_handoff_dropped": ai_handoff.get("stats", {}).get("dropped_total") if isinstance(ai_handoff, dict) else None,
        "drivers": drivers[:3] if isinstance(drivers, list) else [],
    }


async def audit_one(
    client: httpx.AsyncClient,
    endpoint: str,
    url: str,
    max_files: int,
    max_total_chars: int,
    ai_classify: bool,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    payload = {
        "url": url,
        "max_files": max_files,
        "max_total_chars": max_total_chars,
        "ai_classify": ai_classify,
    }
    started = time.perf_counter()

    async with semaphore:
        try:
            response = await client.post(endpoint, json=payload)
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            record: dict[str, Any] = {
                "url": url,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            }
            try:
                body = response.json()
            except json.JSONDecodeError:
                body = {"detail": response.text[:1000]}

            if response.is_success:
                record["ok"] = True
                record["report"] = body
                if isinstance(body, dict):
                    record["snapshot"] = _report_snapshot(body)
            else:
                record["ok"] = False
                record["error"] = body
            return record
        except httpx.HTTPError as exc:
            return {
                "url": url,
                "ok": False,
                "status_code": None,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "error": {"detail": str(exc)},
            }


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    success_count = sum(1 for item in results if item.get("ok"))
    failure_count = len(results) - success_count
    risk_scores: list[int] = []
    durations = [item.get("duration_ms", 0.0) for item in results]
    overall_safety_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    filtered_out_total = 0

    for item in results:
        if not item.get("ok") or not isinstance(item.get("report"), dict):
            continue
        report = item["report"]
        summary = report.get("summary", {})
        risk_score = summary.get("risk_score")
        if isinstance(risk_score, int):
            risk_scores.append(risk_score)

        overall_safety = report.get("overall_safety", {})
        verdict = overall_safety.get("verdict")
        if isinstance(verdict, str):
            overall_safety_counts[verdict] = overall_safety_counts.get(verdict, 0) + 1

        ai_triage = report.get("ai_triage", {})
        if isinstance(ai_triage, dict):
            filtered_out = ai_triage.get("filtered_out_count")
            if isinstance(filtered_out, int):
                filtered_out_total += filtered_out

        clusters = report.get("clusters", {})
        primary_clusters = clusters.get("primary", []) if isinstance(clusters, dict) else []
        counted_primary = False
        if isinstance(primary_clusters, list):
            for cluster in primary_clusters:
                if not isinstance(cluster, dict):
                    continue
                rule_id = cluster.get("rule_id")
                if isinstance(rule_id, str):
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
                    counted_primary = True
        if counted_primary:
            continue

        ai_handoff = report.get("ai_handoff", {})
        handoff_items = ai_handoff.get("items", []) if isinstance(ai_handoff, dict) else []
        if isinstance(handoff_items, list):
            for item_data in handoff_items:
                if not isinstance(item_data, dict):
                    continue
                rule_id = item_data.get("rule_id")
                if isinstance(rule_id, str):
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

    top_rule_counts = [
        {"rule_id": rule_id, "count": count}
        for rule_id, count in sorted(rule_counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    ]

    return {
        "total_urls": len(results),
        "success_count": success_count,
        "failure_count": failure_count,
        "average_risk_score": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else None,
        "max_risk_score": max(risk_scores) if risk_scores else None,
        "average_duration_ms": round(sum(durations) / len(durations), 2) if durations else None,
        "overall_safety_counts": overall_safety_counts,
        "filtered_out_total": filtered_out_total,
        "top_rule_counts": top_rule_counts,
    }


async def run() -> int:
    args = parse_args()
    urls = load_urls(Path(args.input))
    if not urls:
        raise SystemExit("No URLs found in input file.")

    semaphore = asyncio.Semaphore(max(1, args.concurrency))
    timeout = httpx.Timeout(args.timeout)

    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [
            audit_one(
                client=client,
                endpoint=args.endpoint,
                url=url,
                max_files=args.max_files,
                max_total_chars=args.max_total_chars,
                ai_classify=args.ai_classify,
                semaphore=semaphore,
            )
            for url in urls
        ]
        results = await asyncio.gather(*tasks)

    output = {
        "endpoint": args.endpoint,
        "request_defaults": {
            "max_files": args.max_files,
            "max_total_chars": args.max_total_chars,
            "ai_classify": args.ai_classify,
        },
        "summary": build_summary(results),
        "results": results,
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"Wrote {len(results)} code audit results to {output_path}")
    print(json.dumps(output["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
