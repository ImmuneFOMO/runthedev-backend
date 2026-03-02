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
        description="Read batch_audit_results.json and submit successful reports to /audit/explain."
    )
    parser.add_argument(
        "--input",
        default="batch_audit_results.json",
        help="Path to a batch audit results JSON file.",
    )
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:8000/audit/explain",
        help="Explain endpoint URL.",
    )
    parser.add_argument(
        "--output",
        default="batch_explain_results.json",
        help="Path to write the aggregated explain results.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Number of concurrent explain requests.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-request timeout in seconds.",
    )
    parser.add_argument(
        "--only-successful-audits",
        action="store_true",
        default=True,
        help="Process only entries with ok=true and a report payload (default behavior).",
    )
    return parser.parse_args()


def load_reports(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    results = raw.get("results")
    if not isinstance(results, list):
        raise ValueError("Input file must contain a top-level 'results' array.")

    reports: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        if not item.get("ok"):
            continue
        report = item.get("report")
        if not isinstance(report, dict):
            continue
        reports.append(
            {
                "url": item.get("url"),
                "audit_status_code": item.get("status_code"),
                "audit_duration_ms": item.get("duration_ms"),
                "report": report,
            }
        )
    return reports


async def explain_one(
    client: httpx.AsyncClient,
    endpoint: str,
    record: dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    started = time.perf_counter()
    async with semaphore:
        try:
            response = await client.post(endpoint, json=record["report"])
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            result: dict[str, Any] = {
                "url": record.get("url"),
                "audit_status_code": record.get("audit_status_code"),
                "audit_duration_ms": record.get("audit_duration_ms"),
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            }
            try:
                body = response.json()
            except json.JSONDecodeError:
                body = {"detail": response.text[:1000]}

            if response.is_success:
                result["ok"] = True
                result["explanation"] = body
            else:
                result["ok"] = False
                result["error"] = body
            return result
        except httpx.HTTPError as exc:
            return {
                "url": record.get("url"),
                "audit_status_code": record.get("audit_status_code"),
                "audit_duration_ms": record.get("audit_duration_ms"),
                "ok": False,
                "status_code": None,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "error": {"detail": str(exc)},
            }


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    success_count = sum(1 for item in results if item.get("ok"))
    failure_count = len(results) - success_count
    durations = [item.get("duration_ms", 0.0) for item in results]
    priorities: dict[str, int] = {}
    reviewers: dict[str, int] = {}

    for item in results:
        if not item.get("ok"):
            continue
        explanation = item.get("explanation", {})
        ai_review = explanation.get("ai_review", {})
        meta = explanation.get("meta", {})
        priority = ai_review.get("ai_priority")
        reviewer = meta.get("reviewer_used")
        if isinstance(priority, str):
            priorities[priority] = priorities.get(priority, 0) + 1
        if isinstance(reviewer, str):
            reviewers[reviewer] = reviewers.get(reviewer, 0) + 1

    return {
        "total_reports": len(results),
        "success_count": success_count,
        "failure_count": failure_count,
        "average_duration_ms": round(sum(durations) / len(durations), 2) if durations else None,
        "priority_counts": priorities,
        "reviewer_counts": reviewers,
    }


async def run() -> int:
    args = parse_args()
    records = load_reports(Path(args.input))
    if not records:
        raise SystemExit("No successful audit reports found in input file.")

    semaphore = asyncio.Semaphore(max(1, args.concurrency))
    timeout = httpx.Timeout(args.timeout)

    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [
            explain_one(
                client=client,
                endpoint=args.endpoint,
                record=record,
                semaphore=semaphore,
            )
            for record in records
        ]
        results = await asyncio.gather(*tasks)

    output = {
        "endpoint": args.endpoint,
        "summary": build_summary(results),
        "results": results,
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"Wrote {len(results)} explanation results to {output_path}")
    print(json.dumps(output["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
