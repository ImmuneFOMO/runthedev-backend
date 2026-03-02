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
        description="Batch-submit GitHub markdown URLs to the /audit endpoint."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a text file (one URL per line) or JSON file containing a list of URLs.",
    )
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:8000/audit",
        help="Audit endpoint URL.",
    )
    parser.add_argument(
        "--output",
        default="batch_audit_results.json",
        help="Path to write the aggregated JSON results.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Number of concurrent audit requests.",
    )
    parser.add_argument("--max-depth", type=int, default=2, help="Value for max_depth.")
    parser.add_argument("--max-docs", type=int, default=30, help="Value for max_docs.")
    parser.add_argument(
        "--max-total-chars",
        type=int,
        default=500000,
        help="Value for max_total_chars.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
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


async def audit_one(
    client: httpx.AsyncClient,
    endpoint: str,
    url: str,
    max_depth: int,
    max_docs: int,
    max_total_chars: int,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    payload = {
        "url": url,
        "max_depth": max_depth,
        "max_docs": max_docs,
        "max_total_chars": max_total_chars,
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
    risk_scores = [
        item["report"]["summary"]["risk_score"]
        for item in results
        if item.get("ok") and isinstance(item.get("report"), dict)
    ]
    durations = [item.get("duration_ms", 0.0) for item in results]
    return {
        "total_urls": len(results),
        "success_count": success_count,
        "failure_count": failure_count,
        "average_risk_score": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else None,
        "max_risk_score": max(risk_scores) if risk_scores else None,
        "average_duration_ms": round(sum(durations) / len(durations), 2) if durations else None,
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
                max_depth=args.max_depth,
                max_docs=args.max_docs,
                max_total_chars=args.max_total_chars,
                semaphore=semaphore,
            )
            for url in urls
        ]
        results = await asyncio.gather(*tasks)

    output = {
        "endpoint": args.endpoint,
        "summary": build_summary(results),
        "results": results,
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"Wrote {len(results)} results to {output_path}")
    print(json.dumps(output["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
