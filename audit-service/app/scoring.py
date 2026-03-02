from __future__ import annotations

from collections import defaultdict

from .models import Finding, Summary, SummaryCounts


SEVERITY_POINTS = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 3,
    "info": 0,
}


def build_summary(findings: list[Finding], capabilities: list[str]) -> tuple[Summary, list[str]]:
    counts = SummaryCounts()
    total = 0
    grouped: dict[str, int] = defaultdict(int)
    grouped_counts: dict[str, int] = defaultdict(int)
    scored_low_keys: set[tuple[str, str]] = set()

    for finding in findings:
        points = SEVERITY_POINTS[finding.severity]
        if finding.severity == "low":
            low_key = (finding.rule_id, finding.evidence.doc_url)
            if low_key in scored_low_keys:
                points = 0
            else:
                scored_low_keys.add(low_key)
        total += points
        grouped[finding.title] += points
        if points > 0:
            grouped_counts[finding.title] += 1
        if finding.severity == "critical":
            counts.critical += 1
        elif finding.severity == "high":
            counts.high += 1
        elif finding.severity == "medium":
            counts.medium += 1
        elif finding.severity == "low":
            counts.low += 1

    capability_bonus = min(12, 3 * len(set(capabilities)))
    total += capability_bonus
    if capability_bonus:
        grouped["Documented risky capabilities"] += capability_bonus
        grouped_counts["Documented risky capabilities"] = len(set(capabilities))

    mutable_bonus = 5 if any(finding.rule_id == "remote-mutable-source" for finding in findings) else 0
    total += mutable_bonus
    if mutable_bonus:
        grouped["Remote mutable dependency bonus"] += mutable_bonus
        grouped_counts["Remote mutable dependency bonus"] = 1

    if counts.critical == 0 and counts.high <= 3:
        total = min(total, 80)

    ordered = sorted(grouped.items(), key=lambda item: (-item[1], item[0]))
    drivers: list[str] = []
    for title, score in ordered[:3]:
        count = grouped_counts.get(title, 1)
        if count > 1 and title not in {"Documented risky capabilities"}:
            drivers.append(f"{score} pts: {title} across {count} findings")
        elif title == "Documented risky capabilities":
            drivers.append(f"{score} pts: {count} documented capabilities")
        else:
            drivers.append(f"{score} pts: {title}")

    return Summary(risk_score=max(0, min(total, 100)), counts=counts), drivers
