# MCP Skill Audit Service

Doc-first audit service for MCP skill documentation hosted on GitHub.

Use the API in two modes:

- Detailed/internal mode:
  - `POST /audit`
  - `POST /audit/explain`
  - `POST /audit/code`
  These return full structured reports with findings, evidence, clusters, and debug fields.

- Website/product mode:
  - `POST /audit/skill/summary`
  - `POST /audit/code/summary`
  These return compact user-facing summaries. If you are building a website, dashboard, marketplace, or trust page, use the summary endpoints.

It performs two separate jobs:

1. `POST /audit`
   - fetches a root `SKILL.md` or `README.md`
   - follows bounded in-scope markdown/config links and skill dependencies
   - runs deterministic security rules
   - optionally adds inline AI explanation when `ai_explain=true`
   - returns a structured risk report

2. `POST /audit/skill/summary`
   - runs the same skill audit pipeline
   - returns a compact trust/safety summary without raw snippets or findings

3. `POST /audit/explain`
   - accepts the raw `Report` returned by `/audit`
   - runs one AI prioritization pass
   - returns the original report plus a structured AI review

4. `POST /audit/code`
   - accepts a GitHub repo URL or GitHub tree/blob URL
   - fetches a bounded set of relevant source/config files directly from GitHub without cloning
   - runs deterministic code-level MCP security checks
   - returns a structured code audit report

5. `POST /audit/code/summary`
   - runs the same code audit pipeline
   - returns a compact trust/safety summary without raw findings or code snippets

The AI layer does not fetch documents, crawl the web, or replace the rule engine. It only explains and prioritizes the existing report.

## Hackathon rules and compliance

For this service, follow these requirements during the hackathon:

- All projects must be built during the hackathon timeframe.
- Teams must consist of 1 to 4 participants.
- Use of open-source libraries, APIs, and pre-trained models is allowed, provided they are properly credited.
- All code and demos must be submitted before the final deadline to be eligible for judging.
- Projects must comply with applicable laws, ethical AI practices, and the hackathon code of conduct.
- Mistral, partner, and sponsor APIs must be used in accordance with their respective terms of service.
- The organizing team reserves the right to disqualify any team that violates the rules or engages in unfair practices.

## Stack

- Python 3.11+
- FastAPI
- `httpx`
- `markdown-it-py`
- LangChain
- Mistral API or OpenRouter for AI review

## Project layout

```text
app/
  main.py
  fetcher.py
  code_audit/
    github_code_fetcher.py
    file_selector.py
    analyzers.py
    patterns.py
    models.py
  parser.py
  rules.py
  scoring.py
  ai_reviewer.py
  models.py
tests/
requirements.txt
README.md
```

## Run locally

Create a virtualenv, install dependencies, and start the server:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/health`

## Test locally

```bash
source .venv/bin/activate
python -m pytest
```

## Batch testing

To submit a list of GitHub markdown URLs to `/audit`, use [scripts/batch_audit.py](/Users/yuriy/Documents/Github/Work/mcp-sentinel/scripts/batch_audit.py).

Create a file with one URL per line, for example `urls.txt`:

```text
https://github.com/inference-sh/skills/blob/main/skills/agent-ui/SKILL.md
https://github.com/mik0w/pallms/blob/main/README.md
https://github.com/wshobson/agents/blob/main/plugins/conductor/skills/track-management/SKILL.md
```

Then run:

```bash
source .venv/bin/activate
python scripts/batch_audit.py --input urls.txt --output batch_audit_results.json
```

Useful flags:

- `--endpoint http://127.0.0.1:8000/audit`
- `--concurrency 4`
- `--max-depth 2`
- `--max-docs 30`
- `--max-total-chars 500000`

The script writes one aggregated JSON file with a summary plus per-URL results.

To take the successful `report` entries from `batch_audit_results.json` and send them to `/audit/explain`, use [scripts/batch_explain.py](/Users/yuriy/Documents/Github/Work/mcp-sentinel/scripts/batch_explain.py):

```bash
source .venv/bin/activate
python scripts/batch_explain.py \
  --input batch_audit_results.json \
  --output batch_explain_results.json
```

This writes one aggregated JSON file with:

- per-URL explain results
- AI priority counts
- reviewer usage counts
- per-request timing

To batch-test MCP server repos against `/audit/code`, use [scripts/batch_code_audit.py](/Users/yuriy/Documents/Github/Work/mcp-sentinel/scripts/batch_code_audit.py).

The repo ships with a starter list in [scripts/mcp_urls.txt](/Users/yuriy/Documents/Github/Work/mcp-sentinel/scripts/mcp_urls.txt):

```bash
source .venv/bin/activate
python scripts/batch_code_audit.py \
  --input scripts/mcp_urls.txt \
  --output batch_code_audit_results.json \
  --ai-classify
```

Useful flags:

- `--endpoint http://127.0.0.1:8000/audit/code`
- `--concurrency 4`
- `--max-files 40`
- `--max-total-chars 400000`
- `--ai-classify`

The code batch runner writes:

- per-target `/audit/code` results
- a compact `snapshot` per target with `risk_score`, `overall_safety`, and top drivers
- aggregate `overall_safety_counts`
- aggregate `filtered_out_total`
- aggregate top `rule_id` counts

## Environment

The app loads `.env` automatically on startup via `python-dotenv`.

Example `.env`:

```env
GITHUB_TOKEN=ghp_your_github_token_here

MISTRAL_API_KEY=your_mistral_api_key_here
MISTRAL_MODEL=mistral-small-latest

OPENROUTER_API_KEY=your_openrouter_api_key_here
OPENROUTER_MODEL=mistralai/mistral-small-3.1-24b-instruct

LLM_TIMEOUT_SECONDS=15
```

Provider selection order:

1. `MISTRAL_API_KEY` -> Mistral reviewer and optional `/audit/code` AI triage
2. `OPENROUTER_API_KEY` -> OpenRouter reviewer
3. otherwise -> deterministic `NoOpReviewer`

`GITHUB_TOKEN` is optional, but recommended for `POST /audit/code` to avoid GitHub API rate limits when resolving repository metadata and directory listings. Direct blob audits prefer raw GitHub content and minimize API usage, but repo and tree audits still benefit from an authenticated token.

## API

### Which endpoint should I use?

Use these endpoints by intent:

- If you are building a website or product UI:
  - use `POST /audit/skill/summary` for skill docs
  - use `POST /audit/code/summary` for code repos
- If you need raw findings, evidence, drivers, clusters, or debug data:
  - use `POST /audit` for skill docs
  - use `POST /audit/code` for source code
- If you already have a raw skill audit report and want an extra AI explanation pass:
  - use `POST /audit/explain`

Short version:

- Website: use the summary endpoints
- Internal review/debugging: use the detailed endpoints

### `GET /health`

Simple health check.

### `POST /audit`

Request body:

```json
{
  "url": "https://github.com/OWNER/REPO/blob/main/path/to/SKILL.md",
  "max_depth": 2,
  "max_docs": 30,
  "max_total_chars": 500000,
  "ai_explain": false
}
```

Accepted input URLs:

- `github.com/.../blob/...`
- `github.com/.../tree/...`
- `raw.githubusercontent.com/...`

What it returns:

- fetched document graph
- graph summary
- risk score and severity counts
- capabilities detected
- rule findings with evidence
- optional `ai_review` and `meta` when `ai_explain=true`

Example:

```bash
curl -X POST http://127.0.0.1:8000/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://github.com/inference-sh/skills/blob/main/skills/agent-ui/SKILL.md",
    "max_depth": 2,
    "max_docs": 30,
    "max_total_chars": 500000,
    "ai_explain": true
  }'
```

How to use it:

- `ai_explain=false`: deterministic skill report only
- `ai_explain=true`: deterministic skill report plus inline AI review
- use `POST /audit` when you want the full structured report
- use `POST /audit/skill/summary` when you only want a compact end-user trust summary

Important:

- `POST /audit` is not the best endpoint for a website
- for websites, dashboards, or catalog pages, use `POST /audit/skill/summary`
- `POST /audit` is better for internal review, debugging, and model tuning

### `POST /audit/skill/summary`

Compact user-facing summary built from the same skill audit pipeline.

Request body is the same as `POST /audit`.

Use this when you want:

- one pass/warn/fail status
- provider audit statuses
- risk categories
- concise “what to do to stay safe” guidance

This is the recommended endpoint for:

- websites
- trust pages
- marketplace cards
- product UIs
- user-facing summaries

Example:

```bash
curl -X POST http://127.0.0.1:8000/audit/skill/summary \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://github.com/OWNER/REPO/blob/main/skills/find-skills/SKILL.md",
    "ai_explain": true
  }'
```

Response shape:

```json
{
  "skill_name": "find-skills",
  "status": "Fail",
  "audited_by": "Run The Dev",
  "audited_at": "Mar 1, 2026",
  "risk_level": "HIGH",
  "security_audits": [
    {
      "provider": "Run The Dev",
      "status": "Fail"
    }
  ],
  "risk_categories": [
    "EXTERNAL_DOWNLOADS",
    "COMMAND_EXECUTION"
  ],
  "full_analysis": [
    {
      "category": "EXTERNAL_DOWNLOADS",
      "severity": "HIGH",
      "analysis": "The docs install or load configuration directly from a remote URL. Recommended action: Prefer pinned versions."
    }
  ],
  "safe_usage_recommendations": [
    "Prefer pinned versions.",
    "Use least privilege."
  ]
}
```

### `POST /audit/explain`

Accepts the raw `Report` returned by `/audit` directly.

This endpoint:

- selects the active reviewer (`mistral`, `openrouter`, or `noop`)
- sends a compact bounded evidence summary to the AI provider instead of the full report JSON
- asks the model for a tiny tagged response: priority, top rule ids, false-positive hints, attack-path hint, fixes, and confidence
- reconstructs the final `ai_review` server-side and sanitizes it so it stays tied to the actual findings
- returns the original report plus AI review metadata

Token behavior:

- `/audit/explain` does not send the full markdown graph or all findings to the model
- it sends only a bounded summary plus selected medium-or-higher findings
- the model no longer has to generate the full `AIReviewResult` JSON schema directly
- token usage remains available under `meta.token_usage`

Example flow:

1. Call `/audit` if you want the deterministic report first, or call `/audit` with `ai_explain=true` for inline AI.
2. If you want a second explicit explain pass, save the JSON response to `report.json`
3. Send that file directly to `/audit/explain`

This endpoint is mainly for:

- internal analysis
- security review workflows
- comparing deterministic and AI interpretations

It is not the recommended endpoint for websites.

```bash
curl -X POST http://127.0.0.1:8000/audit/explain \
  -H 'Content-Type: application/json' \
  -d @report.json
```

Response shape:

```json
{
  "rule_report": {},
  "ai_review": {
    "ai_summary": "string",
    "ai_priority": "low|medium|high|critical",
    "top_true_risks": ["string"],
    "likely_false_positive_candidates": ["string"],
    "ai_attack_path": "string|null",
    "ai_must_fix_first": ["string"],
    "confidence": 0.9
  },
  "meta": {
    "reviewer_used": "mistral|openrouter|noop",
    "fallback_reason": null,
    "token_usage": {
      "input_tokens": 123,
      "output_tokens": 45,
      "total_tokens": 168
    }
  }
}
```

Token usage is reported per `/audit/explain` request. For `noop` fallback, all token counts are `0`.

### `POST /audit/code`

Deterministic code audit mode for MCP server implementations.

Request body:

```json
{
  "url": "https://github.com/OWNER/REPO",
  "max_files": 40,
  "max_total_chars": 400000,
  "ai_classify": false
}
```

Accepted input URLs:

- `https://github.com/OWNER/REPO`
- `https://github.com/OWNER/REPO/tree/REF/path`
- `https://github.com/OWNER/REPO/blob/REF/path`

API usage:

- Required request field:
  - `url`
- Usually useful request fields:
  - `ai_classify`: enable AI cluster triage
  - `max_files`: limit selected files for repo or tree scans
  - `max_total_chars`: bound total fetched content
- Read these response fields first:
  - `overall_safety`: top-level verdict
  - `summary.risk_score`: final cluster-based score
  - `drivers`: short explanation of what drove the score
  - `clusters.primary`: actionable kept clusters
- Use these response fields when you need detail:
  - `coverage_scope`: what is actually covered by this audit
  - `clusters.suppressed`: what AI filtered out
  - `ai_handoff`: what was sent to AI
  - `findings`: raw/debug evidence rows
  - `snapshot`: compact UI summary

Important:

- `POST /audit/code` is the detailed endpoint
- for websites, dashboards, or trust/product pages, use `POST /audit/code/summary`
- use `POST /audit/code` when you need clusters, findings, evidence, or debug data

This endpoint:

- uses GitHub repo metadata plus the GitHub contents API to resolve targets
- fetches selected files from GitHub directly, without cloning the repository
- prioritizes likely MCP server entrypoints and security-relevant paths
- keeps recursion and total fetched content bounded by request limits
- does not require an LLM
- can optionally run a tiny Mistral-based post-triage on deterministic cluster candidates when `ai_classify=true`
- always returns `coverage_scope` so the API contract is explicit about what rule families are scored
- uses a cluster-first model: primary clusters are the actionable truth unit; raw findings remain for debugging
- always returns `overall_safety` as a concise trust verdict derived from cluster-level risk

To enable AI triage:

- set `MISTRAL_API_KEY` in your environment or `.env`
- optionally set `MISTRAL_MODEL` if you do not want the default `mistral-small-latest`
- send `"ai_classify": true` in the `/audit/code` request body

How to read the result:

- `capabilities` and `scanned_files` always come from the deterministic scanner
- `coverage_scope` describes the supported rule families and scoring policy
- `clusters.primary[]` is the main actionable list to render in UI or review workflows
- `clusters.suppressed[]` contains cluster candidates that AI explicitly suppressed
- `findings[]` is debug-oriented evidence output; summaries and scores are not derived from raw findings
- if `ai_classify=false`, `summary` reflects deterministic candidate clusters within the coverage scope
- if `ai_classify=true`, `summary` reflects AI-kept primary clusters within the coverage scope
- `ai_triage.results[]` is compact per-cluster AI classification keyed by `cluster_id`
- `ai_triage.filtered_out_count` tells you how many clusters were suppressed as likely false positives
- `ai_triage.overall` is a combined repo-level verdict synthesized from kept AI-triaged clusters
- `overall_safety` is the main high-level verdict to read first; it is always present, even when AI triage is disabled
- AI is classification-only; the final JSON report is still produced deterministically

Example:

```bash
curl -X POST http://127.0.0.1:8000/audit/code \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://github.com/OWNER/REPO",
    "max_files": 40,
    "max_total_chars": 400000,
    "ai_classify": true
  }'
```

Response shape:

```json
{
  "input_url": "string",
  "root_target": "OWNER/REPO@ref:path",
  "scanned_files": [
    {
      "path": "server.py",
      "url": "https://raw.githubusercontent.com/...",
      "language": "python",
      "char_count": 1234,
      "context": "server"
    }
  ],
  "coverage_scope": {
    "version": "scope-v1",
    "supported_rules": ["ssrf-fetch", "command-execution"],
    "out_of_scope": ["No full SAST/AST/CFG"],
    "scoring_policy": {
      "final_risk_uses": "ai_kept_clusters_within_supported_rules",
      "deterministic_risk_uses": "candidate_clusters_within_supported_rules"
    }
  },
  "summary": {
    "risk_score": 75,
    "counts": {
      "critical": 1,
      "high": 2,
      "medium": 1,
      "low": 0
    }
  },
  "drivers": ["35 pts: Unsafe command execution"],
  "capabilities": ["network", "shell"],
  "clusters": {
    "primary": [
      {
        "cluster_id": "ssrf-fetch:server.py:fetch:/api",
        "rule_id": "ssrf-fetch",
        "deterministic_severity": "high",
        "context": "mcp",
        "file_path": "server.py",
        "primary_line": 120,
        "primary_snippet": "return fetch(userUrl)",
        "nearby_context": "const userUrl = payload.url; return fetch(userUrl);",
        "capabilities": ["network"],
        "cluster_size": 2,
        "example_locations": [{"line": 120, "snippet": "return fetch(userUrl)"}],
        "taint_summary": {
          "source": "user_input",
          "sink": "network",
          "is_probably_exposed": true,
          "guards_seen": []
        },
        "ai": {
          "verdict": "tp",
          "risk": "high",
          "confidence": 0.82,
          "reason": "User-controlled URL reaches an outbound fetch in MCP runtime code."
        },
        "final": {
          "kept": true,
          "why_kept": "User-controlled URL reaches an outbound fetch in MCP runtime code."
        }
      }
    ],
    "suppressed": [],
    "debug_duplicates": [],
    "stats": {
      "total_clusters": 1,
      "primary_clusters": 1,
      "suppressed_clusters": 0,
      "duplicate_findings": 1
    }
  },
  "overall_safety": {
    "verdict": "unsafe",
    "risk": "high",
    "confidence": 0.82,
    "source": "ai_combined",
    "summary": "1 actionable clusters remained after AI filtering; highest remaining risk is high."
  },
  "snapshot": {
    "risk_score": 75,
    "overall_safety": "unsafe",
    "overall_risk": "high",
    "primary_clusters": 1,
    "kept_clusters": 1,
    "suppressed_clusters": 0,
    "drivers": ["35 pts: Unsafe command execution"]
  },
  "findings": [
    {
      "severity": "high",
      "rule_id": "arbitrary-file-read",
      "title": "Arbitrary file read access",
      "description": "Read access appears to use an externally controlled path in server or MCP runtime code.",
      "confidence": 0.9,
      "evidence": {
        "file_path": "server.py",
        "line": 120,
        "snippet": "open(file_path, \"rb\")"
      },
      "recommendation": [
        "Restrict file operations to a dedicated base directory and normalize paths before use."
      ],
      "context": "mcp",
      "ai_verdict": "likely_tp",
      "ai_risk": "high",
      "ai_confidence": 0.82
    }
  ],
  "ai_triage": {
    "model": "mistral-small-latest",
    "batch_size": 8,
    "filtered_out_count": 2,
    "overall": {
      "verdict": "likely_tp",
      "risk": "medium",
      "confidence": 0.78,
      "recommendations": [
        "restrict file paths to a base directory",
        "add approval gates for dangerous tools"
      ]
    },
    "results": [
      {
        "cluster_id": "ssrf-fetch:server.py:fetch:/api",
        "action": "keep",
        "risk": "high",
        "confidence": 0.82,
        "reason": "User-controlled URL reaches an outbound fetch in MCP runtime code."
      }
    ]
  }
}
```

Recommended consumer behavior:

1. Use `overall_safety` as the quickest “how safe is this code?” signal.
2. Use `clusters.primary` as the cleaned actionable list for review or UI display.
3. Use `clusters.suppressed` and `ai_triage.filtered_out_count` if you need to understand what AI triage suppressed.

### `POST /audit/code/summary`

Compact user-facing summary built from the same `/audit/code` pipeline.

Use this when you do not want to expose code snippets, raw findings, or cluster internals and only need:

- `security_score`
- `quality_score`
- `overall_risk`
- `status`
- `top_risks`
- `safe_usage_recommendations`
- `deployment_guidance`

This is the recommended endpoint for:

- websites
- product summaries
- trust pages
- “is this MCP safe to use?” UI
- deployment recommendation cards

Request body is the same as `POST /audit/code`.

Example:

```bash
curl -X POST http://127.0.0.1:8000/audit/code/summary \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://github.com/OWNER/REPO",
    "max_files": 40,
    "max_total_chars": 400000,
    "include_tests": false,
    "ai_classify": true
  }'
```

Example response:

```json
{
  "audited_by": "Run The Dev",
  "audited_at": "Mar 1, 2026",
  "risk_level": "HIGH",
  "security_score": 78,
  "quality_score": 84,
  "overall_risk": "high",
  "status": "hardening_required",
  "top_risks": [
    "Outbound requests may forward user-controlled parameters to external services."
  ],
  "safe_usage_recommendations": [
    "Restrict outbound network access to trusted domains only and monitor external requests."
  ],
  "deployment_guidance": {
    "local_dev": "acceptable_with_caution",
    "staging": "hardening_required",
    "production": "not_recommended"
  }
}
```

Notes:

- `security_score` is derived from the final cluster-based `risk_score`
- `quality_score` is a separate operational quality estimate based on kept cluster risk and runtime capability footprint
- when `ai_classify=true`, both scores use AI-kept clusters, not suppressed ones

## Rule coverage

Current rule families include:

- remote mutable source references
- SSRF-style URL-fetch language
- public exposure hints
- secret placeholders vs likely live secrets
- env file guidance
- remote install manifests
- API proxy routes with environment keys
- file upload capability
- client-side tool capability
- missing guardrails for documented capabilities

`POST /audit/code` currently adds these code-level rule families:

- `command-execution`
- `arbitrary-file-read`
- `arbitrary-file-write`
- `arbitrary-file-delete`
- `path-traversal`
- `ssrf-fetch`
- `open-proxy-endpoint`
- `hardcoded-secret`
- `missing-webhook-verification`

Coverage scope:

- scored and AI-triaged rule families are intentionally limited to supported code-audit categories
- output is cluster-first; raw `findings` are debug-only evidence
- AI does classification only; it does not generate the report JSON itself
- `unsafe-docker-runtime`
- `tool-approval-missing`
- `prompt-injection-sensitive-wiring`
- `auth-missing-on-network-service`

Capabilities currently tracked:

- `shell`
- `filesystem`
- `network`
- `browser`
- `proxy`

Code-audit capabilities currently tracked:

- `shell`
- `filesystem`
- `network`
- `docker`

Code-audit scoring notes:

- repeated file-access sinks are clustered by file + sink signature before scoring
- file-access scoring is cluster-based instead of raw-hit-based
- CLI and CI contexts are downweighted unless the finding looks sensitive or destructive

## Code audit limitations

The code audit mode is intentionally deterministic and bounded. It is useful for fast, understandable risk triage, but it is not a full SAST engine.

Current limitations:

- GitHub-only inputs: repo, tree, and blob URLs on `github.com`
- no repository cloning and no arbitrary external crawling
- heuristic data-flow only; it does not build full interprocedural taint analysis
- findings are limited to fetched files, subject to `max_files` and `max_total_chars`
- auth, approval, and allowlist checks are inferred from nearby code patterns and can miss framework-level protections
- some findings are intentionally conservative to avoid flagging every `subprocess` or network call
- `file-upload`
- `client-side-tools`

## Fetching behavior

The fetcher is intentionally bounded and deterministic.

It supports:

- relative in-repo markdown links
- direct config links (`.json`, `.yml`, `.yaml`, `.toml`)
- `npx skills add OWNER/REPO@SKILL` dependency references

Safety limits:

- `max_depth`
- `max_docs`
- `max_total_chars`
- visited-set loop prevention

## Testing

Run the test suite:

```bash
source .venv/bin/activate
python -m pytest tests
```

## Notes

- If the AI review returns `reviewer_used: "noop"`, the service fell back to deterministic summarization.
- If `fallback_reason` is non-null, it usually indicates provider rate limits, invalid model output, or upstream API failure.
- For app integration, you can either:
  - call `POST /audit` with `ai_explain=true` for one-call skill audit + AI review, or
  - call `POST /audit` first and then `POST /audit/explain` using the raw report from the first call.
