# MCP Skill Audit Service

Doc-first audit service for MCP skill documentation hosted on GitHub.

It performs two separate jobs:

1. `POST /audit`
   - fetches a root `SKILL.md` or `README.md`
   - follows bounded in-scope markdown/config links and skill dependencies
   - runs deterministic security rules
   - returns a structured risk report

2. `POST /audit/explain`
   - accepts the raw `Report` returned by `/audit`
   - runs one AI prioritization pass
   - returns the original report plus a structured AI review

The AI layer does not fetch documents, crawl the web, or replace the rule engine. It only explains and prioritizes the existing report.

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

## Batch testing

To submit a list of GitHub markdown URLs to `/audit`, use [scripts/batch_audit.py](scripts/batch_audit.py).

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

## Environment

The app loads `.env` automatically on startup via `python-dotenv`.

Example `.env`:

```env
MISTRAL_API_KEY=your_mistral_api_key_here
MISTRAL_MODEL=mistral-small-latest

OPENROUTER_API_KEY=your_openrouter_api_key_here
OPENROUTER_MODEL=mistralai/mistral-small-3.1-24b-instruct

LLM_TIMEOUT_SECONDS=15
```

Provider selection order:

1. `MISTRAL_API_KEY` -> Mistral reviewer
2. `OPENROUTER_API_KEY` -> OpenRouter reviewer
3. otherwise -> deterministic `NoOpReviewer`

## API

### `GET /health`

Simple health check.

### `POST /audit`

Request body:

```json
{
  "url": "https://github.com/OWNER/REPO/blob/main/path/to/SKILL.md",
  "max_depth": 2,
  "max_docs": 30,
  "max_total_chars": 500000
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

Example:

```bash
curl -X POST http://127.0.0.1:8000/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://github.com/inference-sh/skills/blob/main/skills/agent-ui/SKILL.md",
    "max_depth": 2,
    "max_docs": 30,
    "max_total_chars": 500000
  }'
```

### `POST /audit/explain`

Accepts the raw `Report` returned by `/audit` directly.

This endpoint:

- selects the active reviewer (`mistral`, `openrouter`, or `noop`)
- sends one compact evidence bundle to the AI provider
- sanitizes the model output so it stays tied to the actual findings
- returns the original report plus AI review metadata

Example flow:

1. Call `/audit`
2. Save the JSON response to `report.json`
3. Send that file directly to `/audit/explain`

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

### `POST /audit/marketplace`

Returns the same underlying audit, but mapped into a marketplace-style envelope suitable for catalog views.

Example:

```bash
curl -X POST http://127.0.0.1:8000/audit/marketplace \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://github.com/rudrankriyam/asc-skills/blob/main/skills/asc-cli-usage/SKILL.md"
  }'
```

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

Capabilities currently tracked:

- `shell`
- `filesystem`
- `network`
- `browser`
- `proxy`
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
- For app integration, the intended flow is `POST /audit` first and then `POST /audit/explain` using the raw report from the first call.
