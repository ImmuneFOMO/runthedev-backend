# RunTheDev Backend

Discovery and audit platform for MCP servers and Agent Skills. This monorepo contains the API backend and audit service.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│  React Frontend │────▶│  Backend Service  │
│  (separate repo)│     │  Rust / Axum      │
└─────────────────┘     │  Port 4000        │
                        └────────┬──────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼             ▼
              ┌──────────┐ ┌──────────┐ ┌──────────────┐
              │PostgreSQL │ │Meilisearch│ │Audit Service │
              │  :5432    │ │  :7700    │ │ Python/FastAPI│
              └──────────┘ └──────────┘ │  Port 8000    │
                                        └──────────────┘
```

| Service | Tech | Port | Purpose |
|---------|------|------|---------|
| **Backend Service** | Rust, Axum 0.8, SQLx | 4000 | Main API — serves servers, skills, search, admin |
| **Audit Service** | Python, FastAPI | 8000 | Audits MCP skill docs for security risks |
| **PostgreSQL** | 16-alpine | 5432 | Primary database (merged_servers, merged_skills, audit_runs) |
| **Meilisearch** | v1.6 | 7700 | Full-text search engine |

## Quick Start (Docker)

The fastest way to get everything running:

```bash
# 1. Clone the repo
git clone https://github.com/ImmuneFOMO/runthedev-backend.git
cd runthedev-backend

# 2. Create env files from examples
cp .env.example .env
cp backend-service/.env.example backend-service/.env
cp audit-service/.env.example audit-service/.env

# 3. Set required secrets in .env (root)
# - POSTGRES_PASSWORD
# - MEILI_MASTER_KEY
# - ADMIN_API_KEY
# 4. (Optional) Add AI keys for audit explanations
# Edit root .env and add MISTRAL_API_KEY or OPENROUTER_API_KEY

# 5. Start everything
docker compose up --build

# 6. Verify
curl http://localhost:4000/api/stats
curl http://localhost:8000/health
```

That's it! The backend will:
- Connect to PostgreSQL and run migrations
- Connect to Meilisearch and sync data on startup
- Start serving the API on port 4000

## Local Development (without Docker)

For faster iteration, run services individually.

### Prerequisites

- **Rust 1.85+** (for edition 2024) — `rustup update stable`
- **Python 3.11+**
- **PostgreSQL 16**
- **Meilisearch** — [install guide](https://www.meilisearch.com/docs/learn/getting_started/installation)

### Option A: Run infra with Docker, services locally

```bash
# Start only PostgreSQL and Meilisearch
docker compose up postgres meilisearch -d

# Verify they're running
docker compose ps
```

### Start the Backend Service

```bash
cd backend-service

# Create .env from example
cp .env.example .env
# Edit .env if needed (defaults work with docker compose infra)

# Run
cargo run
```

The server starts on `http://localhost:4000`. On first run it will:
1. Run database migrations (creates `audit_runs` table)
2. Sync all data to Meilisearch (may take a minute for 270k+ skills)
3. Start background jobs (daily search sync at 03:00 UTC, audit queue at 04:00 UTC)

### Start the Audit Service

```bash
cd audit-service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Create .env from example
cp .env.example .env
# Edit .env to add AI API keys (optional)

# Run
uvicorn app.main:app --reload --port 8000
```

The audit service starts on `http://localhost:8000`. API docs at `http://localhost:8000/docs`.

---

## API Reference

Base URL: `http://localhost:4000`

All responses are JSON. Errors always return `{ "error": "<message>" }`.

### Authentication

Public endpoints require no authentication. Admin endpoints require a Bearer token:

```
Authorization: Bearer <ADMIN_API_KEY>
```

The `ADMIN_API_KEY` value is set in the backend's `.env` file.

### Pagination

All list endpoints return a paginated envelope:

| Field | Type | Description |
|-------|------|-------------|
| `items` | array | Results for the current page |
| `total` | integer | Total matching items across all pages |
| `page` | integer | Current page (1-indexed) |
| `per_page` | integer | Items per page |
| `total_pages` | integer | Ceiling of `total / per_page` |

- `page` is **1-indexed** (minimum 1)
- `per_page` is clamped to **1–50** (default: 12)
- Requesting a page beyond `total_pages` returns an empty `items` array

### Rate Limiting

| Route Group | Limit | Endpoints |
|-------------|-------|-----------|
| List/Search | 30 req/min per IP | `GET /api/servers`, `GET /api/skills` |
| Public | 60 req/min per IP | Stats, categories, detail endpoints |
| Admin | 120 req/min per IP | All `POST/GET /api/admin/*` |

When exceeded, the API returns:

```json
HTTP/1.1 429 Too Many Requests

{ "error": "Too many requests" }
```

### Error Shapes

**401 Unauthorized** — missing or invalid `Authorization` header on admin routes:

```json
{ "error": "Unauthorized" }
```

**404 Not Found** — `dedup_key` does not match any record:

```json
{ "error": "Not found" }
```

**429 Too Many Requests** — rate limit exceeded:

```json
{ "error": "Too many requests" }
```

---

### Public Endpoints

#### `GET /api/stats`

Aggregate counts for the landing page.

**Headers:** None required.

```bash
curl http://localhost:4000/api/stats
```

**Response:**

```json
{
  "servers_count": 1423,
  "skills_count": 271540,
  "audited_servers": 87,
  "audited_skills": 312
}
```

---

#### `GET /api/servers`

List and search MCP servers with pagination, filtering, and sorting.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | `""` | Full-text search query (routes through Meilisearch when non-empty) |
| `sort` | string | `featured` | Sort order: `featured`, `stars`, `downloads`, `name` |
| `categories` | string | `""` | Comma-separated category filter, e.g. `search,databases` |
| `page` | integer | `1` | Page number (1-indexed) |
| `per_page` | integer | `12` | Results per page (max 50) |

**Sort options for servers:**

| Value | Behavior |
|-------|----------|
| `featured` | Graded servers first, then by stars descending |
| `stars` | GitHub stars descending |
| `downloads` | Weekly downloads descending |
| `name` | Alphabetical ascending |

**Headers:** None required.

```bash
# Browse featured servers
curl "http://localhost:4000/api/servers?page=1&per_page=5"

# Search with category filter
curl "http://localhost:4000/api/servers?q=postgres&categories=databases&sort=stars"
```

**Response:**

```json
{
  "items": [
    {
      "id": 42,
      "name": "postgres-mcp-server",
      "description": "MCP server for PostgreSQL databases",
      "github_url": "https://github.com/example/postgres-mcp",
      "categories": ["databases", "sql"],
      "language": "TypeScript",
      "security_grade": "A",
      "quality_grade": "B+",
      "license_grade": "A",
      "stars": 1250,
      "weekly_downloads": 3400,
      "source_count": 2,
      "audit": {
        "grade": "B+",
        "score": 82.5
      }
    }
  ],
  "total": 47,
  "page": 1,
  "per_page": 5,
  "total_pages": 10
}
```

Fields with `null` values (`github_url`, `language`, `security_grade`, `quality_grade`, `license_grade`, `weekly_downloads`, `audit`) are omitted from the response.

---

#### `GET /api/skills`

List and search Agent Skills with pagination, filtering, and sorting.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | `""` | Full-text search query (routes through Meilisearch when non-empty) |
| `sort` | string | `featured` | Sort order: `featured`, `stars`, `installs`, `name` |
| `categories` | string | `""` | Comma-separated category filter |
| `page` | integer | `1` | Page number (1-indexed) |
| `per_page` | integer | `12` | Results per page (max 50) |

**Sort options for skills:**

| Value | Behavior |
|-------|----------|
| `featured` | Scored skills first, then by stars descending |
| `stars` | GitHub stars descending |
| `installs` | Total installs descending |
| `name` | Alphabetical ascending |

**Headers:** None required.

```bash
# Browse featured skills
curl "http://localhost:4000/api/skills?page=1&per_page=5"

# Search skills
curl "http://localhost:4000/api/skills?q=code+review&sort=installs"
```

**Response:**

```json
{
  "items": [
    {
      "id": 1001,
      "skill_name": "code-review-skill",
      "name": "Code Review",
      "description": "Automated code review using LLMs",
      "github_url": "https://github.com/example/code-review",
      "categories": ["development", "code-quality"],
      "quality_score": 0.91,
      "audit_summary": { "risk_level": "low", "flags": 0 },
      "stars": 540,
      "installs": 12400,
      "source_count": 3,
      "audit": {
        "grade": "A",
        "score": 95.0
      }
    }
  ],
  "total": 271540,
  "page": 1,
  "per_page": 5,
  "total_pages": 54308
}
```

Fields with `null` values (`github_url`, `categories`, `quality_score`, `audit_summary`, `audit`) are omitted from the response.

---

#### `GET /api/servers/categories`

Returns all server category facets with counts. Results are cached for 5 minutes.

**Headers:** None required.

```bash
curl http://localhost:4000/api/servers/categories
```

**Response:**

```json
[
  { "name": "databases", "count": 142 },
  { "name": "search", "count": 98 },
  { "name": "cloud", "count": 73 }
]
```

---

#### `GET /api/skills/categories`

Returns all skill category facets with counts. Results are cached for 5 minutes.

**Headers:** None required.

```bash
curl http://localhost:4000/api/skills/categories
```

**Response:**

```json
[
  { "name": "development", "count": 45200 },
  { "name": "productivity", "count": 31000 },
  { "name": "data", "count": 18700 }
]
```

---

#### `GET /api/servers/{dedup_key}`

Full detail for a single server, including tools, resources, prompts, and up to 3 related servers.

> **Important:** The `dedup_key` often contains `/` characters (e.g. `github/owner/repo`).
> You **must URL-encode** the slashes: `/` → `%2F`.

**Headers:** None required.

```bash
# dedup_key = "github/example/postgres-mcp" → encode slashes
curl "http://localhost:4000/api/servers/github%2Fexample%2Fpostgres-mcp"
```

**Response:**

```json
{
  "id": 42,
  "dedup_key": "github/example/postgres-mcp",
  "name": "postgres-mcp-server",
  "description": "MCP server for PostgreSQL databases",
  "github_owner": "example",
  "github_repo": "postgres-mcp",
  "github_url": "https://github.com/example/postgres-mcp",
  "categories": ["databases", "sql"],
  "language": "TypeScript",
  "license": "MIT",
  "security_grade": "A",
  "quality_grade": "B+",
  "license_grade": "A",
  "stars": 1250,
  "forks": 89,
  "weekly_downloads": 3400,
  "tools": [
    { "name": "query", "description": "Run a SQL query" },
    { "name": "list_tables", "description": "List all tables" }
  ],
  "tools_count": 2,
  "resources": null,
  "prompts": null,
  "connections": null,
  "source_count": 2,
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-02-20T14:00:00Z",
  "audit": {
    "grade": "B+",
    "score": 82.5
  },
  "related": [
    {
      "id": 55,
      "name": "mysql-mcp",
      "categories": ["databases"],
      "stars": 800,
      "security_grade": "B"
    }
  ]
}
```

Returns `404` if the `dedup_key` does not match any server.

---

#### `GET /api/skills/{dedup_key}`

Full detail for a single skill, including markdown content, security audits, engagement metrics, and up to 3 related skills.

> **Important:** URL-encode the `dedup_key` — `/` → `%2F`.

**Headers:** None required.

```bash
curl "http://localhost:4000/api/skills/github%2Fexample%2Fcode-review"
```

**Response:**

```json
{
  "id": 1001,
  "dedup_key": "github/example/code-review",
  "skill_name": "code-review-skill",
  "name": "Code Review",
  "description": "Automated code review using LLMs",
  "github_owner": "example",
  "github_repo": "code-review",
  "github_url": "https://github.com/example/code-review",
  "categories": ["development", "code-quality"],
  "quality_score": 0.91,
  "audit_summary": { "risk_level": "low", "flags": 0 },
  "skill_md_content": "# Code Review Skill\n\nThis skill...",
  "security_audits": [{ "rule": "no-exec", "pass": true }],
  "stars": 540,
  "forks": 32,
  "installs": 12400,
  "weekly_installs": 890,
  "activations": 45000,
  "unique_users": 3200,
  "upvotes": 120,
  "downvotes": 5,
  "source_count": 3,
  "created_at": "2025-01-10T08:00:00Z",
  "updated_at": "2025-03-01T12:00:00Z",
  "audit": {
    "grade": "A",
    "score": 95.0
  },
  "related": [
    {
      "id": 1050,
      "skill_name": "lint-checker",
      "name": "Lint Checker",
      "categories": ["development"],
      "installs": 8900
    }
  ]
}
```

Returns `404` if the `dedup_key` does not match any skill.

---

### Admin Endpoints

All admin endpoints require the `Authorization` header:

```
Authorization: Bearer <ADMIN_API_KEY>
```

Missing or invalid tokens return `401 Unauthorized`:

```json
{ "error": "Unauthorized" }
```

---

#### `POST /api/admin/audit`

Queue an item (server or skill) for audit.

**Headers:**

```
Authorization: Bearer <ADMIN_API_KEY>
Content-Type: application/json
```

**Request Body:**

```json
{
  "item_type": "server",
  "item_dedup_key": "github/example/postgres-mcp"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `item_type` | string | Yes | `"server"` or `"skill"` |
| `item_dedup_key` | string | Yes | The item's `dedup_key` |

```bash
curl -X POST http://localhost:4000/api/admin/audit \
  -H "Authorization: Bearer runthedev-admin-dev-key" \
  -H "Content-Type: application/json" \
  -d '{"item_type": "server", "item_dedup_key": "github/example/postgres-mcp"}'
```

**Response (`200 OK`):**

```json
{
  "id": 1,
  "item_type": "server",
  "item_dedup_key": "github/example/postgres-mcp",
  "status": "pending",
  "result": null,
  "score": null,
  "grade": null,
  "requested_by": "admin",
  "created_at": "2025-03-01T10:00:00Z",
  "completed_at": null
}
```

If the same item already has an in-flight run (`pending`/`running`), the endpoint returns that existing run instead of creating a duplicate.

**Errors:**
- `400 Bad Request` — `item_type` is not `"server"` or `"skill"`
- `400 Bad Request` — `item_dedup_key` is empty or too long
- `404 Not Found` — `item_dedup_key` does not exist in the database

---

#### `GET /api/admin/audits`

List audit runs with optional status filter.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | string | *(all)* | Filter by status: `pending`, `running`, `completed`, `failed` |
| `page` | integer | `1` | Page number (1-indexed) |
| `per_page` | integer | `12` | Results per page (max 50) |

**Headers:**

```
Authorization: Bearer <ADMIN_API_KEY>
```

```bash
curl "http://localhost:4000/api/admin/audits?status=completed&page=1&per_page=10" \
  -H "Authorization: Bearer runthedev-admin-dev-key"
```

**Response:**

```json
{
  "items": [
    {
      "id": 1,
      "item_type": "server",
      "item_dedup_key": "github/example/postgres-mcp",
      "status": "completed",
      "result": { "findings": [] },
      "score": 82.5,
      "grade": "B+",
      "requested_by": "admin",
      "created_at": "2025-03-01T10:00:00Z",
      "completed_at": "2025-03-01T10:02:30Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 10,
  "total_pages": 1
}
```

---

#### `POST /api/admin/sync-search`

Trigger a full Meilisearch re-sync. The sync runs in the background; the endpoint returns immediately.

**Headers:**

```
Authorization: Bearer <ADMIN_API_KEY>
```

```bash
curl -X POST http://localhost:4000/api/admin/sync-search \
  -H "Authorization: Bearer runthedev-admin-dev-key"
```

**Response (`202 Accepted`):**

```json
{ "status": "sync_started" }
```

If a sync is already running, the endpoint returns `409 Conflict`:

```json
{ "status": "sync_already_running" }
```

---

### Audit Service Endpoints

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/audit` | Audit a GitHub skill URL |
| POST | `/audit/explain` | AI-enhanced audit explanation |
| POST | `/audit/marketplace` | Marketplace-formatted audit |

See the Audit Service's own docs at `http://localhost:8000/docs` for full request/response details.

---

## Environment Variables

### Backend Service

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `MEILI_URL` | Yes | — | Meilisearch URL |
| `MEILI_MASTER_KEY` | Yes | — | Meilisearch API key |
| `ADMIN_API_KEY` | Yes | — | Bearer token for admin endpoints |
| `HOST` | No | `0.0.0.0` | Bind address |
| `PORT` | No | `4000` | Bind port |
| `RUST_LOG` | No | `info` | Log level (trace/debug/info/warn/error) |
| `CORS_EXTRA_ORIGINS` | No | — | Comma-separated extra allowed browser origins |

### Audit Service

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISTRAL_API_KEY` | No* | — | Mistral AI key |
| `OPENROUTER_API_KEY` | No* | — | OpenRouter key |
| `MISTRAL_MODEL` | No | `mistral-small-latest` | Mistral model name |
| `OPENROUTER_MODEL` | No | `mistralai/mistral-small-3.1-24b-instruct` | OpenRouter model name |
| `LLM_TIMEOUT_SECONDS` | No | `15` | AI call timeout |

*At least one AI key needed for `/audit/explain`. Without it, only deterministic rules run.

## Database

The backend uses two pre-existing tables (`merged_servers`, `merged_skills`) populated by a separate scraper. The backend creates one additional table via migration:

- **`audit_runs`** — Tracks audit requests and results

To reset the database:
```bash
docker compose down -v  # removes volumes
docker compose up -d postgres
```

## Project Structure

```
runthedev-backend/
├── docker-compose.yml           # Full dev stack
├── README.md                    # This file
├── backend-service/
│   ├── Cargo.toml
│   ├── Dockerfile
│   ├── .env.example
│   ├── rust-toolchain.toml      # Pins Rust 1.85+
│   ├── migrations/
│   │   └── 001_create_audit_runs.sql
│   └── src/
│       ├── main.rs              # Entrypoint — wires everything
│       ├── config.rs            # Environment configuration
│       ├── state.rs             # Shared app state
│       ├── error.rs             # Error types → HTTP responses
│       ├── routes/              # HTTP handlers
│       ├── models/              # Data structs
│       ├── search/              # Meilisearch sync & query
│       ├── jobs/                # Background cron jobs
│       └── middleware/          # Auth & rate limiting
└── audit-service/
    ├── Dockerfile
    ├── .env.example
    ├── requirements.txt
    └── app/
        ├── main.py              # FastAPI app
        ├── models.py            # Pydantic models
        ├── rules.py             # 30+ security rules
        ├── fetcher.py           # GitHub doc fetcher
        ├── parser.py            # Markdown parser
        ├── scoring.py           # Risk scoring
        └── ai_reviewer.py       # AI review layer
```

## License

MIT
