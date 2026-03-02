# RunTheDev CLI -- Implementation Spec

## What This Is

A Rust CLI tool that lets developers check MCP servers and agent skills against our audit database before installing them into their coding tools (Claude Code, Codex, OpenCode, etc).

**Core flow:**
```
$ rtd check github.com/user/cool-mcp

  Found: cool-mcp (MCP Server)
  Audit: PASSED (grade: A, score: 92.3)
    Security:  A
    Quality:   A
    License:   MIT

  Install methods:
    [1] Local (stdio)  -- npx -y @user/cool-mcp
    [2] Remote (HTTP)  -- https://cool-mcp.example.com/mcp

  > Choose: 1

  Install to:
    [x] Claude Code
    [x] Codex
    [ ] OpenCode
    [ ] Cursor

  > Done. Installed to Claude Code, Codex.
```

If audit is bad:
```
  Audit: FAILED (grade: D, score: 34.1)
    - CRITICAL: Unsanitized shell exec in tools handler
    - HIGH: Hardcoded credentials detected
    - MEDIUM: No input validation on user parameters

  Are you sure you want to install? [y/N]
```

If no audit exists:
```
  No audit available for this package.
  Your request has been recorded (7/10 requests before auto-audit).
  If you still want to install, choose a target:
    [ ] Claude Code
    [ ] Codex
    [ ] OpenCode
```

---

## Research Summary

### Existing Tools Analyzed (repos cloned to /tmp/mcp-research/)

We cloned and deeply analyzed 8 projects with subagents. Here are the key takeaways:

#### Package Managers (install MCP to clients)

| Project | Lang | Stars | Clients | Key Insight |
|---|---|---|---|---|
| **Smithery CLI** | TypeScript | 533 | 17 clients | Best reference for client config writing. `src/config/clients.ts` (438 LOC) has all 17 client definitions. `src/lib/client-config-io.ts` (699 LOC) handles JSON/JSONC/YAML format translation. Supports `claude mcp add` (CLI-based) and file-based configs. |
| **MCPM** | Python | ~200 | 14 clients | Polymorphic `BaseClientManager` -> `JSONClientManager`/`YAMLClientManager` with per-client managers. Writes delegating `mcpm run` entries. 379-server bundled registry. |
| **mcptools** | Go | 1.5K | 6 clients | Simple approach: hardcoded 6 config paths (macOS only). `configs set windsurf,cursor,vscode ServerName -- command args` for multi-client install. |

#### Security Scanners (audit MCP)

| Project | Lang | Stars | Key Insight |
|---|---|---|---|
| **mcp-scan** (Snyk) | Python | ~2K | Most mature. BUT detection is a **black-box cloud API** -- local tool only collects data and sends to `api.snyk.io`. Supports 13+ client config paths. Tool pinning via MD5 hash of descriptions. |
| **AgentAudit** | JavaScript | new | **Closest to our concept** (~80% overlap). `agentaudit scan <git-url>` does quick regex scan (11 patterns, 2 sec). `agentaudit audit <git-url>` sends source to LLM for deep audit. Has registry at agentaudit.dev. Discovers 20+ client configs. But: no install flow, no "request audit" system, 6.5K LOC monolith. |
| **Nova Proximity** | Python | 286 | Connects to **live running MCP servers** (not repos). NOVA rule engine with LLM evaluation. Also scans Agent Skills (SKILL.md). |
| **MCP Shield** | TypeScript | small | 5 regex-based detection categories on tool descriptions. Optional Claude API for deeper analysis. Clean code but narrow scope. |
| **mcpserver-audit** (CSA) | Markdown | 10 | Not a tool -- a prompt-driven methodology + semgrep rules. AIVSS scoring framework. |

### Key Architectural Decision: What To Borrow

1. **Client config paths** -- from Smithery `clients.ts` and MCPM `managers/`. This is the hardest part and it's already solved.
2. **Config format translation** -- from Smithery `client-config-io.ts`. The abstraction layer (internal format -> client-specific format) is exactly what we need.
3. **Quick scan regex patterns** -- from AgentAudit `cli.mjs` (11 patterns) and MCP Shield `tool-analyzer.ts` (5 categories).
4. **Tool poisoning detection** -- from AgentAudit `tool-poisoning-detector.mjs` (8 categories, 913 LOC).

---

## Our Database (PostgreSQL @ localhost:5432/runthedev)

### Tables

| Table | Rows | Description |
|---|---|---|
| `merged_servers` | 22,446 | Deduplicated MCP servers from 3 sources |
| `merged_skills` | 269,869 | Deduplicated agent skills |
| `raw_servers` | 24,263 | Raw data (glama: 17.8K, smithery: 3.6K, registry: 2.8K) |
| `raw_skills` | - | Raw skill data |
| `audit_runs` | 1 (pending) | Audit results storage |

### merged_servers schema

```sql
id               SERIAL PRIMARY KEY
dedup_key        VARCHAR(500) UNIQUE NOT NULL  -- "owner/repo" format
github_owner     VARCHAR(255)
github_repo      VARCHAR(255)
github_url       VARCHAR(1000)
name             VARCHAR(500) NOT NULL
description      TEXT NOT NULL
tools            JSONB       -- array of tool definitions
resources        JSONB
prompts          JSONB
connections      JSONB       -- install info from Smithery: [{type: "stdio"|"http", configSchema, deploymentUrl, bundleUrl}]
security_grade   VARCHAR(5)  -- "a", "b", "c", "d", "f" (from Glama, 6,974 servers have this)
quality_grade    VARCHAR(5)
license_grade    VARCHAR(5)
license          VARCHAR(200)
categories       JSONB       -- array of category strings
language         VARCHAR(100)
stars            INTEGER NOT NULL
forks            INTEGER NOT NULL
weekly_downloads INTEGER
source_ids       JSONB NOT NULL  -- {"glama": "...", "smithery": "...", "registry": "..."}
source_count     INTEGER NOT NULL
created_at       TIMESTAMPTZ
updated_at       TIMESTAMPTZ
```

### merged_skills schema

```sql
id               SERIAL PRIMARY KEY
dedup_key        VARCHAR(500) UNIQUE NOT NULL
skill_name       VARCHAR
name             VARCHAR
description      TEXT NOT NULL
github_owner     VARCHAR(255)
github_repo      VARCHAR(255)
github_url       VARCHAR(1000)
categories       JSONB
quality_score    FLOAT8
audit_summary    JSONB
skill_md_content TEXT
security_audits  JSONB
stars            INTEGER
forks            INTEGER
installs         INTEGER
weekly_installs  INTEGER
activations      INTEGER
unique_users     INTEGER
upvotes          INTEGER
downvotes        INTEGER
source_ids       JSONB NOT NULL
source_count     INTEGER NOT NULL
created_at       TIMESTAMPTZ
updated_at       TIMESTAMPTZ
```

### audit_runs schema

```sql
id              SERIAL PRIMARY KEY
item_type       VARCHAR(10) NOT NULL  -- 'server' or 'skill'
item_dedup_key  VARCHAR(500) NOT NULL -- matches dedup_key in merged_*
status          VARCHAR(20) NOT NULL  -- 'pending', 'running', 'completed', 'failed'
result          JSONB                 -- full audit report when completed
score           FLOAT8                -- 0-100
grade           VARCHAR(5)            -- A/B/C/D/F
requested_by    VARCHAR(100)          -- 'admin', 'cron', 'cli'
created_at      TIMESTAMPTZ
completed_at    TIMESTAMPTZ
```

### Data Coverage

- **6,974 servers** (31%) have `security_grade` from Glama
- **1,937 servers** (8.6%) have `connections` (install info) from Smithery
  - 1,551 = HTTP (remote)
  - 386 = stdio (local)
- **1,700 servers** have `tools` data
- **0 completed audits** in `audit_runs` (only 1 pending)

### connections JSONB structure (from Smithery)

```json
// stdio example:
[{
  "type": "stdio",
  "runtime": "node",
  "bundleUrl": "https://backend.smithery.ai/storage/.../server.mcpb",
  "configSchema": {
    "type": "object",
    "required": ["apiKey"],
    "properties": {
      "apiKey": { "type": "string", "description": "Your API key" }
    }
  }
}]

// http example:
[{
  "type": "http",
  "configSchema": { ... },
  "deploymentUrl": "https://servername--owner.run.tools"
}]
```

### Existing API Endpoints (backend-service, Axum, Rust)

```
GET  /api/servers                    -- list/search servers (Meilisearch + PG)
GET  /api/servers/:dedup_key         -- server detail with audit brief
GET  /api/servers/categories         -- category counts
GET  /api/skills                     -- list/search skills
GET  /api/skills/:dedup_key          -- skill detail with audit brief
GET  /api/skills/categories          -- category counts
GET  /api/search?q=                  -- unified search
GET  /api/stats                      -- total counts

POST /api/admin/audit                -- trigger audit (admin key required)
GET  /api/admin/audits               -- list audit runs
POST /api/admin/sync-search          -- trigger Meilisearch sync
```

---

## Architecture

### CLI (Rust binary: `rtd`)

```
cli/
├── Cargo.toml
├── src/
│   ├── main.rs                  # clap CLI: subcommands, arg parsing
│   ├── api/
│   │   ├── mod.rs
│   │   └── client.rs            # reqwest HTTP client to backend API
│   ├── clients/
│   │   ├── mod.rs               # ClientConfig trait + registry
│   │   ├── claude_code.rs       # ~/.claude.json (JSON, mcpServers)
│   │   ├── codex.rs             # ~/.codex/config.toml (TOML, mcp_servers)
│   │   ├── opencode.rs          # ~/.opencode/opencode.jsonc (JSONC, mcp)
│   │   ├── cursor.rs            # ~/.cursor/mcp.json (JSON, mcpServers)
│   │   ├── vscode.rs            # ~/.vscode/mcp.json or settings.json (JSON, servers)
│   │   ├── windsurf.rs          # ~/.codeium/windsurf/mcp_config.json (JSON, mcpServers, url->serverUrl)
│   │   ├── claude_desktop.rs    # ~/Library/Application Support/Claude/claude_desktop_config.json
│   │   └── goose.rs             # ~/.config/goose/config.yaml (YAML, extensions, cmd/envs)
│   ├── config/
│   │   ├── mod.rs
│   │   ├── json.rs              # JSON/JSONC read/write with serde_json
│   │   ├── toml.rs              # TOML read/write
│   │   └── yaml.rs              # YAML read/write
│   ├── install/
│   │   ├── mod.rs
│   │   ├── transport.rs         # Resolve stdio vs http install method
│   │   └── writer.rs            # Write server config to client config file
│   └── ui/
│       ├── mod.rs
│       └── display.rs           # console + dialoguer + indicatif output
```

### Key Trait

```rust
pub trait ClientConfig {
    fn id(&self) -> &str;                          // "claude-code", "codex", etc.
    fn display_name(&self) -> &str;                // "Claude Code"
    fn config_path(&self) -> Option<PathBuf>;      // platform-specific
    fn is_installed(&self) -> bool;                 // config dir/binary exists
    fn capabilities(&self) -> ClientCapabilities;  // supports_stdio, supports_http

    fn read_servers(&self) -> Result<HashMap<String, serde_json::Value>>;
    fn add_server(&self, name: &str, config: ServerConfig) -> Result<()>;
    fn remove_server(&self, name: &str) -> Result<()>;
}

pub struct ClientCapabilities {
    pub supports_stdio: bool,
    pub supports_http: bool,
    pub supports_oauth: bool,
    pub needs_proxy_for_remote: bool,  // Claude Desktop = true
}

pub enum ServerConfig {
    Stdio {
        command: String,
        args: Vec<String>,
        env: HashMap<String, String>,
    },
    Http {
        url: String,
        headers: Option<HashMap<String, String>>,
    },
}
```

### Client Config Paths (all platforms)

| Client | macOS | Linux | Windows | Format | Server Key |
|---|---|---|---|---|---|
| Claude Code | `~/.claude.json` | `~/.claude.json` | `~/.claude.json` | JSON | `mcpServers` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%/Claude/claude_desktop_config.json` | JSON | `mcpServers` |
| Codex | `~/.codex/config.toml` | `~/.codex/config.toml` | `~/.codex/config.toml` | TOML | `mcp_servers` |
| OpenCode | `~/.opencode/opencode.jsonc` | `~/.opencode/opencode.jsonc` | `~/.opencode/opencode.jsonc` | JSONC | `mcp` (type: local/remote) |
| Cursor | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | JSON | `mcpServers` |
| VS Code | `~/.vscode/mcp.json` | `~/.vscode/mcp.json` | `~/.vscode/mcp.json` | JSON | `servers` (with `type` field) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | same | same | JSON | `mcpServers` (url -> `serverUrl`) |
| Goose | `~/.config/goose/config.yaml` | same | same | YAML | `extensions` (command->`cmd`, env->`envs`) |

### Skill install targets (current CLI behavior)

When `rtd <identifier>` resolves to a **skill**, CLI now installs a generated `SKILL.md` to client skill directories:

| Client | macOS path | Linux path |
|---|---|---|
| Claude Code | `~/.claude/skills/<skill-name>/SKILL.md` | `~/.claude/skills/<skill-name>/SKILL.md` |
| Codex | `~/.agents/skills/<skill-name>/SKILL.md` | `~/.agents/skills/<skill-name>/SKILL.md` |
| OpenCode | `~/.config/opencode/skills/<skill-name>/SKILL.md` | `~/.config/opencode/skills/<skill-name>/SKILL.md` |

Notes:
- Skill content is sourced from backend `GET /api/skills/:dedup_key` (`skill_md_content`) with generated frontmatter (`name`, `description`) for compatibility.
- MCP server installation remains config-driven (`~/.claude.json`, `~/.codex/config.toml`, `~/.opencode/opencode.jsonc`, etc.); CLI writes client config entries and does not execute package installers during setup.

### Transport Resolution

When installing a server, CLI must determine which install method to offer:

```
1. Server has connections data in DB?
   -> connections[].type == "stdio" -> offer local install
   -> connections[].type == "http"  -> offer remote install
   -> both exist                    -> let user choose

2. No connections in DB, but has github_url?
   -> CLI can offer: "We don't have install info. Enter manually or detect from repo."
   -> Future: auto-detect from package.json/pyproject.toml via GitHub API

3. Client supports this transport?
   -> Check ClientCapabilities
   -> Claude Desktop: stdio only (needs mcp-remote proxy for http)
   -> Most others: both stdio and http
```

---

## Backend Changes Needed

### New table: audit_requests

```sql
CREATE TABLE audit_requests (
    id SERIAL PRIMARY KEY,
    item_type VARCHAR(10) NOT NULL CHECK (item_type IN ('server', 'skill')),
    item_dedup_key VARCHAR(500) NOT NULL,
    source VARCHAR(50) NOT NULL DEFAULT 'cli',  -- 'cli', 'web'
    cli_version VARCHAR(20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_requests_item ON audit_requests (item_type, item_dedup_key);
```

### New API endpoints for CLI

```
# Check if we have info on a server/skill
# Returns: item info + audit data + connections + request count
GET /api/cli/check?slug=<dedup_key>&type=<server|skill>

Response:
{
  "found": true,
  "item": {
    "name": "...",
    "description": "...",
    "github_url": "...",
    "security_grade": "a",
    "quality_grade": "a",
    "stars": 1234,
    "language": "typescript"
  },
  "audit": {                    // null if no audit
    "grade": "A",
    "score": 92.3,
    "result": { ... }           // full findings
  },
  "connections": [ ... ],       // install methods, null if none
  "audit_request_count": 7      // how many CLI users have requested audit
}

# Record that a user wanted audit for this item
POST /api/cli/request-audit
Body: { "slug": "owner/repo", "type": "server", "cli_version": "0.1.0" }

Response:
{
  "request_count": 8,
  "auto_audit_triggered": false,  // true when count >= 10
  "message": "Request recorded. 8/10 before auto-audit."
}

# (Optional) Record that a user installed via CLI
POST /api/cli/install-event
Body: { "slug": "owner/repo", "type": "server", "client": "claude-code", "method": "stdio" }
```

---

## CLI Commands

```
rtd check <identifier>         # Main command: check audit + offer install
rtd search <query>             # Search our DB for servers/skills
rtd install <identifier>       # Direct install (skip audit display)
rtd list                       # List installed MCP servers across all detected clients
rtd remove <name> [--client]   # Remove a server from client config
rtd clients                    # Show detected coding tools and their config paths
rtd version                    # Version info
```

### Identifier formats

```
rtd check owner/repo                    # GitHub owner/repo (matches dedup_key)
rtd check github.com/owner/repo         # Full GitHub URL
rtd check https://github.com/owner/repo # Full URL with protocol
rtd check npm:@scope/package            # npm package (future)
rtd check pypi:package-name             # PyPI package (future)
```

---

## Dependencies (Cargo.toml)

```toml
[package]
name = "rtd"
version = "0.1.0"
edition = "2024"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
serde_yaml = "0.9"
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
tokio = { version = "1", features = ["full"] }
dialoguer = { version = "0.11", features = ["fuzzy-select"] }
console = "0.15"
indicatif = "0.17"
dirs = "6"
anyhow = "1"
```

---

## Implementation Order

### Phase 1: Core check flow (MVP)
1. CLI skeleton with clap (main.rs, subcommands)
2. API client -- GET /api/cli/check, POST /api/cli/request-audit
3. Backend: new endpoints + audit_requests table + migration
4. UI: display audit results, grades, warnings
5. Interactive prompts: "install? where?"

### Phase 2: Client config writers
6. ClientConfig trait + registry of clients
7. JSON writer (Claude Code, Cursor, Claude Desktop, Windsurf)
8. TOML writer (Codex)
9. JSONC writer (OpenCode)
10. YAML writer (Goose)
11. Transport resolution (stdio vs http, per-client capabilities)

### Phase 3: Polish
12. `rtd search` -- call existing /api/servers + /api/skills endpoints
13. `rtd list` -- scan all client configs, show installed servers
14. `rtd clients` -- show detected clients
15. `rtd remove` -- remove server from config
16. Error handling, edge cases, platform testing

### Phase 4: Distribution
17. GitHub Actions CI: build for macOS (arm64, x86), Linux, Windows
18. Homebrew formula
19. `cargo install rtd`
20. Shell installer: `curl -sSL https://rtd.runthedev.com/install | sh`
