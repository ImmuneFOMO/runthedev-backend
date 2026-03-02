# Rule Matrix

Compact matrix of the deterministic rules currently implemented in `app/rules.py`.

| rule_id | Trigger Summary | Default Severity | Default Confidence | Key False-Positive Protections |
| --- | --- | --- | --- | --- |
| `remote-mutable-source` | Authoritative markdown/instruction links on mutable `main`/`master` branches | `high` | `0.9` | Requires authoritative link text/path hints such as `SKILL.md`, `README.md`, `guide`, `instructions` |
| `ssrf-language` | User-controlled or arbitrary URL fetching language | `medium` / `high` | `0.9` | Suppressed when allowlist / sandbox / auth guardrails are mentioned anywhere |
| `prompt-override-language` | Instruction-tampering phrases like “ignore previous instructions” or “override system” | `medium` / `high` | `0.8` | Requires instruction-like context such as `agent must`, `you are`, `system:`, `instructions:` |
| `stealth-or-nondisclosure` | “Do not tell the user”, “secretly”, “silently”, “without user knowing” | `medium` / `high` | `0.7` | Requires nearby action verbs like `fetch`, `read`, `send`, `upload`, `run`; ignores UI/debug wording |
| `data-exfiltration-instructions` | Instructions to dump env or send sensitive data like `.env`, `~/.ssh`, tokens, keys | `high` / `critical` | `0.9` | Requires imperative verb plus sensitive target tokens |
| `unsafe-file-patterns` | Broad repo globs or sensitive paths like `**/*`, `.git`, `/etc`, `~/.ssh` | `medium` / `high` | `0.8` | Requires nearby file-operation context such as `read`, `files`, `glob`, `load`, `scan` |
| `dangerous-allowlist-absence` | Sensitive filesystem access examples with no allowlist/denylist guidance | `high` | `0.6` | Only fires when filesystem capability is present and sensitive path examples are shown |
| `private-ip-ssrf-mitigation-missing` | Arbitrary URL fetch guidance without localhost / private-IP / metadata blocking | `high` | `0.6` | Only fires on explicit user-controlled URL language; suppressed if mitigation terms are present |
| `redirect-following-risk` | Redirect following enabled without destination restrictions | `medium` | `0.7` | Suppressed if allowlist/private-IP blocking language is present |
| `public-exposure` | `0.0.0.0`, `--host 0.0.0.0`, or public endpoint guidance | `medium` / `high` | `0.9` | Auth mentions reduce the wording but do not suppress the finding |
| `likely-live-secret` | Real-looking credentials or high-entropy secret values | `high` | `0.6` | Rejects URLs/images/JSON paths, link URLs, short values, readable slugs, fake test keys |
| `secret-placeholder` | Fake or placeholder secret values in real secret contexts | `low` | `0.6` / `0.9` | Requires env/config-style context; suppresses ordinary testing payloads and helper schema examples |
| `env-file-guidance` | `.env`, `.env.local`, `dotenv`, or environment-file guidance | `low` | `0.9` | Fires only on env guidance patterns |
| `remote-install-manifest` | Install/load/add directly from remote URLs or mutable branches | `medium` / `high` | `0.9` | Severity rises for mutable branches and remote script execution patterns |
| `unpinned-dependency-install` | `npm install`, `pip install`, `go get`, or `@latest` without version pinning | `medium` | `0.8` | Ignores pinned installs like `@1.2.0`, `==1.2.3`, `@v1.2.3` |
| `curl-pipe-shell` | Remote content piped into `bash`, `sh`, PowerShell, or expression evaluators | `critical` / `high` | `0.95` | Requires explicit shell/evaluator piping or `IEX` / `Invoke-Expression` patterns |
| `git-clone-main-then-run` | `git clone` followed by `./install.sh`, `setup.sh`, or `make install` | `high` | `0.85` | Requires clone and execution in same code block or within 20 lines |
| `api-proxy-route-with-key` | Proxy/API route guidance combined with env key usage | `medium` | `0.9` | Requires both route-like and env-key-like patterns |
| `webhook-signature-missing` | Webhook/callback endpoint guidance with no signature/HMAC verification | `medium` / `high` | `0.6` | Suppressed if `signature`, `HMAC`, `verify`, or `secret` is mentioned |
| `oauth-scope-overreach` | Broad OAuth or permission scopes such as `admin`, `repo`, `full access` | `medium` | `0.7` | Requires scope-related context, not just broad words alone |
| `no-auth-mentioned-for-network-service` | Exposed service/endpoint/port with no auth guidance anywhere | `medium` | `0.6` | Fires only when network service language exists and auth terms are absent |
| `sensitive-logging` | Verbose/request/header logging in contexts that also mention secrets or tokens | `medium` | `0.7` | Requires both logging language and secret/token context |
| `sandbox-disable-instructions` | `--privileged`, `disable sandbox`, `run as root`, `chmod 777`, `setenforce 0` | `high` | `0.9` | Direct pattern match only |
| `docker-privileged-host-mount` | Docker privileged mode, `-v /:/host`, or Docker socket mount | `critical` | `0.95` | Requires Docker command context |
| `approval-claims-without-mechanism` | “Requires approval” / “human-in-the-loop” with no configuration mechanism | `medium` | `0.6` | Suppressed if approval mode/config/how-to-enable language exists |
| `file-upload-capability` | File upload handling or upload examples | `low` | `0.5` | Suppressed in testing-only docs for noisy Playwright/example cases |
| `client-side-tools-capability` | Client-side/browser tool execution | `low` | `0.5` | Requires explicit client-side tooling language |
| `capability-shell` | Shell or explicit command execution capability | `low` | `0.5` | Requires explicit shell/exec/subprocess wording, not generic tool states |
| `capability-filesystem` | Filesystem read/write capability | `low` | `0.5` | Requires explicit filesystem wording |
| `capability-network` | Network fetching or external HTTP request capability | `low` | `0.5` | Suppressed in testing-only docs to avoid request-example noise |
| `capability-browser` | Generic browser interaction capability | `low` | `0.5` | Suppressed in testing-only docs |
| `capability-browser-automation` | Playwright/Selenium/Puppeteer/browser automation | `low` | `0.5` | Suppressed in testing-only docs |
| `capability-proxy` | Proxy or API mediation capability | `low` | `0.5` | Requires route/proxy language |
| `capability-file-upload` | Upload/input-file capability | `low` | `0.5` | Suppressed in testing-only docs |
| `capability-client-side-tools` | Browser-side tool execution capability | `low` | `0.5` | Requires explicit client-side tool wording |
| `capability-docker` | Docker/container runtime capability | `low` | `0.5` | Requires Docker/container command context |
| `capability-git` | Git repository manipulation capability | `low` | `0.5` | Requires clone/push/pull/checkout/repository operation wording |
| `capability-k8s` | Kubernetes/cluster administration capability | `low` | `0.5` | Requires `kubectl`, `kubernetes`, `helm`, or `cluster role` wording |
| `capability-email` | Email sending/delivery capability | `low` | `0.5` | Requires mail provider or outbound email wording |
| `capability-payment` | Billing/payment/checkout/subscription capability | `low` | `0.5` | Requires explicit payment-domain wording |
| `capability-clipboard` | Clipboard access capability | `low` | `0.5` | Requires clipboard/copy/paste wording |
| `capability-notifications` | Notification/alert capability | `low` | `0.5` | Requires notification wording |
| `missing-guardrails-shell` | Shell capability with no allowlist/sandbox/auth guidance | `high` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-filesystem` | Filesystem capability with no allowlist/sandbox/auth guidance | `high` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-network` | Network capability with no allowlist/sandbox/auth guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-browser` | Browser capability with no allowlist/sandbox/auth guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-browser-automation` | Browser automation with no allowlist/sandbox/auth guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-proxy` | Proxy capability with no allowlist/sandbox/auth guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-file-upload` | Upload capability with no allowlist/sandbox/auth guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-client-side-tools` | Client-side tools with no allowlist/sandbox/auth guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-docker` | Docker capability with no guardrails or privilege limits | `high` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-git` | Git capability with no trust or scope guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-k8s` | Kubernetes capability with no RBAC/approval/guardrail guidance | `high` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-email` | Email capability with no auth/scope/approval guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-payment` | Payment capability with no auth/approval/guardrail guidance | `high` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-clipboard` | Clipboard access with no scope/approval guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `missing-guardrails-notifications` | Notification capability with no scope/auth guidance | `medium` | `0.5` | Suppressed if guardrail terms are present anywhere |
| `prompt-injection-corpus` | Adversarial prompt patterns / jailbreak corpus detected | `medium` / `high` | `0.7` | Requires 2+ injection marker matches and corpus signal (large doc, README, or corpus marker) |
