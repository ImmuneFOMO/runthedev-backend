from __future__ import annotations

import re


CODE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml"}
SOURCE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml"}
IGNORED_DIRS = {"node_modules", "dist", "build", ".next", ".git", "coverage", "__pycache__"}
NOISE_DIRS = {"docs", "docs-site", ".astro", "_astro", "storybook", "website", ".react-router"}
NOISE_FILE_HINT_RE = re.compile(r"\b(min\.js|bundle\.js|chunk\.[a-z0-9]+\.js|client\.[a-z0-9]+\.js)\b", re.IGNORECASE)
TEST_HINT_RE = re.compile(r"(^|/)(test|tests|__tests__|spec|specs|fixtures)(/|$)|(?:^|[._-])(test|spec)(?:[._-]|$)", re.IGNORECASE)
ENTRYPOINT_HINT_RE = re.compile(r"(main|app|server|index|cli|mcp|tool|tools|routes|api|webhook|auth)\.", re.IGNORECASE)
PRIORITY_SEGMENT_RE = re.compile(r"(^|/)(mcp|server|tool|tools|routes|api|webhook|auth)(/|$)", re.IGNORECASE)
MCP_CONFIG_RE = re.compile(r"(^|/)(\.mcp\.json|mcp\.json|claude\.json|context7\.json)$", re.IGNORECASE)
MCP_REPO_HINT_RE = re.compile(r"(^|/)(mcp|transport|session|server|tools?|resources?|sampling|context|program)(/|\.|$)", re.IGNORECASE)
MCP_CONTEXT_PATH_RE = re.compile(r"(^|/)(mcp|transport|session|resources?|sampling|context)(/|\.|$)", re.IGNORECASE)
SCRIPT_HINT_RE = re.compile(r"(^|/)(scripts?)(/|$)", re.IGNORECASE)
TEMPLATE_HINT_RE = re.compile(r"(^|/)(assets?|templates?)(/|$)|template", re.IGNORECASE)
CI_PATH_RE = re.compile(r"^\.github/(workflows|actions)/", re.IGNORECASE)
WORKFLOW_YAML_RE = re.compile(r"(^|/)\.github/workflows/.+\.(yaml|yml)$", re.IGNORECASE)

SERVER_CONTEXT_RE = re.compile(
    r"(@app\.(?:get|post|put|delete|patch)|@router\.(?:get|post|put|delete|patch)|@bp\.(?:get|post|put|delete|patch)|app\.(?:get|post|put|delete|patch)\s*\(|router\.(?:get|post|put|delete|patch)\s*\(|FastAPI\s*\(|Flask\s*\(|express\s*\(|Express\s*\(|fastify\s*\(|app\.listen\s*\(|listen\s*\()",
    re.IGNORECASE,
)
MCP_CONTEXT_RE = re.compile(
    r"\bmcp\b|Model Context Protocol|server\.registerTool|registerTool|registerResource|resources?\b|sampling\b|transport\b|session\b|StdioServerTransport|StreamableHTTPServerTransport|tool registry|tool definition",
    re.IGNORECASE,
)
CLI_CONTEXT_RE = re.compile(
    r"argparse|sys\.argv|click\.(?:argument|option|command)|typer\.|ArgumentParser|process\.argv|commander|yargs|if __name__ == ['\"]__main__['\"]|def main\s*\(",
    re.IGNORECASE,
)
CI_CONTEXT_RE = re.compile(r"\bruns-on:\b|\bsteps:\b|\buses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@", re.IGNORECASE)

SHELL_EXEC_RE = re.compile(
    r"(subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system\s*\(|exec\s*\(|eval\s*\(|child_process\.(?:exec|execSync|spawn|spawnSync)|spawn\s*\()"
)
SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True|shell:\s*true", re.IGNORECASE)
REQUEST_CALL_RE = re.compile(
    r"(requests\.(?:get|post|request)|httpx\.(?:get|post|request)|axios\.(?:get|post|request)|fetch\s*\(|urllib\.request\.urlopen\s*\()"
)
ROUTE_RE = re.compile(
    r"(@app\.(?:get|post|put|delete|patch)|@(router|bp)\.(?:get|post|put|delete|patch)|app\.(?:get|post|put|delete|patch)\s*\(|router\.(?:get|post|put|delete|patch)\s*\(|FastAPI\s*\(|Express\s*\(|express\s*\()"
)
WEBHOOK_RE = re.compile(r"\bwebhook\b|/webhook\b|x-hub-signature|x-signature|webhook_secret", re.IGNORECASE)
WEBHOOK_ROUTE_RE = re.compile(r"/webhook\b|/hooks?\b|/events?\b|@app\.(?:post|get)\(\s*[\"'][^\"']*webhook", re.IGNORECASE)
CALLBACK_URL_RE = re.compile(r"callback\s*(?:url|endpoint)", re.IGNORECASE)
VERIFY_RE = re.compile(r"signature|hmac|verify|webhook_secret|x-signature|x-hub-signature", re.IGNORECASE)
AUTH_RE = re.compile(r"Depends\s*\(|OAuth|JWT|Bearer|APIKey|api[_-]?key|authorization|authenticate|auth\b|require_auth|verify_token", re.IGNORECASE)
OPEN_PROXY_RE = re.compile(r"proxy|forward|upstream|target_url|url\s*=", re.IGNORECASE)
SECRET_NAME_RE = re.compile(r"(api[_-]?key|token|secret|password|bearer)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{16,})"
)
SECRET_REFERENCE_RE = re.compile(
    r"(\$\{[A-Za-z0-9_]+\}|secrets\.[A-Za-z0-9_]+|process\.env\.[A-Za-z0-9_]+|\$\{\{\s*secrets\.[^}]+\}\}|\"?\$[A-Za-z0-9_]+\"?)",
    re.IGNORECASE,
)
SAFE_SECRET_PLACEHOLDER_RE = re.compile(r"(example|test|dummy|placeholder|changeme|your_|xxx|\.\.\.)", re.IGNORECASE)
DOCKER_DANGER_RE = re.compile(r"/var/run/docker\.sock|--privileged|-v\s+/:/|privileged:\s*true|docker\.sock", re.IGNORECASE)
FILE_OP_RE = re.compile(
    r"(\bopen\s*\(|\bPath\s*\(|unlink\s*\(|remove\s*\(|rmtree\s*\(|fs\.(?:readFile|writeFile|unlink|rm)|read_text\s*\(|write_text\s*\()"
)
FILE_READ_RE = re.compile(
    r"(\bopen\s*\([^)]*(?:['\"]r[b]?['\"])?\)|read_text\s*\(|read_bytes\s*\(|fs\.readFile(?:Sync)?\s*\(|Path\s*\([^)]*\)\.read_text\s*\(|Path\s*\([^)]*\)\.read_bytes\s*\()",
    re.IGNORECASE,
)
FILE_WRITE_RE = re.compile(
    r"(\bopen\s*\([^)]*,\s*['\"](?:w|wb|a|ab|x|xb)['\"]|write_text\s*\(|write_bytes\s*\(|fs\.writeFile(?:Sync)?\s*\(|appendFile(?:Sync)?\s*\()",
    re.IGNORECASE,
)
FILE_DELETE_RE = re.compile(
    r"(unlink\s*\(|Path\([^)]*\)\.unlink\s*\(|os\.remove\s*\(|remove\s*\(|shutil\.rmtree\s*\(|rmtree\s*\(|fs\.(?:rm|unlink)(?:Sync)?\s*\()",
    re.IGNORECASE,
)
SENSITIVE_PATH_RE = re.compile(r"/etc|~/.ssh|\.git\b")
USER_INPUT_RE = re.compile(
    r"(request\.(?:json|body|query_params|path_params|headers)|Request\b|input\b|user_input|userInput|args\b|argv\b|sys\.argv|payload\b|params\b|query\b|url\b|path\b|form\b|tool_args|tool_input|message\.content|model_output|llm_output|completion)"
)
EXTERNAL_PATH_TAINT_RE = re.compile(
    r"(request\.(?:json|body|query_params|path_params|headers)|req\.(?:body|query|params)|Request\b|payload\b|params\.get|query\b|body\b|form\b|ctx\.arguments|tool_(?:args|input)|@tool\b|\btool\s*\()",
    re.IGNORECASE,
)
SCHEMA_PATH_HINT_RE = re.compile(r"(filename|file_path|filepath|path)\s*[:=]\s*[{(]|\b(required|type)\b.*\b(path|filename)\b", re.IGNORECASE)
ALLOWLIST_RE = re.compile(r"allowlist|whitelist|trusted_hosts|trusted_domains|private ip|rfc1918|127\.0\.0\.1|169\.254\.169\.254|localhost", re.IGNORECASE)
APPROVAL_RE = re.compile(r"approve|approval|allowlist|permit|authorize|authz", re.IGNORECASE)
SAFE_REPO_PATH_RE = re.compile(
    r"import\.meta\.url|__dirname|__filename|fileURLToPath\s*\(|path\.(?:join|resolve)\s*\(\s*(?:__dirname|__filename)|new URL\s*\(\s*['\"][^'\"]+['\"],\s*import\.meta\.url\)",
    re.IGNORECASE,
)
PACKAGE_METADATA_RE = re.compile(r"package\.json|tsconfig\.json|pyproject\.toml|packageJSON", re.IGNORECASE)
COMMAND_EXEC_STRONG_RE = re.compile(
    r"(subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system\s*\(|child_process\.(?:exec|execSync|spawn|spawnSync)|spawn\s*\()"
)
CLI_INPUT_RE = re.compile(r"argparse|sys\.argv|click\.argument|click\.option|ArgumentParser|process\.argv|commander", re.IGNORECASE)
PATH_BUILD_RE = re.compile(r"(path\.(?:join|resolve|normalize)\s*\(|os\.path\.(?:join|abspath|realpath|normpath)\s*\(|Path\s*\(|resolve\s*\()", re.IGNORECASE)
PATH_TRAVERSAL_LITERAL_RE = re.compile(r"\.\./|\.\.\\\\|['\"]\.\.['\"]")
MODULE_IMPORT_RE = re.compile(
    r"^\s*(?:import\s+(?:type\s+)?(?:.+?\s+from\s+)?['\"][^'\"]+['\"]|export\s+.+?\s+from\s+['\"][^'\"]+['\"]|type\s+\w+\s*=\s*typeof\s+import\(\s*['\"][^'\"]+['\"]\s*\)|(?:const|let|var)\s+\w+\s*=\s*require\(\s*['\"][^'\"]+['\"]\s*\))",
    re.IGNORECASE,
)
MODULE_IMPORT_CONTINUATION_RE = re.compile(r"^\s*}\s*from\s+['\"][^'\"]+['\"];?\s*$", re.IGNORECASE)
PATH_MITIGATION_RE = re.compile(
    r"(is_relative_to\s*\(|relative_to\s*\(|commonpath\s*\(|startswith\s*\(\s*str?\(?base|is_absolute\s*\(|reject absolute|allowlist of extensions|suffix(?:es)?\s+allowlist|endswith\s*\()",
    re.IGNORECASE,
)
FIXED_BASE_RE = re.compile(r"(base_dir|basedir|root_dir|rootdir|workspace|sandbox|allowed_dir|safe_dir)", re.IGNORECASE)
