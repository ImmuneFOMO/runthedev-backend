from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import re

from app.models import CodeEvidence, CodeFinding, FileOpType

from .models import CodeAnalysisResult, ScannedCodeFile
from .patterns import (
    ALLOWLIST_RE,
    APPROVAL_RE,
    AUTH_RE,
    CALLBACK_URL_RE,
    CLI_INPUT_RE,
    COMMAND_EXEC_STRONG_RE,
    DOCKER_DANGER_RE,
    EXTERNAL_PATH_TAINT_RE,
    FILE_DELETE_RE,
    FILE_OP_RE,
    FILE_READ_RE,
    FILE_WRITE_RE,
    FIXED_BASE_RE,
    OPEN_PROXY_RE,
    PACKAGE_METADATA_RE,
    PATH_BUILD_RE,
    PATH_MITIGATION_RE,
    PATH_TRAVERSAL_LITERAL_RE,
    MODULE_IMPORT_CONTINUATION_RE,
    MODULE_IMPORT_RE,
    REQUEST_CALL_RE,
    ROUTE_RE,
    SAFE_SECRET_PLACEHOLDER_RE,
    SAFE_REPO_PATH_RE,
    SCHEMA_PATH_HINT_RE,
    SECRET_NAME_RE,
    SECRET_REFERENCE_RE,
    SECRET_VALUE_RE,
    SENSITIVE_PATH_RE,
    SHELL_EXEC_RE,
    SHELL_TRUE_RE,
    USER_INPUT_RE,
    VERIFY_RE,
    WEBHOOK_RE,
    WEBHOOK_ROUTE_RE,
)


FILE_ACCESS_RULES = {
    "arbitrary-file-read",
    "arbitrary-file-write",
    "arbitrary-file-delete",
}

SCRIPT_PATH_RE = re.compile(r"(^|/)(?:scripts|tools)/|^\.github/", re.IGNORECASE)
TEMP_OUTPUT_RE = re.compile(r"/tmp\b|\btmp\b|\.cache\b|\bdist\b|\bbuild\b|tempfile|gettempdir|mkdtemp", re.IGNORECASE)
LOCKFILE_PATH_RE = re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|actions-lock\.json)$", re.IGNORECASE)
BUILD_CONFIG_PATH_RE = re.compile(r"(^|/)(vite\.config|webpack\.config|rollup\.config|next\.config|tsconfig|eslint|prettier)(\.[^/]+)?$", re.IGNORECASE)
MCP_TRANSPORT_MARKER_RE = re.compile(r"serveSSE|transport|StreamableHTTP|ServerSentEvents|MCPServer|FastMCP|@mcp\.tool|mcp\.tool", re.IGNORECASE)
FASTAPI_MARKER_RE = re.compile(r"FastAPI\s*\(", re.IGNORECASE)
FLASK_MARKER_RE = re.compile(r"Flask\s*\(__name__\)", re.IGNORECASE)
EXPRESS_MARKER_RE = re.compile(r"\bexpress\s*\(", re.IGNORECASE)
FASTIFY_MARKER_RE = re.compile(r"\bfastify\s*\(", re.IGNORECASE)
KOA_MARKER_RE = re.compile(r"\bnew\s+Koa\s*\(|\bkoa\s*\(", re.IGNORECASE)
NODE_HTTP_MARKER_RE = re.compile(r"http\.createServer\s*\(|createServer\s*\(", re.IGNORECASE)
SERVER_START_MARKER_RE = re.compile(r"uvicorn\.run\s*\(|app\.listen\s*\(|serve\s*\(|0\.0\.0\.0", re.IGNORECASE)
PORT_RE = re.compile(r"\b(?:(?:port|PORT)\s*[:=]\s*|listen\s*\()([0-9]{2,5})")
ROUTE_PREFIX_RE = re.compile(r"['\"](/[^'\"\s)]*)['\"]")
ROUTE_HANDLER_LINE_RE = re.compile(r"^\s*@\w+\.(?:get|post|put|delete|patch|route)\s*\(|\b(?:app|router)\.(?:get|post|put|delete|patch|route)\s*\(", re.IGNORECASE)
REAL_COMMAND_EXEC_RE = re.compile(
    r"(subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(|os\.system\s*\(|child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(|(?<![A-Za-z0-9_])(?:exec|eval|spawn)\s*\()"
)
PUBLIC_ROUTE_RE = re.compile(r"/(?:openapi(?:\.json)?|postman(?:\.json)?|healthz?|status|docs|redoc|swagger)(?:/|$|['\"])", re.IGNORECASE)
FIXED_UPSTREAM_URL_RE = re.compile(
    r"(?:[A-Z][A-Z0-9_]*_URL|BASE_URL|API_URL|DATA_API_URL|SERVICE_URL|process\.env\.[A-Z0-9_]*URL)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class MatchContext:
    file: ScannedCodeFile
    line_no: int
    line: str
    window: str


def analyze_codebase(files: list[ScannedCodeFile]) -> CodeAnalysisResult:
    findings: list[CodeFinding] = []
    capabilities: set[str] = set()

    for code_file in files:
        findings.extend(_analyze_file(code_file, capabilities))

    clustered = _assign_clusters(findings)
    clustered.sort(key=lambda item: (_severity_rank(item.severity), item.evidence.file_path, item.evidence.line or 0, item.rule_id), reverse=True)
    return CodeAnalysisResult(capabilities=sorted(capabilities), findings=clustered)


def _analyze_file(code_file: ScannedCodeFile, capabilities: set[str]) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    lines = code_file.text.splitlines()

    lowered = code_file.text.lower()
    if any(term in lowered for term in ["subprocess", "child_process", "os.system", "docker", "requests.", "httpx.", "fastapi", "express"]):
        if any(term in code_file.text for term in ["subprocess", "child_process", "os.system"]):
            capabilities.add("shell")
        if any(term in code_file.text for term in ["requests.", "httpx.", "fetch(", "axios."]):
            capabilities.add("network")
        if any(term in code_file.text for term in ["open(", "Path(", "fs.readFile", "fs.writeFile", "read_text(", "write_text("]):
            capabilities.add("filesystem")
        if "docker" in lowered:
            capabilities.add("docker")

    for index, line in enumerate(lines, start=1):
        window = _window(lines, index)
        ctx = MatchContext(file=code_file, line_no=index, line=line, window=window)
        findings.extend(_command_execution(ctx))
        findings.extend(_file_access_findings(ctx))
        findings.extend(_path_traversal(ctx))
        findings.extend(_ssrf_fetch(ctx))
        findings.extend(_hardcoded_secret(ctx))
        findings.extend(_unsafe_docker_runtime(ctx))
        findings.extend(_prompt_injection_sensitive_wiring(ctx))

    findings.extend(_webhook_verification(code_file))
    findings.extend(_auth_missing_network_service(code_file))
    findings.extend(_open_proxy_endpoint(code_file))
    findings.extend(_tool_approval_missing(code_file))

    return findings


def _command_execution(ctx: MatchContext) -> list[CodeFinding]:
    if not _is_real_command_execution(ctx.line):
        return []
    user_controlled = _likely_user_controlled(ctx.window)
    shell_true = SHELL_TRUE_RE.search(ctx.window) is not None
    severity = "critical" if user_controlled and shell_true else "high"
    description = "Dangerous command execution was found in server code."
    if user_controlled:
        description = "Command execution appears to receive user-controlled or model-controlled input."
    return [
        _finding(
            severity=severity,
            rule_id="command-execution",
            title="Unsafe command execution",
            description=description,
            confidence=0.95 if user_controlled else 0.82,
            file=ctx.file,
            line_no=ctx.line_no,
            snippet=ctx.line,
            recommendation=[
                "Replace shell invocation with strict argument lists and fixed allowlisted commands.",
                "Reject untrusted command fragments instead of interpolating request or model input.",
            ],
        )
    ]


def _file_access_findings(ctx: MatchContext) -> list[CodeFinding]:
    operation = _file_operation_details(ctx.line)
    if operation is None:
        return []
    if operation[0] == "read" and _multipart_upload_file_wrapper(ctx.window):
        return []
    if _safe_repo_local_path(ctx.window):
        return []
    if ctx.file.context in {"cli", "library"} and SCRIPT_PATH_RE.search(ctx.file.path):
        if not (_has_external_path_taint(ctx.window) and not _path_mitigation_present(ctx.window)):
            return []
    if TEMP_OUTPUT_RE.search(ctx.window) and not _has_external_path_taint(ctx.window):
        return []

    op_type, sink_signature = operation
    external_taint = _has_external_path_taint(ctx.window)
    cli_taint = CLI_INPUT_RE.search(ctx.window) is not None
    dynamic_path = _has_dynamic_path_evidence(ctx.window)
    sensitive_path = SENSITIVE_PATH_RE.search(ctx.window) is not None or _absolute_path_signal(ctx.window)
    destructive = op_type == "delete" or _destructive_file_signal(ctx.window)
    traversal = _path_traversal_signal(ctx.window)

    if not (external_taint or dynamic_path or sensitive_path or destructive or traversal):
        return []
    if external_taint and _path_mitigation_present(ctx.window):
        external_taint = False

    severity, description, confidence = _file_access_severity(
        context=ctx.file.context,
        op_type=op_type,
        external_taint=external_taint,
        cli_taint=cli_taint,
        dynamic_path=dynamic_path,
        sensitive_path=sensitive_path,
        destructive=destructive,
        traversal=traversal,
    )
    if severity is None:
        return []

    rule_id, title = _file_rule_metadata(op_type)
    return [
        _finding(
            severity=severity,
            rule_id=rule_id,
            title=title,
            description=description,
            confidence=confidence,
            file=ctx.file,
            line_no=ctx.line_no,
            snippet=ctx.line,
            recommendation=[
                "Restrict file operations to a dedicated base directory and normalize paths before use.",
                "Block access to sensitive paths such as `/etc`, `~/.ssh`, and `.git`.",
            ],
            op_type=op_type,
            cluster_id=_file_access_cluster_id(rule_id, ctx.file.path, sink_signature),
        )
    ]


def _path_traversal(ctx: MatchContext) -> list[CodeFinding]:
    if _comment_or_docstring_line(ctx.line):
        return []
    if _static_module_import(ctx.line):
        return []
    if _safe_repo_local_path(ctx.window):
        return []
    if BUILD_CONFIG_PATH_RE.search(ctx.file.path) and _safe_repo_local_path(ctx.window):
        return []
    if PATH_BUILD_RE.search(ctx.line) is None and FILE_OP_RE.search(ctx.line) is None and PATH_TRAVERSAL_LITERAL_RE.search(ctx.line) is None:
        return []
    if PATH_TRAVERSAL_LITERAL_RE.search(ctx.line) and PATH_BUILD_RE.search(ctx.window) is None and FILE_OP_RE.search(ctx.window) is None:
        return []
    if not _path_traversal_line_signal(ctx.line):
        return []
    if _path_mitigation_present(ctx.window):
        return []

    tainted = _has_external_path_taint(ctx.window)
    severity = "high" if tainted and ctx.file.context in {"server", "mcp"} else "medium"
    return [
        _finding(
            severity=severity,
            rule_id="path-traversal",
            title="Path traversal risk",
            description="Path-building logic appears vulnerable to traversal or base-directory escape without a visible containment check.",
            confidence=0.9 if severity == "high" else 0.74,
            file=ctx.file,
            line_no=ctx.line_no,
            snippet=ctx.line,
            recommendation=[
                "Canonicalize the resolved path and verify it stays inside a fixed base directory.",
                "Reject absolute paths and `..` segments unless strict containment checks are enforced.",
            ],
        )
    ]


def _ssrf_fetch(ctx: MatchContext) -> list[CodeFinding]:
    if not REQUEST_CALL_RE.search(ctx.line):
        return []
    if not _likely_user_controlled(ctx.window):
        return []
    if _oauth_token_exchange_request(ctx.line, ctx.window):
        return []
    if _fixed_vendor_api_wrapper(ctx.line, ctx.window):
        return [
            _finding(
                severity="low",
                rule_id="ssrf-fetch",
                title="Potential SSRF or arbitrary URL fetch",
                description="Outbound request uses a fixed third-party host with caller-controlled parameters.",
                confidence=0.7,
                file=ctx.file,
                line_no=ctx.line_no,
                snippet=ctx.line,
                recommendation=[
                    "Keep the upstream host fixed and validate user-controlled parameters before forwarding them.",
                    "Avoid redirect-based host changes and document the trusted upstream boundary.",
                ],
            )
        ]
    if _fixed_base_upstream_with_user_params(ctx.line, ctx.window):
        return []
    severity = "critical" if _has_user_controlled_full_url(ctx.line, ctx.window) and ALLOWLIST_RE.search(ctx.window) is None else "high"
    description = "Network fetch logic appears to use a caller-controlled URL."
    if severity == "critical":
        description = "Network fetch logic appears to use a caller-controlled URL without visible allowlist or private-IP protections."
    return [
        _finding(
            severity=severity,
            rule_id="ssrf-fetch",
            title="Potential SSRF or arbitrary URL fetch",
            description=description,
            confidence=0.92,
            file=ctx.file,
            line_no=ctx.line_no,
            snippet=ctx.line,
            recommendation=[
                "Require an allowlist of trusted upstreams before making outbound requests.",
                "Reject localhost, RFC1918, and cloud metadata IP ranges.",
            ],
        )
    ]


def _open_proxy_endpoint(code_file: ScannedCodeFile) -> list[CodeFinding]:
    if code_file.context not in {"server", "mcp"}:
        return []
    findings: list[CodeFinding] = []
    lines = code_file.text.splitlines()
    for index, line in enumerate(lines, start=1):
        if ROUTE_HANDLER_LINE_RE.search(line) is None:
            continue
        window = _window(lines, index, radius=12)
        if OPEN_PROXY_RE.search(window) is None or REQUEST_CALL_RE.search(window) is None:
            continue
        if AUTH_RE.search(window):
            continue
        findings.append(
            _finding(
                severity="high",
                rule_id="open-proxy-endpoint",
                title="Open proxy endpoint behavior",
                description="An HTTP route appears to forward caller-controlled upstream requests without visible auth checks.",
                confidence=0.84,
                file=code_file,
                line_no=index,
                snippet=line,
                recommendation=[
                    "Require authentication and authorization for proxy endpoints.",
                    "Restrict upstream destinations to a small allowlist instead of forwarding arbitrary URLs.",
                ],
            )
        )
    return findings


def _hardcoded_secret(ctx: MatchContext) -> list[CodeFinding]:
    if LOCKFILE_PATH_RE.search(ctx.file.path):
        return []
    if SECRET_NAME_RE.search(ctx.line) is None:
        return []
    if SECRET_REFERENCE_RE.search(ctx.line):
        return []
    if _templated_secret_value(ctx.window):
        return []
    if re.search(r"(os\.environ\.get|os\.getenv|process\.env|env\.get)\s*\(", ctx.line):
        return []
    if SECRET_VALUE_RE.search(ctx.line) is None:
        return []
    if SAFE_SECRET_PLACEHOLDER_RE.search(ctx.line):
        return []
    confidence = 0.97 if any(prefix in ctx.line for prefix in ["ghp_", "sk_live_", "AKIA", "Bearer "]) else 0.83
    severity = "critical" if confidence >= 0.95 else "high"
    return [
        _finding(
            severity=severity,
            rule_id="hardcoded-secret",
            title="Hardcoded credential or token",
            description="A likely live secret is embedded directly in code or configuration.",
            confidence=confidence,
            file=ctx.file,
            line_no=ctx.line_no,
            snippet=ctx.line,
            recommendation=[
                "Remove the secret from source control and rotate it immediately.",
                "Load credentials from environment variables or a secret manager instead of hardcoding them.",
            ],
        )
    ]


def _webhook_verification(code_file: ScannedCodeFile) -> list[CodeFinding]:
    if code_file.language in {"json", "yaml"}:
        return []
    findings: list[CodeFinding] = []
    lines = code_file.text.splitlines()
    for index, line in enumerate(lines, start=1):
        if ROUTE_RE.search(line) is None and WEBHOOK_ROUTE_RE.search(line) is None and WEBHOOK_RE.search(line) is None:
            continue
        window = _window(lines, index, radius=12)
        if code_file.context != "server" and ROUTE_RE.search(window) is None:
            continue
        if not _looks_like_webhook_context(window):
            continue
        if not _http_handler_indicator(window):
            continue
        if VERIFY_RE.search(window):
            continue
        findings.append(
            _finding(
                severity="high",
                rule_id="missing-webhook-verification",
                title="Webhook signature verification missing",
                description="Webhook handling code is present without nearby signature or HMAC verification logic.",
                confidence=0.8,
                file=code_file,
                line_no=index,
                snippet=line,
                recommendation=[
                    "Verify webhook signatures before parsing or acting on the payload.",
                    "Reject unsigned or replayed webhook requests.",
                ],
            )
        )
    return findings


def _unsafe_docker_runtime(ctx: MatchContext) -> list[CodeFinding]:
    if DOCKER_DANGER_RE.search(ctx.line) is None:
        return []
    return [
        _finding(
            severity="critical",
            rule_id="unsafe-docker-runtime",
            title="Unsafe Docker or container runtime usage",
            description="Container configuration exposes privileged runtime access such as the Docker socket or host mounts.",
            confidence=0.96,
            file=ctx.file,
            line_no=ctx.line_no,
            snippet=ctx.line,
            recommendation=[
                "Remove privileged flags, host root mounts, and Docker socket access.",
                "Run containers with the least privileges needed and isolated volumes only.",
            ],
        )
    ]


def _tool_approval_missing(code_file: ScannedCodeFile) -> list[CodeFinding]:
    if code_file.context not in {"server", "mcp"}:
        return []
    lines = code_file.text.splitlines()
    for index, line in enumerate(lines, start=1):
        window = _window(lines, index, radius=8)
        if not _looks_remotely_triggerable(window):
            continue
        if APPROVAL_RE.search(window) or AUTH_RE.search(window):
            continue

        if COMMAND_EXEC_STRONG_RE.search(line) is not None and _has_external_taint(window):
            severity = "critical" if SHELL_TRUE_RE.search(window) else "high"
            if severity in {"high", "critical"}:
                return [_approval_finding(code_file, index, line)]

        if REQUEST_CALL_RE.search(line) is not None and _has_external_taint(window):
            severity = "critical" if ALLOWLIST_RE.search(window) is None else "high"
            if severity in {"high", "critical"}:
                return [_approval_finding(code_file, index, line)]

        file_op = _file_operation_details(line)
        if file_op is None:
            continue
        severity, _description, _confidence = _file_access_severity(
            context=code_file.context,
            op_type=file_op[0],
            external_taint=_has_external_path_taint(window),
            cli_taint=CLI_INPUT_RE.search(window) is not None,
            dynamic_path=_has_dynamic_path_evidence(window),
            sensitive_path=SENSITIVE_PATH_RE.search(window) is not None or _absolute_path_signal(window),
            destructive=file_op[0] == "delete" or _destructive_file_signal(window),
            traversal=_path_traversal_signal(window),
        )
        if severity in {"high", "critical"} and _has_external_path_taint(window):
            return [_approval_finding(code_file, index, line)]
    return []


def _prompt_injection_sensitive_wiring(ctx: MatchContext) -> list[CodeFinding]:
    if not SHELL_EXEC_RE.search(ctx.line) and not FILE_OP_RE.search(ctx.line) and not REQUEST_CALL_RE.search(ctx.line):
        return []
    if re.search(r"model_output|llm_output|completion|message\.content", ctx.window) is None:
        return []
    return [
        _finding(
            severity="high",
            rule_id="prompt-injection-sensitive-wiring",
            title="Prompt-injection-sensitive tool wiring",
            description="Untrusted model or tool output appears to flow directly into a dangerous action.",
            confidence=0.9,
            file=ctx.file,
            line_no=ctx.line_no,
            snippet=ctx.line,
            recommendation=[
                "Treat model output as untrusted input and validate it before execution.",
                "Use strict schemas and allowlists before mapping model output to commands, paths, or URLs.",
            ],
        )
    ]


def _auth_missing_network_service(code_file: ScannedCodeFile) -> list[CodeFinding]:
    if code_file.context not in {"server", "mcp"}:
        return []
    if not is_exposed_service_file(code_file.text, code_file.path, code_file.context):
        return []
    findings: list[CodeFinding] = []
    lines = code_file.text.splitlines()
    service_kind = _infer_service_kind(code_file.text, code_file.path, code_file.context)
    for index, line in enumerate(lines, start=1):
        if ROUTE_HANDLER_LINE_RE.search(line) is None:
            continue
        window = _window(lines, index, radius=12)
        if AUTH_RE.search(window):
            continue
        if _public_docs_or_health_route(line, window):
            continue
        severity = "high" if OPEN_PROXY_RE.search(window) or REQUEST_CALL_RE.search(window) else "medium"
        route_key = _route_prefix_or_port(window, line)
        cluster_id = f"auth-missing-on-network-service:{code_file.path}:{service_kind}:{route_key}"
        finding = _finding(
            severity=severity,
            rule_id="auth-missing-on-network-service",
            title="HTTP endpoint without visible auth checks",
            description="A route handler is exposed without nearby authentication or API key verification logic.",
            confidence=0.78,
            file=code_file,
            line_no=index,
            snippet=line,
            recommendation=[
                "Require authentication for exposed routes unless they are intentionally public and low risk.",
                "Document and enforce auth at the router or dependency layer so it is visible in code review.",
            ],
            cluster_id=cluster_id,
        )
        findings.append(finding)
    return findings


def _file_operation_details(line: str) -> tuple[FileOpType, str] | None:
    candidates: list[tuple[FileOpType, tuple[str, re.Pattern[str]]]] = [
        ("delete", ("Path.unlink", re.compile(r"Path\([^)]*\)\.unlink\s*\(", re.IGNORECASE))),
        ("delete", ("shutil.rmtree", re.compile(r"shutil\.rmtree\s*\(", re.IGNORECASE))),
        ("delete", ("fs.rmSync", re.compile(r"fs\.rmSync\s*\(", re.IGNORECASE))),
        ("delete", ("fs.rm", re.compile(r"fs\.rm\s*\(", re.IGNORECASE))),
        ("delete", ("fs.unlinkSync", re.compile(r"fs\.unlinkSync\s*\(", re.IGNORECASE))),
        ("delete", ("fs.unlink", re.compile(r"fs\.unlink\s*\(", re.IGNORECASE))),
        ("delete", ("os.remove", re.compile(r"os\.remove\s*\(", re.IGNORECASE))),
        ("delete", ("remove", re.compile(r"\bremove\s*\(", re.IGNORECASE))),
        ("delete", ("unlink", re.compile(r"\bunlink\s*\(", re.IGNORECASE))),
        ("write", ("Path.write_text", re.compile(r"write_text\s*\(", re.IGNORECASE))),
        ("write", ("Path.write_bytes", re.compile(r"write_bytes\s*\(", re.IGNORECASE))),
        ("write", ("fs.writeFileSync", re.compile(r"fs\.writeFileSync\s*\(", re.IGNORECASE))),
        ("write", ("fs.writeFile", re.compile(r"fs\.writeFile\s*\(", re.IGNORECASE))),
        ("write", ("appendFile", re.compile(r"appendFile(?:Sync)?\s*\(", re.IGNORECASE))),
        ("write", ("open:write", re.compile(r"\bopen\s*\([^)]*,\s*['\"](?:w|wb|a|ab|x|xb)['\"]", re.IGNORECASE))),
        ("read", ("Path.read_text", re.compile(r"read_text\s*\(", re.IGNORECASE))),
        ("read", ("Path.read_bytes", re.compile(r"read_bytes\s*\(", re.IGNORECASE))),
        ("read", ("fs.readFileSync", re.compile(r"fs\.readFileSync\s*\(", re.IGNORECASE))),
        ("read", ("fs.readFile", re.compile(r"fs\.readFile\s*\(", re.IGNORECASE))),
        ("read", ("open:read", re.compile(r"\bopen\s*\(", re.IGNORECASE))),
    ]
    for op_type, (label, pattern) in candidates:
        if pattern.search(line):
            return op_type, label
    return None


def _file_rule_metadata(op_type: FileOpType) -> tuple[str, str]:
    if op_type == "read":
        return "arbitrary-file-read", "Arbitrary file read access"
    if op_type == "write":
        return "arbitrary-file-write", "Arbitrary file write access"
    return "arbitrary-file-delete", "Arbitrary file delete access"


def _file_access_cluster_id(rule_id: str, file_path: str, sink_signature: str) -> str:
    return f"{rule_id}:{file_path}:{sink_signature}"


def _file_access_severity(
    *,
    context: str,
    op_type: FileOpType,
    external_taint: bool,
    cli_taint: bool,
    dynamic_path: bool,
    sensitive_path: bool,
    destructive: bool,
    traversal: bool,
) -> tuple[str | None, str, float]:
    if context in {"server", "mcp"}:
        if external_taint:
            return "high", f"{op_type.capitalize()} access appears to use an externally controlled path in server or MCP runtime code.", 0.9
        if dynamic_path or sensitive_path or destructive or traversal:
            return "medium", f"{op_type.capitalize()} access operates on a dynamic or sensitive path in server or MCP runtime code.", 0.76
        return None, "", 0.0

    if context in {"cli", "library"}:
        if external_taint or cli_taint or dynamic_path or sensitive_path or destructive or traversal:
            if sensitive_path or destructive or traversal:
                return "medium", f"{context.capitalize()} {op_type} access touches caller-controlled or potentially unsafe paths.", 0.72
            return "low", f"{context.capitalize()} {op_type} access uses caller-provided paths.", 0.62
        return None, "", 0.0

    if context == "ci":
        if external_taint or dynamic_path or sensitive_path or destructive or traversal:
            if sensitive_path or destructive or traversal:
                return "medium", f"CI or automation {op_type} access uses mutable paths or sensitive operations.", 0.7
            return "low", f"CI or automation {op_type} access uses mutable paths.", 0.58
        return None, "", 0.0

    if sensitive_path or destructive or traversal or dynamic_path or external_taint:
        severity = "medium" if (sensitive_path or destructive or traversal) else "low"
        return severity, f"Library {op_type} access uses dynamic or potentially unsafe paths.", 0.66 if severity == "low" else 0.72
    return None, "", 0.0


def _has_external_taint(text: str) -> bool:
    return _has_external_path_taint(text) or re.search(r"message\.content|model_output|llm_output|completion", text) is not None


def _has_external_path_taint(text: str) -> bool:
    if _safe_repo_local_path(text):
        return False
    if CLI_INPUT_RE.search(text):
        return False
    return EXTERNAL_PATH_TAINT_RE.search(text) is not None or SCHEMA_PATH_HINT_RE.search(text) is not None


def _has_dynamic_path_evidence(text: str) -> bool:
    if _safe_repo_local_path(text):
        return False
    if re.search(r"\b(req|request|payload|ctx\.arguments|tool_|query|body|params)\b", text, re.IGNORECASE) is None:
        return False
    if re.search(r"\b(path|file|filename|filepath|output|input|target)\b", text, re.IGNORECASE) is not None:
        return True
    return PATH_BUILD_RE.search(text) is not None


def _looks_like_webhook_context(text: str) -> bool:
    if WEBHOOK_ROUTE_RE.search(text):
        return True
    if WEBHOOK_RE.search(text) and ROUTE_RE.search(text):
        return True
    if CALLBACK_URL_RE.search(text) and VERIFY_RE.search(text):
        return True
    return False


def _path_traversal_signal(text: str) -> bool:
    if PATH_TRAVERSAL_LITERAL_RE.search(text):
        return True
    if _has_external_path_taint(text) and PATH_BUILD_RE.search(text) and FIXED_BASE_RE.search(text):
        return True
    return False


def _path_traversal_line_signal(line: str) -> bool:
    if _static_module_import(line):
        return False
    if PATH_TRAVERSAL_LITERAL_RE.search(line):
        return True
    if PATH_BUILD_RE.search(line) and (_has_external_path_taint(line) or re.search(r"payload|req\.|request\.|ctx\.arguments|tool_", line, re.IGNORECASE)):
        return True
    return False


def _path_mitigation_present(text: str) -> bool:
    if PATH_MITIGATION_RE.search(text):
        return True
    if PATH_BUILD_RE.search(text) and re.search(r"resolve\(|normalize\(", text, re.IGNORECASE) and re.search(r"is_relative_to|commonpath|startswith", text, re.IGNORECASE):
        return True
    return False


def _absolute_path_signal(text: str) -> bool:
    return re.search(r"['\"]/(?:[^'\"]+)['\"]|[A-Za-z]:\\|~/", text) is not None


def _destructive_file_signal(text: str) -> bool:
    return FILE_DELETE_RE.search(text) is not None or re.search(r"chmod|chown|rm\s+-|delete", text, re.IGNORECASE) is not None


def _http_handler_indicator(text: str) -> bool:
    return ROUTE_RE.search(text) is not None or re.search(r"\b(req|request)\b|Request\b|request\.", text) is not None


def _looks_remotely_triggerable(text: str) -> bool:
    return ROUTE_RE.search(text) is not None or re.search(r"\b(req|request)\b|Request\b|request\.", text) is not None


def _safe_repo_local_path(text: str) -> bool:
    if PACKAGE_METADATA_RE.search(text) and SAFE_REPO_PATH_RE.search(text):
        return True
    if re.search(r"Path\s*\(\s*__file__\s*\)", text):
        return True
    if re.search(r"\b(?:join|resolve)\s*\(\s*__dirname", text):
        return True
    if SAFE_REPO_PATH_RE.search(text) and SENSITIVE_PATH_RE.search(text) is None and USER_INPUT_RE.search(text) is None:
        return True
    return False


def is_exposed_service_file(text: str, file_path: str, context: str) -> bool:
    lowered_path = file_path.lower()
    if context == "mcp":
        return True
    if "server" in lowered_path:
        return True
    if MCP_TRANSPORT_MARKER_RE.search(text):
        return True
    if FASTAPI_MARKER_RE.search(text) or FLASK_MARKER_RE.search(text) or EXPRESS_MARKER_RE.search(text):
        return True
    if NODE_HTTP_MARKER_RE.search(text) or SERVER_START_MARKER_RE.search(text):
        return True
    return False


def _infer_service_kind(text: str, file_path: str, context: str) -> str:
    if EXPRESS_MARKER_RE.search(text):
        return "express"
    if FASTIFY_MARKER_RE.search(text):
        return "fastify"
    if KOA_MARKER_RE.search(text):
        return "koa"
    if context == "mcp" or MCP_TRANSPORT_MARKER_RE.search(text) or FASTAPI_MARKER_RE.search(text) or FLASK_MARKER_RE.search(text) or NODE_HTTP_MARKER_RE.search(text) or "server" in file_path.lower():
        return "http"
    return "unknown"


def _route_prefix_or_port(window: str, line: str) -> str:
    route_match = ROUTE_PREFIX_RE.search(line)
    if route_match:
        route = route_match.group(1)
        if route.startswith("/"):
            parts = [part for part in route.split("/") if part]
            if parts:
                return f"/{parts[0]}"
            return "/"
    port_match = PORT_RE.search(window)
    if port_match:
        return f"port:{port_match.group(1)}"
    return "unknown"


def _public_docs_or_health_route(line: str, window: str) -> bool:
    return PUBLIC_ROUTE_RE.search(line) is not None or PUBLIC_ROUTE_RE.search(window) is not None


def _likely_user_controlled(text: str) -> bool:
    return USER_INPUT_RE.search(text) is not None


def _has_user_controlled_full_url(line: str, window: str) -> bool:
    if re.search(r"\b(target_url|user_url|callback_url|endpoint_url)\b", window, re.IGNORECASE):
        return True
    if re.search(r"\b(?:url|endpoint)\s*=\s*(?:request\.|req\.|payload|params|query|body|ctx\.arguments|tool_)", window, re.IGNORECASE):
        return True
    if re.search(r"fetch\s*\(\s*url\s*\)|requests\.(?:get|post|request)\s*\(\s*url\b|httpx\.(?:get|post|request)\s*\(\s*url\b", line, re.IGNORECASE):
        return True
    if re.search(r"new URL\s*\(\s*(?:request\.|req\.|payload|params|query|body|ctx\.arguments)", window, re.IGNORECASE):
        return True
    return False


def _fixed_base_upstream_with_user_params(line: str, window: str) -> bool:
    if FIXED_UPSTREAM_URL_RE.search(window) is None and _fixed_literal_upstream(window) is None:
        return False
    if re.search(r"fetch\s*\(\s*url\s*\)|requests\.(?:get|post|request)\s*\(\s*url\b|httpx\.(?:get|post|request)\s*\(\s*url\b", line, re.IGNORECASE):
        return False
    if _has_user_controlled_full_url(line, window):
        return False
    if re.search(r"\?[$]{0,1}\{?(?:params|query|searchParams|payload|request\.)", line, re.IGNORECASE):
        return True
    if re.search(r"URLSearchParams|params\s*=|query\s*=|searchParams", window, re.IGNORECASE):
        return True
    return False


def _fixed_vendor_api_wrapper(line: str, window: str) -> bool:
    if _has_user_controlled_full_url(line, window):
        return False
    if re.search(r"https://(?:slack\.com/api|api\.github\.com|maps\.googleapis\.com|api\.search\.brave\.com)", window, re.IGNORECASE) is None:
        return False
    if re.search(r"new URL\s*\(\s*[\"']https://|fetch\s*\(\s*`https://", window, re.IGNORECASE) is None and FIXED_UPSTREAM_URL_RE.search(window) is None:
        return False
    return re.search(r"searchParams|params\.append|params\s*=|query\s*=|\?\$\{", window, re.IGNORECASE) is not None


def _fixed_literal_upstream(text: str) -> str | None:
    match = re.search(r"new URL\s*\(\s*[\"'](https://[^\"']+)[\"']\s*\)", text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"(?:const|let|var)\s+url\s*=\s*[\"'](https://[^\"']+)[\"']", text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _oauth_token_exchange_request(line: str, window: str) -> bool:
    if re.search(r"requests\.(?:post|request)\s*\(", line) is None:
        return False
    if re.search(r"(oauth|token_endpoint|token_url|refresh_token|authorization code|access token)", window, re.IGNORECASE) is None:
        return False
    return re.search(r"\b(self\.)?(token_url|token_endpoint)\b", window, re.IGNORECASE) is not None


def _templated_secret_value(text: str) -> bool:
    return re.search(r'["\']\$\{[A-Za-z0-9_]+\}["\']', text) is not None


def _multipart_upload_file_wrapper(text: str) -> bool:
    if re.search(r"multipart form data|multipart/form-data|prepare multipart form data", text, re.IGNORECASE):
        return True
    return re.search(r'files\s*=\s*\{[^}]*["\']file["\']\s*:', text, re.IGNORECASE | re.DOTALL) is not None


def _comment_or_docstring_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith(("#", "//", "*", '"""', "'''")):
        return True
    return re.match(r"^[A-Za-z_][A-Za-z0-9_]*:\s", stripped) is not None


def _window(lines: list[str], line_no: int, radius: int = 4) -> str:
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[severity]


def _snippet(line: str) -> str:
    compact = " ".join(line.strip().split())
    return compact[:180]


def _finding(
    *,
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    confidence: float,
    file: ScannedCodeFile,
    line_no: int,
    snippet: str,
    recommendation: list[str],
    op_type: FileOpType | None = None,
    cluster_id: str | None = None,
) -> CodeFinding:
    return CodeFinding(
        severity=severity,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=title,
        description=description,
        confidence=confidence,
        evidence=CodeEvidence(file_path=file.path, line=line_no, snippet=_snippet(snippet)),
        recommendation=recommendation,
        op_type=op_type,
        cluster_id=cluster_id,
        context=file.context,
        nearby_context=_nearby_context(snippet if snippet != file.path else "", file, line_no),
    )


def _approval_finding(file: ScannedCodeFile, line_no: int, snippet: str) -> CodeFinding:
    return _finding(
        severity="medium",
        rule_id="tool-approval-missing",
        title="Dangerous capability without approval checks",
        description="Dangerous tool or runtime capability is present without visible approval, allowlist, or auth checks nearby.",
        confidence=0.72,
        file=file,
        line_no=line_no,
        snippet=snippet,
        recommendation=[
            "Gate dangerous actions behind explicit approvals or strong authorization checks.",
            "Add capability-specific allowlists for commands, paths, and destinations.",
        ],
    )


def _cluster_and_dedupe_findings(findings: list[CodeFinding]) -> list[CodeFinding]:
    return _assign_clusters(findings)


def _nearby_context(snippet: str, file: ScannedCodeFile, line_no: int) -> str:
    lines = file.text.splitlines()
    window = _window(lines, line_no, radius=4)
    compact = "\n".join(line[:200] for line in window.splitlines())
    return compact[:600]


def _static_module_import(line: str) -> bool:
    return MODULE_IMPORT_RE.search(line) is not None or MODULE_IMPORT_CONTINUATION_RE.search(line) is not None


def _assign_clusters(findings: list[CodeFinding]) -> list[CodeFinding]:
    grouped: dict[str, list[CodeFinding]] = defaultdict(list)
    for finding in findings:
        if finding.cluster_id is None:
            finding.cluster_id = _cluster_id_for_finding(finding)
        grouped[finding.cluster_id].append(finding)

    for cluster_id, cluster_findings in grouped.items():
        primary = max(
            cluster_findings,
            key=lambda item: (
                float(item.confidence),
                len(item.nearby_context or ""),
                _severity_rank(item.severity),
                -(item.evidence.line or 0),
            ),
        )
        cluster_size = len(cluster_findings)
        for finding in cluster_findings:
            finding.cluster_id = cluster_id
            finding.cluster_size = cluster_size
            finding.cluster_role = "primary" if finding is primary else "duplicate"
    return findings


def _cluster_id_for_finding(finding: CodeFinding) -> str:
    file_path = finding.evidence.file_path
    rule_id = finding.rule_id
    snippet = finding.evidence.snippet
    window = finding.nearby_context or ""

    if rule_id == "command-execution":
        shell = "shell_true" if SHELL_TRUE_RE.search(window) else "shell_false"
        signature = _command_signature(snippet)
        return f"{rule_id}:{file_path}:{signature}:{shell}"
    if rule_id in {"ssrf-fetch", "open-proxy-endpoint"}:
        return f"{rule_id}:{file_path}:{_request_signature(snippet)}:{_route_prefix_or_port(window, snippet)}"
    if rule_id in FILE_ACCESS_RULES:
        sink = finding.op_type or "unknown"
        variable = _path_variable_name(snippet)
        return f"{rule_id}:{file_path}:{sink}:{variable}"
    if rule_id == "hardcoded-secret":
        return f"{rule_id}:{file_path}:{_secret_signature(snippet)}"
    if rule_id == "auth-missing-on-network-service":
        if finding.cluster_id:
            return finding.cluster_id
        return f"{rule_id}:{file_path}:{_route_prefix_or_port(window, snippet)}"
    if rule_id == "prompt-injection-sensitive-wiring":
        return f"{rule_id}:{file_path}:{_dangerous_sink_kind(snippet)}"
    if rule_id == "unsafe-docker-runtime":
        return f"{rule_id}:{file_path}:{_docker_signature(snippet)}"
    if rule_id == "path-traversal":
        return f"{rule_id}:{file_path}:{_path_traversal_signature(snippet)}"
    digest = hashlib.sha1(f"{rule_id}|{file_path}|{snippet}".encode("utf-8")).hexdigest()[:12]
    return f"{rule_id}:{file_path}:{digest}"


def _command_signature(text: str) -> str:
    for label, pattern in {
        "subprocess.run": r"subprocess\.run",
        "subprocess.Popen": r"subprocess\.Popen",
        "subprocess.call": r"subprocess\.call",
        "os.system": r"os\.system",
        "child_process.exec": r"child_process\.(?:exec|execSync)",
        "child_process.spawn": r"child_process\.(?:spawn|spawnSync)",
        "exec": r"(?<![A-Za-z0-9_])exec\s*\(",
        "eval": r"(?<![A-Za-z0-9_])eval\s*\(",
        "spawn": r"(?<![A-Za-z0-9_])spawn\s*\(",
    }.items():
        if re.search(pattern, text):
            return label
    return "unknown"


def _request_signature(text: str) -> str:
    for label, pattern in {
        "requests.get": r"requests\.get",
        "requests.post": r"requests\.post",
        "httpx.get": r"httpx\.get",
        "httpx.post": r"httpx\.post",
        "fetch": r"fetch\s*\(",
        "axios": r"axios\.",
        "urllib": r"urllib\.request\.urlopen",
    }.items():
        if re.search(pattern, text):
            return label
    return "unknown"


def _path_variable_name(text: str) -> str:
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*(?:path|file|target|output|input))\b", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return "unknown"


def _secret_signature(text: str) -> str:
    if "ghp_" in text:
        return "ghp"
    if "gho_" in text:
        return "gho"
    if "sk_live_" in text:
        return "sk_live"
    if "AKIA" in text:
        return "akia"
    if "Bearer " in text:
        return "bearer"
    return "generic"


def _dangerous_sink_kind(text: str) -> str:
    if SHELL_EXEC_RE.search(text):
        return "shell"
    if REQUEST_CALL_RE.search(text):
        return "network"
    if FILE_OP_RE.search(text):
        return "filesystem"
    return "unknown"


def _docker_signature(text: str) -> str:
    if "docker.sock" in text:
        return "docker_socket"
    if "privileged" in text:
        return "privileged"
    return "docker"


def _path_traversal_signature(text: str) -> str:
    if PATH_TRAVERSAL_LITERAL_RE.search(text):
        return "dotdot"
    if "click.Path" in text:
        return "click_path"
    if "__dirname" in text or "__file__" in text or "import.meta.url" in text:
        return "repo_local"
    return "path_build"


def _is_real_command_execution(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*")):
        return False
    if re.match(r"(type\s+\w+\s*=|interface\s+\w+)", stripped):
        return False
    match = REAL_COMMAND_EXEC_RE.search(line)
    if match is None:
        return False
    if _match_inside_quotes(line, match.start()):
        return False
    return True


def _match_inside_quotes(text: str, position: int) -> bool:
    single = False
    double = False
    escaped = False
    for index, char in enumerate(text):
        if index >= position:
            break
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
        elif char == '"' and not single:
            double = not double
    return single or double
