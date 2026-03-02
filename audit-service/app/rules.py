from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import math
import re

from .models import DocumentContext, Evidence, Finding


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
RULE_CONFIDENCE = {
    "deterministic": 0.9,
    "heuristic": 0.6,
    "capability": 0.5,
}
GUARDRAIL_RE = re.compile(
    r"\b(allowlist|denylist|sandbox|permission(?:s)?|authenticate|authentication|authorization|auth\b|approved domains?|trusted domains?|least privilege|rate limit|origin restrictions?)\b",
    re.IGNORECASE,
)
AUTHORITATIVE_LINK_RE = re.compile(
    r"^https://(?:raw\.githubusercontent\.com|github\.com)/.+/(?:blob/)?(main|master)/.+\.(?:md|markdown)$",
    re.IGNORECASE,
)
MUTABLE_BRANCH_RE = re.compile(
    r"https://(?:raw\.githubusercontent\.com|github\.com)/.+/(?:blob/|tree/)?(?:main|master)/",
    re.IGNORECASE,
)
SSRF_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "high",
        re.compile(r"\b(fetch|download|retrieve)\s+(?:any|arbitrary)\s+url\b", re.IGNORECASE),
        "The docs describe fetching arbitrary URLs without stating a domain allowlist.",
    ),
    (
        "medium",
        re.compile(r"\b(provide|pass|supply)\s+(?:a|any)\s+url\b", re.IGNORECASE),
        "The docs accept user-supplied URLs without describing an allowlist or validation policy.",
    ),
    (
        "medium",
        re.compile(r"\b(download|fetch)\s+from\s+(?:a|any)\s+url\b", re.IGNORECASE),
        "The docs describe downloading from caller-controlled URLs without guardrails.",
    ),
]
EXPLICIT_URL_FETCH_RE = re.compile(
    r"\b(?:fetch|download|retrieve)\s+(?:any|arbitrary)?\s*url\b|\b(?:provide|pass|supply)\s+(?:a|any)\s+url\b|\bfetch\s+url\b",
    re.IGNORECASE,
)
PRIVATE_IP_MITIGATION_RE = re.compile(
    r"\b(169\.254\.169\.254|localhost|127\.0\.0\.1|private ip|rfc1918|allowlist|denylist|metadata)\b",
    re.IGNORECASE,
)
CAPABILITY_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "shell",
        "capability-shell",
        re.compile(r"\b(shell|exec|command execution|subprocess|os\.system|bash execution)\b", re.IGNORECASE),
        "Shell or explicit command execution capability is documented.",
    ),
    (
        "filesystem",
        "capability-filesystem",
        re.compile(r"\b(filesystem|read files?|write files?|file access|read/write)\b", re.IGNORECASE),
        "Filesystem read or write capability is documented.",
    ),
    (
        "network",
        "capability-network",
        re.compile(r"\b(httpx|axios|http requests?|fetch url|url fetching|call external api|download from url|proxy request|network access)\b", re.IGNORECASE),
        "Network fetch capability is documented.",
    ),
    (
        "browser",
        "capability-browser",
        re.compile(r"\b(headless browser|browser access|open browser|web browser)\b", re.IGNORECASE),
        "Browser interaction capability is documented.",
    ),
    (
        "browser-automation",
        "capability-browser-automation",
        re.compile(r"\b(playwright|selenium|puppeteer|browser automation)\b", re.IGNORECASE),
        "Browser automation capability is documented.",
    ),
    (
        "proxy",
        "capability-proxy",
        re.compile(r"\b(api route|proxy route|server route|proxy endpoint|backend proxy)\b", re.IGNORECASE),
        "Proxy or API mediation capability is documented.",
    ),
    (
        "file-upload",
        "capability-file-upload",
        re.compile(
            r"\b(allowfiles|setinputfiles|multipart/form-data|file input|image upload|upload files?|attach file|dropzone|choose file|select file|drag and drop)\b",
            re.IGNORECASE,
        ),
        "File upload capability is documented.",
    ),
    (
        "client-side-tools",
        "capability-client-side-tools",
        re.compile(r"\b(client-side tools|tool execution in browser|browser tools?)\b", re.IGNORECASE),
        "Client-side tool execution is documented.",
    ),
    (
        "docker",
        "capability-docker",
        re.compile(r"\b(docker run|docker compose|dockerfile|container image|--privileged|docker\.sock)\b", re.IGNORECASE),
        "Docker or container runtime capability is documented.",
    ),
    (
        "git",
        "capability-git",
        re.compile(r"\b(git clone|git checkout|git pull|git push|repository operations?)\b", re.IGNORECASE),
        "Git repository manipulation capability is documented.",
    ),
    (
        "k8s",
        "capability-k8s",
        re.compile(r"\b(kubectl|kubernetes|helm install|cluster role|k8s)\b", re.IGNORECASE),
        "Kubernetes or cluster administration capability is documented.",
    ),
    (
        "email",
        "capability-email",
        re.compile(r"\b(send email|smtp|mailgun|sendgrid|ses|email delivery|outbound email)\b", re.IGNORECASE),
        "Email sending or delivery capability is documented.",
    ),
    (
        "payment",
        "capability-payment",
        re.compile(r"\b(payment|billing|checkout|subscription|stripe|paypal|crypto|bank transfer|wallet)\b", re.IGNORECASE),
        "Payment or billing capability is documented.",
    ),
    (
        "clipboard",
        "capability-clipboard",
        re.compile(r"\b(copy to clipboard|paste from clipboard|clipboard\.(?:write|read))\b", re.IGNORECASE),
        "Clipboard access capability is documented.",
    ),
    (
        "notifications",
        "capability-notifications",
        re.compile(r"\b(send notification(?:s)?|push notification(?:s)?|desktop notification(?:s)?|toast notification(?:s)?)\b", re.IGNORECASE),
        "Notification or alerting capability is documented.",
    ),
]
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*)\s*[:=]\s*([^\s#]+)"
)
PLACEHOLDER_SECRET_RE = re.compile(
    r"\b(?:YOUR_[A-Z0-9_]+|API_KEY=\.\.\.|TOKEN=\.\.\.|SECRET=\.\.\.|sk-\.\.\.|inf_\.\.\.|xxxx+|bearer\s+\.\.\.)\b",
    re.IGNORECASE,
)
LIVE_SECRET_PREFIX_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bghp_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxoxb-[A-Za-z0-9-]{24,}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bbearer\s+[A-Za-z0-9._-]{24,}\b", re.IGNORECASE),
]
GENERIC_LIVE_SECRET_RE = re.compile(r"^[A-Za-z0-9+/=]{32,}$")
ENV_HINT_RE = re.compile(r"(?im)(^|\s)(\.env(?:\.local)?|dotenv|example\.env)\b")
TEST_CONTEXT_RE = re.compile(r"\b(test|testing|unit|integration|e2e|playwright|fixture|fixtures)\b", re.IGNORECASE)
CONFIG_CONTEXT_RE = re.compile(r"\b(\.env(?:\.local)?|config/env|process\.env|custom:|environment variables?|test configuration)\b", re.IGNORECASE)
FAKE_SECRET_VALUE_RE = re.compile(r"\b(?:sk_test_[A-Za-z0-9_]+|pk_test_[A-Za-z0-9_]+|SG\.[A-Za-z0-9_.-]+|fake[_-]?(?:key|token|secret)|test[_-]?(?:key|token|secret))\b", re.IGNORECASE)
PUBLIC_EXPOSURE_RES: list[tuple[str, re.Pattern[str], str]] = [
    ("medium", re.compile(r"\b0\.0\.0\.0\b"), "The docs expose a service on all interfaces."),
    ("medium", re.compile(r"--host\s+0\.0\.0\.0"), "The docs bind a service to all interfaces."),
    ("high", re.compile(r"\bpublic endpoint\b", re.IGNORECASE), "The docs mention a public endpoint without describing authentication."),
]
AUTHORITATIVE_HINTS = {"source", "skill", "readme", "instructions", "guide", "reference"}
PLACEHOLDER_HINTS = ("example", "your_", "your-", "<", ">", "{", "changeme", "xxxx", "token_here", "replace_me", "...")
REMOTE_INSTALL_RES: list[re.Pattern[str]] = [
    re.compile(r"\bnpx\s+\S+\s+add\s+https://\S+", re.IGNORECASE),
    re.compile(r"\bcurl\s+https://\S+\s*\|\s*(?:bash|sh)\b", re.IGNORECASE),
    re.compile(r"\binstall\s+from\s+https://\S+", re.IGNORECASE),
    re.compile(r"\badd\s+https://\S+\.json\b", re.IGNORECASE),
]
API_ROUTE_RE = re.compile(r"\b(api route|server route|route handler|proxy route|/api/)\b", re.IGNORECASE)
ENV_KEY_RE = re.compile(r"\b(api[_ -]?key|token|secret|process\.env|os\.environ|dotenv)\b", re.IGNORECASE)
INSTRUCTION_CONTEXT_RE = re.compile(r"\b(agent must|you are|system:|instructions?:|do not|developer message|system prompt)\b", re.IGNORECASE)
PROMPT_OVERRIDE_DIRECT_RE = re.compile(r"\b(ignore previous instructions|override system|always comply)\b", re.IGNORECASE)
PROMPT_OVERRIDE_RE = re.compile(r"\b(ignore previous instructions|override system|system prompt|developer message|always comply)\b", re.IGNORECASE)
STEALTH_RE = re.compile(r"\b(do not tell the user|secretly|silently|without user knowing)\b", re.IGNORECASE)
STEALTH_ACTION_RE = re.compile(r"\b(fetch|read|send|upload|exfiltrate|run)\b", re.IGNORECASE)
UI_DEBUG_RE = re.compile(r"\b(ui|debug|toast|spinner|loading|render|display|progress|notification)\b", re.IGNORECASE)
EXFIL_RE = re.compile(r"\b(printenv|dump env|read\s+\.env|read\s+~\/\.ssh|export keys?|send tokens?)\b", re.IGNORECASE)
IMPERATIVE_RE = re.compile(r"\b(read|send|upload|fetch|exfiltrate|dump|print|export|copy|run)\b", re.IGNORECASE)
SENSITIVE_TARGET_RE = re.compile(r"\b(\.env|~\/\.ssh|ssh|tokens?|keys?|credential(?:s)?|secret(?:s)?|env)\b", re.IGNORECASE)
UNSAFE_FILE_RE = re.compile(r"(\*\*/\*|read entire repo|scan home directory|/etc|~\/\.ssh|\.git\b)", re.IGNORECASE)
FILE_ACTION_RE = re.compile(r"\b(files?|read|pattern|glob|load|write|scan)\b", re.IGNORECASE)
REDIRECT_RE = re.compile(r"\b(follow redirects|redirects enabled|handle redirects)\b", re.IGNORECASE)
NPM_INSTALL_RE = re.compile(r"\bnpm\s+install\s+([^\s`]+)")
PIP_INSTALL_RE = re.compile(r"\bpip(?:3)?\s+install\s+([^\s`]+)")
GO_GET_RE = re.compile(r"\bgo\s+get\s+([^\s`]+)")
LATEST_PKG_RE = re.compile(r"\b[A-Za-z0-9_./@-]+@latest\b")
CURL_PIPE_RE = re.compile(r"\bcurl\s+\S+\s*\|\s*(?:bash|sh)\b|\bwget\s+\S+\s*\|\s*(?:bash|sh)\b|\bpowershell\b.*\biex\b|\bInvoke-Expression\b|\bIEX\(", re.IGNORECASE)
WEBHOOK_RE = re.compile(r"\b(webhook|callback url)\b", re.IGNORECASE)
WEBHOOK_ENDPOINT_RE = re.compile(r"(/webhook\b|/callback\b)", re.IGNORECASE)
WEBHOOK_VERIFY_RE = re.compile(r"\b(signature|hmac|verify|secret)\b", re.IGNORECASE)
OAUTH_SCOPE_RE = re.compile(r"\bscope(?:s)?\b", re.IGNORECASE)
BROAD_SCOPE_RE = re.compile(r"\b(admin|repo|all permissions|full access)\b", re.IGNORECASE)
NETWORK_SERVICE_RE = re.compile(r"\b(runs on port\s+\d+|listens on port\s+\d+|exposes?\s+/api|endpoint\b|localhost:\d+|http://[^\s]+)\b", re.IGNORECASE)
AUTH_TERMS_RE = re.compile(r"\b(auth|token|jwt|oauth|api key|authentication|authorization)\b", re.IGNORECASE)
LOGGING_RE = re.compile(r"\b(debug logs?|log headers|print request|verbose logging)\b", re.IGNORECASE)
SANDBOX_DISABLE_RE = re.compile(r"(--privileged|\bdisable sandbox\b|\brun as root\b|\bchmod 777\b|\bsetenforce 0\b|\bdisable selinux\b)", re.IGNORECASE)
DOCKER_CONTEXT_RE = re.compile(r"\b(docker run|docker compose|docker)\b", re.IGNORECASE)
DOCKER_PRIV_RE = re.compile(r"(--privileged|-v\s+/:/host|/var/run/docker\.sock)", re.IGNORECASE)
APPROVAL_CLAIM_RE = re.compile(r"\b(human-in-the-loop|approval required|requires approval)\b", re.IGNORECASE)
APPROVAL_MECHANISM_RE = re.compile(r"\b(how to enable approval|approval mode|approval config|config(?:ure|uration)?)\b", re.IGNORECASE)
FILE_UPLOAD_RE = re.compile(
    r"\b(allowfiles|setinputfiles|multipart/form-data|file input|image upload|upload files?|attach file|dropzone|choose file|select file|drag and drop)\b",
    re.IGNORECASE,
)
FILE_UPLOAD_CONTEXT_RE = re.compile(
    r"\b(file|image|attachment|input|multipart|form-data|drag and drop|setinputfiles|allowfiles)\b",
    re.IGNORECASE,
)
FILE_UPLOAD_FALSE_POSITIVE_RE = re.compile(
    r"\b(do not upload|upload to (?:reddit|github|discord)|uploaded prompt|upload this text)\b",
    re.IGNORECASE,
)
PROMPT_CORPUS_MARKER_RE = re.compile(
    r"\b(do anything now|jailbreak|bypass|uncensored|payloads?|prompt injection|corpus|dataset)\b",
    re.IGNORECASE,
)
CORPUS_RESEARCH_MARKER_RE = re.compile(
    r"\b(jailbreak|bypass|payloads?|prompt injection|corpus|dataset|research list|collected prompts?)\b",
    re.IGNORECASE,
)
PROMPT_INJECTION_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore-previous", re.compile(r"\bignore previous instructions\b", re.IGNORECASE)),
    ("override-system", re.compile(r"\boverride system\b", re.IGNORECASE)),
    ("system-prompt", re.compile(r"\bsystem prompt\b", re.IGNORECASE)),
    ("developer-message", re.compile(r"\bdeveloper message\b", re.IGNORECASE)),
    ("always-comply", re.compile(r"\balways comply\b", re.IGNORECASE)),
    ("do-anything-now", re.compile(r"\bdo anything now\b", re.IGNORECASE)),
    ("bypass", re.compile(r"\bbypass\b", re.IGNORECASE)),
    ("uncensored", re.compile(r"\buncensored\b", re.IGNORECASE)),
    ("do-not-tell", re.compile(r"\bdo not tell the user\b", re.IGNORECASE)),
]
OPERATIONAL_CONTEXT_RE = re.compile(
    r"\b(capabilities?:|use this to|enable|configure|set\b|api route|tool\b|endpoint\b|supports?\b|allows?\b|run\b|execute\b|docker run|kubectl|git clone|process payment|send email|copy to clipboard|paste from clipboard|push notification|desktop notification|upload endpoint|file input|multipart/form-data)\b",
    re.IGNORECASE,
)
SECTION_OPERATIONAL_RE = re.compile(r"\b(capabilities?|features?|usage|setup|configuration|config|api|props?|tools?)\b", re.IGNORECASE)
NETWORK_CONTEXT_RE = re.compile(r"\b(httpx|axios|http requests?|fetch url|url fetching|call external api|download from url|proxy request|network access)\b", re.IGNORECASE)
BROWSER_CONTEXT_RE = re.compile(r"\b(open browser|launch browser|browser access|headless browser|browser automation|playwright|selenium|puppeteer)\b", re.IGNORECASE)
EMAIL_CONTEXT_RE = re.compile(r"\b(send email|smtp|mailgun|sendgrid|ses|email delivery|outbound email)\b", re.IGNORECASE)
NOTIFICATION_CONTEXT_RE = re.compile(r"\b(send notification(?:s)?|push notification(?:s)?|desktop notification(?:s)?|toast notification(?:s)?)\b", re.IGNORECASE)
CLIPBOARD_CONTEXT_RE = re.compile(r"\b(copy to clipboard|paste from clipboard|clipboard\.(?:write|read))\b", re.IGNORECASE)
PAYMENT_CONTEXT_RE = re.compile(r"\b(process payment|billing flow|checkout|subscription|charge card|payment provider|stripe|paypal|wallet)\b", re.IGNORECASE)
GIT_CONTEXT_RE = re.compile(r"\b(git clone|git checkout|git pull|git push)\b", re.IGNORECASE)
K8S_CONTEXT_RE = re.compile(r"\b(kubectl|kubernetes|helm install|cluster role|k8s)\b", re.IGNORECASE)
DOCKER_CONTEXT_STRONG_RE = re.compile(r"\b(docker run|docker compose|dockerfile|container image|docker\.sock|--privileged)\b", re.IGNORECASE)
FILESYSTEM_CONTEXT_RE = re.compile(r"\b(read files?|write files?|file access|filesystem|read/write|open local)\b", re.IGNORECASE)
SHELL_CONTEXT_RE = re.compile(r"\b(shell|exec|command execution|subprocess|os\.system|bash execution|run this script)\b", re.IGNORECASE)
FILE_UPLOAD_OPERATIONAL_RE = re.compile(r"\b(file input|multipart/form-data|setinputfiles|allowfiles|upload endpoint|attach file|choose file|select file|drag and drop|image upload)\b", re.IGNORECASE)


@dataclass(slots=True)
class MatchContext:
    doc: DocumentContext
    start: int
    end: int
    section: str | None


@dataclass(slots=True)
class AnalysisResult:
    findings: list[Finding]
    capabilities: list[str]


def llm_explanation_stub(_findings: list[Finding]) -> None:
    """Placeholder for a future optional LLM summarizer."""


def _normalized_snippet(text: str, start: int, end: int, window: int = 120) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    return " ".join(text[left:right].split())[:280]


def _match_in_doc(doc: DocumentContext, pattern: re.Pattern[str]) -> MatchContext | None:
    match = pattern.search(doc.text)
    if not match:
        return None
    return MatchContext(doc=doc, start=match.start(), end=match.end(), section=doc.parsed.section_for_offset(match.start()))


def _mentioned_anywhere(doc: DocumentContext, pattern: re.Pattern[str]) -> bool:
    return bool(pattern.search(doc.text))


def _mentioned_anywhere_docs(docs: list[DocumentContext], pattern: re.Pattern[str]) -> bool:
    return any(_mentioned_anywhere(doc, pattern) for doc in docs)


def _nearby_text(doc: DocumentContext, start: int, end: int, window: int = 180) -> str:
    return _normalized_snippet(doc.text, start, end, window=window)


def _has_nearby_keywords(doc: DocumentContext, start: int, end: int, pattern: re.Pattern[str], window: int = 180) -> bool:
    return bool(pattern.search(_nearby_text(doc, start, end, window=window)))


def _capability_context_pattern(capability: str) -> re.Pattern[str]:
    mapping = {
        "shell": SHELL_CONTEXT_RE,
        "filesystem": FILESYSTEM_CONTEXT_RE,
        "network": NETWORK_CONTEXT_RE,
        "browser": BROWSER_CONTEXT_RE,
        "browser-automation": BROWSER_CONTEXT_RE,
        "file-upload": FILE_UPLOAD_OPERATIONAL_RE,
        "docker": DOCKER_CONTEXT_STRONG_RE,
        "git": GIT_CONTEXT_RE,
        "k8s": K8S_CONTEXT_RE,
        "email": EMAIL_CONTEXT_RE,
        "payment": PAYMENT_CONTEXT_RE,
        "clipboard": CLIPBOARD_CONTEXT_RE,
        "notifications": NOTIFICATION_CONTEXT_RE,
    }
    return mapping.get(capability, OPERATIONAL_CONTEXT_RE)


def _code_block_mentions_capability(doc: DocumentContext, pattern: re.Pattern[str]) -> bool:
    return any(pattern.search(block.content) for block in doc.parsed.code_blocks)


def _capability_context_strength(
    doc: DocumentContext,
    capability: str,
    pattern: re.Pattern[str],
    section: str | None,
    nearby: str,
) -> int:
    score = 0
    if _code_block_mentions_capability(doc, pattern):
        score += 1
    if OPERATIONAL_CONTEXT_RE.search(nearby) or (section and SECTION_OPERATIONAL_RE.search(section)):
        score += 1
    if _capability_context_pattern(capability).search(nearby):
        score += 1
    return score


def _find_capability_match(doc: DocumentContext, capability: str, pattern: re.Pattern[str]) -> MatchContext | None:
    corpus_like = _is_corpus_or_research_doc(doc)
    for match in pattern.finditer(doc.text):
        section = doc.parsed.section_for_offset(match.start())
        nearby = _nearby_text(doc, match.start(), match.end())
        if _suppress_capability_in_context(doc, capability, section, nearby):
            continue
        strength = _capability_context_strength(doc, capability, pattern, section, nearby)
        threshold = 2 if corpus_like or capability in {"network", "browser", "browser-automation", "email", "clipboard", "notifications", "file-upload", "payment"} else 1
        if strength < threshold:
            continue
        return MatchContext(doc=doc, start=match.start(), end=match.end(), section=section)
    return None


def _evidence_from_match(match_context: MatchContext) -> Evidence:
    return Evidence(
        doc_url=match_context.doc.meta.url,
        section=match_context.section,
        snippet=_normalized_snippet(match_context.doc.text, match_context.start, match_context.end),
    )


def _evidence_from_block(doc: DocumentContext, section: str | None, snippet: str) -> Evidence:
    return Evidence(
        doc_url=doc.meta.url,
        section=section,
        snippet=" ".join(snippet.split())[:280],
    )


def _finding(
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    evidence: Evidence,
    recommendation: list[str],
    confidence: float,
) -> Finding:
    return Finding(
        severity=severity,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=title,
        description=description,
        confidence=confidence,
        evidence=evidence,
        recommendation=recommendation,
    )


def _guardrails_present(docs: list[DocumentContext]) -> bool:
    return any(GUARDRAIL_RE.search(doc.text) for doc in docs)


def _auth_present(docs: list[DocumentContext]) -> bool:
    auth_re = re.compile(r"\b(auth|authenticate|authentication|authorization|api key|token|oauth)\b", re.IGNORECASE)
    return any(auth_re.search(doc.text) for doc in docs)


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def _is_test_context(doc: DocumentContext, section: str | None = None) -> bool:
    path_text = doc.meta.url
    title_text = doc.meta.title or ""
    section_text = section or ""
    return bool(TEST_CONTEXT_RE.search(f"{path_text} {title_text} {section_text}"))


def _has_config_secret_context(doc: DocumentContext, start: int) -> bool:
    snippet = _normalized_snippet(doc.text, start, start)
    return bool(CONFIG_CONTEXT_RE.search(f"{doc.meta.url} {snippet}"))


def _is_explicit_secret_context(doc: DocumentContext, key: str, value: str, start: int, section: str | None) -> bool:
    normalized_key = key.strip()
    if normalized_key.isupper():
        return True
    if "password" in normalized_key.lower():
        return bool(re.search(r"(?:^|[_-])password(?:$|[_-])", normalized_key, re.IGNORECASE)) and _has_config_secret_context(doc, start)
    if _has_config_secret_context(doc, start):
        return True
    if FAKE_SECRET_VALUE_RE.search(value):
        return True
    if section and CONFIG_CONTEXT_RE.search(section):
        return True
    return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    frequencies = {char: value.count(char) / length for char in set(value)}
    return -sum(probability * math.log2(probability) for probability in frequencies.values())


def _text_ranges_for_links(doc: DocumentContext) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for link in doc.parsed.links:
        index = doc.text.find(link.url)
        if index >= 0:
            ranges.append((index, index + len(link.url)))
    return ranges


def _is_in_ranges(position: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in ranges)


def _is_forbidden_secret_context(value: str) -> bool:
    lowered = value.lower()
    forbidden_tokens = ("/", "http", ".json", ".png", ".jpg", ".jpeg", ".svg", ".webp", "...")
    return any(token in lowered for token in forbidden_tokens)


def _looks_like_live_secret(value: str) -> bool:
    compact = value.strip("'\"")
    if len(compact) < 24:
        return False
    if _is_forbidden_secret_context(compact):
        return False
    if not re.search(r"[A-Za-z]", compact) or not re.search(r"\d", compact):
        return False

    for pattern in LIVE_SECRET_PREFIX_PATTERNS:
        if pattern.search(compact):
            return True

    # Generic heuristic only applies to opaque-looking strings, not readable slugs or IDs.
    if not GENERIC_LIVE_SECRET_RE.fullmatch(compact):
        return False

    return _shannon_entropy(compact) >= 4.2


def analyze_documents(docs: list[DocumentContext]) -> AnalysisResult:
    findings: list[Finding] = []
    guardrails_present = _guardrails_present(docs)
    auth_present = _auth_present(docs)
    capabilities = sorted(_detected_capabilities(docs))

    findings.extend(_remote_mutable_source_dependency(docs))
    findings.extend(_capability_flags(docs, capabilities))
    findings.extend(_ssrf_language(docs, guardrails_present))
    findings.extend(_public_exposure(docs, auth_present))
    findings.extend(_secrets_in_docs(docs))
    findings.extend(_prompt_override_language(docs))
    findings.extend(_prompt_injection_corpus(docs))
    findings.extend(_stealth_or_nondisclosure(docs))
    findings.extend(_data_exfiltration_instructions(docs))
    findings.extend(_unsafe_file_patterns(docs))
    findings.extend(_dangerous_allowlist_absence(docs, guardrails_present, capabilities))
    findings.extend(_private_ip_ssrf_mitigation_missing(docs))
    findings.extend(_redirect_following_risk(docs))
    findings.extend(_remote_install_manifest(docs))
    findings.extend(_unpinned_dependency_install(docs))
    findings.extend(_curl_pipe_shell(docs))
    findings.extend(_git_clone_main_then_run(docs))
    findings.extend(_api_proxy_route_with_key(docs))
    findings.extend(_webhook_signature_missing(docs))
    findings.extend(_oauth_scope_overreach(docs))
    findings.extend(_no_auth_for_network_service(docs))
    findings.extend(_sensitive_logging(docs))
    findings.extend(_sandbox_disable_instructions(docs))
    findings.extend(_docker_privileged_host_mount(docs))
    findings.extend(_approval_claims_without_mechanism(docs))
    findings.extend(_file_upload_capability(docs))
    findings.extend(_client_side_tools_capability(docs))
    findings.extend(_missing_guardrails(docs, guardrails_present, capabilities))

    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.title, item.rule_id))
    return AnalysisResult(findings=findings, capabilities=capabilities)


def _detected_capabilities(docs: list[DocumentContext]) -> set[str]:
    capabilities: set[str] = set()
    for capability, _rule_id, pattern, _description in CAPABILITY_PATTERNS:
        if any(_find_capability_match(doc, capability, pattern) is not None for doc in docs):
            capabilities.add(capability)
    return capabilities


def _remote_mutable_source_dependency(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        for link in doc.parsed.links:
            if not AUTHORITATIVE_LINK_RE.match(link.url):
                continue
            hint_text = f"{link.text} {link.section or ''}".lower()
            path_name = PurePosixPath(link.url).name.lower()
            if not any(hint in hint_text for hint in AUTHORITATIVE_HINTS) and path_name not in {"skill.md", "readme.md"}:
                continue
            findings.append(
                _finding(
                    severity="high",
                    rule_id="remote-mutable-source",
                    title="Remote mutable source dependency",
                    description="The docs reference instructions on a mutable main/master branch, which can change without review.",
                    evidence=Evidence(doc_url=doc.meta.url, section=link.section, snippet=f"{link.text or path_name} -> {link.url}"),
                    recommendation=[
                        "Pin authoritative documentation links to a commit SHA or versioned tag.",
                        "Treat mutable branch docs as informational, not as the source of truth for execution steps.",
                    ],
                    confidence=RULE_CONFIDENCE["deterministic"],
                )
            )
    return findings


def _capability_flags(docs: list[DocumentContext], capabilities: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for capability, rule_id, pattern, description in CAPABILITY_PATTERNS:
        if capability not in capabilities:
            continue
        for doc in docs:
            match_context = _find_capability_match(doc, capability, pattern)
            if match_context is None:
                continue
            findings.append(
                _finding(
                    severity="low",
                    rule_id=rule_id,
                    title=f"Documented capability: {capability}",
                    description=description,
                    evidence=_evidence_from_match(match_context),
                    recommendation=[
                        "Document the intended trust boundary for this capability.",
                        "Add execution constraints and examples of safe use.",
                    ],
                    confidence=RULE_CONFIDENCE["capability"],
                )
            )
            break
    return findings


def _ssrf_language(docs: list[DocumentContext], guardrails_present: bool) -> list[Finding]:
    if guardrails_present:
        return []

    for severity, pattern, description in SSRF_PATTERNS:
        for doc in docs:
            match_context = _match_in_doc(doc, pattern)
            if match_context is None:
                continue
            return [
                _finding(
                    severity=severity,
                    rule_id="ssrf-language",
                    title="Potential SSRF-style URL fetching",
                    description=description,
                    evidence=_evidence_from_match(match_context),
                    recommendation=[
                        "Require an allowlist of domains or URL schemes.",
                        "Reject link-local, private, loopback, and metadata service destinations.",
                    ],
                    confidence=RULE_CONFIDENCE["deterministic"],
                )
            ]
    return []


def _prompt_override_language(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        corpus_like = _is_prompt_injection_like_doc(doc)
        for match in PROMPT_OVERRIDE_RE.finditer(doc.text):
            match_context = MatchContext(
                doc=doc,
                start=match.start(),
                end=match.end(),
                section=doc.parsed.section_for_offset(match.start()),
            )
            if not corpus_like and not _has_nearby_keywords(doc, match_context.start, match_context.end, INSTRUCTION_CONTEXT_RE):
                continue
            severity = "high" if PROMPT_OVERRIDE_DIRECT_RE.search(match.group(0)) else "medium"
            findings.append(
                _finding(
                    severity=severity,
                    rule_id="prompt-override-language",
                    title="Prompt override or instruction tampering language",
                    description="The docs include language encouraging override of higher-priority instructions or system context.",
                    evidence=_evidence_from_match(match_context),
                    recommendation=[
                        "Remove language that instructs agents to ignore higher-priority directives.",
                        "Document explicit trust boundaries and instruction precedence instead.",
                    ],
                    confidence=0.8,
                )
            )
    return findings


def _prompt_injection_corpus(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        matched_markers: list[tuple[str, re.Match[str]]] = []
        seen_names: set[str] = set()
        for name, pattern in PROMPT_INJECTION_MARKERS:
            match = pattern.search(doc.text)
            if match is None or name in seen_names:
                continue
            seen_names.add(name)
            matched_markers.append((name, match))

        if len(matched_markers) < 2:
            continue

        has_corpus_signal = bool(PROMPT_CORPUS_MARKER_RE.search(doc.text)) or len(doc.text) >= 5000 or "readme" in doc.meta.url.lower()
        if not has_corpus_signal:
            continue

        first_match = matched_markers[0][1]
        findings.append(
            _finding(
                severity="high" if len(matched_markers) >= 3 else "medium",
                rule_id="prompt-injection-corpus",
                title="Prompt-injection or jailbreak corpus",
                description="The docs appear to collect or distribute adversarial prompt patterns intended to override model behavior.",
                evidence=Evidence(
                    doc_url=doc.meta.url,
                    section=doc.parsed.section_for_offset(first_match.start()),
                    snippet=_normalized_snippet(doc.text, first_match.start(), matched_markers[min(len(matched_markers) - 1, 1)][1].end(), window=180),
                ),
                recommendation=[
                    "Treat the content as adversarial test material rather than operational instructions.",
                    "Avoid feeding corpus entries into production agents without isolation and clear labeling.",
                    "Separate research corpora from deployable skill documentation.",
                ],
                confidence=0.7,
            )
        )
    return findings


def _stealth_or_nondisclosure(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, STEALTH_RE)
        if match_context is None:
            continue
        nearby = _nearby_text(doc, match_context.start, match_context.end)
        if UI_DEBUG_RE.search(nearby):
            continue
        if not STEALTH_ACTION_RE.search(nearby):
            continue
        severity = "high" if "do not tell the user" in nearby.lower() or "without user knowing" in nearby.lower() else "medium"
        findings.append(
            _finding(
                severity=severity,
                rule_id="stealth-or-nondisclosure",
                title="Stealth or nondisclosure instruction",
                description="The docs describe performing actions without informing the user.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Require explicit user disclosure and approval for sensitive actions.",
                    "Remove stealth-oriented language from skill instructions.",
                ],
                confidence=0.7,
            )
        )
    return findings


def _data_exfiltration_instructions(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, EXFIL_RE)
        if match_context is None:
            continue
        nearby = _nearby_text(doc, match_context.start, match_context.end)
        if not IMPERATIVE_RE.search(nearby) or not SENSITIVE_TARGET_RE.search(nearby):
            continue
        lowered = nearby.lower()
        severity = "critical" if any(token in lowered for token in ("printenv", "dump env", ".env", "~/.ssh")) else "high"
        findings.append(
            _finding(
                severity=severity,
                rule_id="data-exfiltration-instructions",
                title="Sensitive data exfiltration instructions",
                description="The docs include instructions to read, dump, or export sensitive credentials or environment data.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Remove instructions to access or export sensitive local secrets.",
                    "Constrain any diagnostic tooling to non-sensitive data and documented approval paths.",
                ],
                confidence=0.9,
            )
        )
    return findings


def _unsafe_file_patterns(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, UNSAFE_FILE_RE)
        if match_context is None:
            continue
        if not _has_nearby_keywords(doc, match_context.start, match_context.end, FILE_ACTION_RE):
            continue
        nearby = _nearby_text(doc, match_context.start, match_context.end).lower()
        severity = "high" if any(token in nearby for token in ("/etc", "~/.ssh", ".git")) else "medium"
        findings.append(
            _finding(
                severity=severity,
                rule_id="unsafe-file-patterns",
                title="Unsafe filesystem pattern or sensitive path usage",
                description="The docs reference broad filesystem scans or sensitive paths that should be tightly constrained.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Restrict file access to explicit allowlisted paths and globs.",
                    "Avoid examples that read sensitive system paths or entire repositories.",
                ],
                confidence=0.8,
            )
        )
    return findings


def _dangerous_allowlist_absence(
    docs: list[DocumentContext],
    guardrails_present: bool,
    capabilities: list[str],
) -> list[Finding]:
    if guardrails_present or "filesystem" not in capabilities:
        return []
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, re.compile(r"(/etc|~\/\.ssh|\.git\b|\*\*/\*)", re.IGNORECASE))
        if match_context is None:
            continue
        if not _has_nearby_keywords(doc, match_context.start, match_context.end, FILE_ACTION_RE):
            continue
        findings.append(
            _finding(
                severity="high",
                rule_id="dangerous-allowlist-absence",
                title="Sensitive filesystem access without allowlist guidance",
                description="The docs show sensitive filesystem access patterns without describing allowlist or denylist controls.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Document an explicit allowlist or denylist for filesystem operations.",
                    "Exclude sensitive locations such as /etc, ~/.ssh, and .git from default access.",
                ],
                confidence=0.6,
            )
        )
        break
    return findings


def _private_ip_ssrf_mitigation_missing(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, EXPLICIT_URL_FETCH_RE)
        if match_context is None:
            continue
        if PRIVATE_IP_MITIGATION_RE.search(doc.text):
            continue
        findings.append(
            _finding(
                severity="high",
                rule_id="private-ip-ssrf-mitigation-missing",
                title="Missing private IP and metadata SSRF mitigations",
                description="The docs describe user-controlled URL fetching without mentioning allowlists or localhost/private-IP blocking.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Block localhost, RFC1918, and metadata service destinations explicitly.",
                    "Require domain allowlists for user-supplied URLs.",
                ],
                confidence=0.6,
            )
        )
        break
    return findings


def _redirect_following_risk(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, REDIRECT_RE)
        if match_context is None:
            continue
        if PRIVATE_IP_MITIGATION_RE.search(doc.text):
            continue
        findings.append(
            _finding(
                severity="medium",
                rule_id="redirect-following-risk",
                title="Redirect following risk",
                description="The docs enable redirect following without describing destination allowlists or private-IP protections.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Validate redirect destinations against an allowlist.",
                    "Block redirects to localhost, private networks, and metadata services.",
                ],
                confidence=0.7,
            )
        )
        break
    return findings


def _public_exposure(docs: list[DocumentContext], auth_present: bool) -> list[Finding]:
    findings: list[Finding] = []
    for severity, pattern, description in PUBLIC_EXPOSURE_RES:
        for doc in docs:
            match_context = _match_in_doc(doc, pattern)
            if match_context is None:
                continue
            adjusted_severity = "medium" if severity == "medium" else severity
            findings.append(
                _finding(
                    severity=adjusted_severity,
                    rule_id="public-exposure",
                    title="Public exposure hint without clear auth",
                    description=description if not auth_present else "The docs expose a network service broadly; verify the authentication model is explicit.",
                    evidence=_evidence_from_match(match_context),
                    recommendation=[
                        "Bind to localhost by default for local development.",
                        "Document authentication and network exposure requirements next to the command.",
                    ],
                    confidence=RULE_CONFIDENCE["deterministic"],
                )
            )
            break
    return findings


def _secrets_in_docs(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []

    for doc in docs:
        link_ranges = _text_ranges_for_links(doc)

        for match in SECRET_ASSIGNMENT_RE.finditer(doc.text):
            key = match.group(1)
            value = match.group(2)
            section = doc.parsed.section_for_offset(match.start())
            if _is_test_context(doc, section) and not _is_explicit_secret_context(doc, key, value, match.start(), section):
                continue
            if _looks_like_live_secret(value):
                findings.append(
                    _finding(
                        severity="high",
                        rule_id="likely-live-secret",
                        title="Likely live secret in docs",
                        description="The docs include a credential-looking value that should be removed or rotated.",
                        evidence=Evidence(
                            doc_url=doc.meta.url,
                            section=section,
                            snippet=_normalized_snippet(doc.text, match.start(), match.end()),
                        ),
                        recommendation=[
                            "Rotate any real credential that appears in documentation.",
                            "Replace literal secrets with clearly fake placeholders.",
                        ],
                        confidence=RULE_CONFIDENCE["heuristic"],
                    )
                )
            else:
                if not _is_explicit_secret_context(doc, key, value, match.start(), section):
                    continue
                findings.append(
                    _finding(
                        severity="low",
                        rule_id="secret-placeholder",
                        title="Secret placeholder in docs",
                        description="The docs include a secret placeholder example. Ensure users do not replace it inline in shared docs.",
                        evidence=Evidence(
                            doc_url=doc.meta.url,
                            section=section,
                            snippet=_normalized_snippet(doc.text, match.start(), match.end()),
                        ),
                        recommendation=[
                            "Keep placeholders obviously fake.",
                            "Use local environment files or a secret manager for real values.",
                        ],
                        confidence=RULE_CONFIDENCE["heuristic"],
                    )
                )

        for match in PLACEHOLDER_SECRET_RE.finditer(doc.text):
            section = doc.parsed.section_for_offset(match.start())
            if _is_test_context(doc, section) and not _is_explicit_secret_context(doc, match.group(0), match.group(0), match.start(), section):
                continue
            findings.append(
                _finding(
                    severity="low",
                    rule_id="secret-placeholder",
                    title="Secret placeholder in docs",
                    description="The docs contain a placeholder secret token or variable example.",
                    evidence=Evidence(
                        doc_url=doc.meta.url,
                        section=section,
                        snippet=_normalized_snippet(doc.text, match.start(), match.end()),
                    ),
                    recommendation=[
                        "Keep placeholders obviously fake.",
                        "Tell users to store real values in local environment files or secret managers.",
                    ],
                    confidence=RULE_CONFIDENCE["deterministic"],
                )
            )

        token_pattern = re.compile(
            r"\b(?:ghp_[A-Za-z0-9]{24,}|gho_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16}|xoxb-[A-Za-z0-9-]{24,}|sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|bearer\s+[A-Za-z0-9._-]{24,}|[A-Za-z0-9+/=]{32,})\b",
            re.IGNORECASE,
        )
        for match in token_pattern.finditer(doc.text):
            candidate = match.group(0)
            if _is_in_ranges(match.start(), link_ranges):
                continue
            section = doc.parsed.section_for_offset(match.start())
            if FAKE_SECRET_VALUE_RE.search(candidate):
                findings.append(
                    _finding(
                        severity="low",
                        rule_id="secret-placeholder",
                        title="Secret placeholder in docs",
                        description="The docs include a test or fake credential example in a secret-like context.",
                        evidence=Evidence(
                            doc_url=doc.meta.url,
                            section=section,
                            snippet=_normalized_snippet(doc.text, match.start(), match.end()),
                        ),
                        recommendation=[
                            "Keep placeholders obviously fake.",
                            "Use local environment files or a secret manager for real values.",
                        ],
                        confidence=RULE_CONFIDENCE["heuristic"],
                    )
                )
                continue
            if _looks_like_live_secret(candidate):
                findings.append(
                    _finding(
                        severity="high",
                        rule_id="likely-live-secret",
                        title="Likely live secret in docs",
                        description="The docs contain a token-like string that looks live and should be reviewed immediately.",
                        evidence=Evidence(
                            doc_url=doc.meta.url,
                            section=section,
                            snippet=_normalized_snippet(doc.text, match.start(), match.end()),
                        ),
                        recommendation=[
                            "Rotate any credential that appears in documentation.",
                            "Replace literal tokens with clearly fake placeholders.",
                        ],
                        confidence=RULE_CONFIDENCE["heuristic"],
                    )
                )

        env_match = ENV_HINT_RE.search(doc.text)
        if env_match:
            findings.append(
                _finding(
                    severity="low",
                    rule_id="env-file-guidance",
                    title="Environment file guidance present",
                    description="The docs mention `.env` or dotenv usage. Verify the examples do not encourage storing committed secrets.",
                    evidence=Evidence(
                        doc_url=doc.meta.url,
                        section=doc.parsed.section_for_offset(env_match.start()),
                        snippet=_normalized_snippet(doc.text, env_match.start(), env_match.end()),
                    ),
                    recommendation=[
                        "Pair `.env` guidance with `.gitignore` instructions.",
                        "Keep environment examples free of real credentials.",
                    ],
                    confidence=RULE_CONFIDENCE["deterministic"],
                )
            )

    return _dedupe_findings(findings)


def _remote_install_manifest(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        for pattern in REMOTE_INSTALL_RES:
            match_context = _match_in_doc(doc, pattern)
            if match_context is None:
                continue
            snippet = _normalized_snippet(doc.text, match_context.start, match_context.end)
            severity = "high" if "curl" in snippet.lower() and "|" in snippet and (" bash" in snippet.lower() or " sh" in snippet.lower()) else "medium"
            if severity != "high" and MUTABLE_BRANCH_RE.search(snippet):
                severity = "high"
            findings.append(
                _finding(
                    severity=severity,
                    rule_id="remote-install-manifest",
                    title="Remote install manifest or script execution",
                    description=(
                        "The docs execute a remote script directly from a mutable source."
                        if severity == "high"
                        else "The docs install or load configuration directly from a remote URL."
                    ),
                    evidence=_evidence_from_match(match_context),
                    recommendation=[
                        "Prefer pinned commits, checksums, or versioned releases for install manifests.",
                        "Avoid piping remote scripts directly into a shell.",
                    ],
                    confidence=RULE_CONFIDENCE["deterministic"],
                )
            )
            break
    return findings


def _unpinned_dependency_install(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        for block in doc.parsed.code_blocks:
            content = block.content
            for match in NPM_INSTALL_RE.finditer(content):
                package = match.group(1)
                if re.search(r"@\d", package):
                    continue
                findings.append(
                    _finding(
                        severity="medium",
                        rule_id="unpinned-dependency-install",
                        title="Unpinned dependency install",
                        description="The docs install a dependency without pinning a version.",
                        evidence=_evidence_from_block(doc, block.section, content[match.start():match.end()]),
                        recommendation=[
                            "Pin package installs to explicit versions or immutable references.",
                            "Prefer reproducible installation instructions over latest or floating tags.",
                        ],
                        confidence=0.8,
                    )
                )
                break
            for match in PIP_INSTALL_RE.finditer(content):
                package = match.group(1)
                if "==" in package:
                    continue
                findings.append(
                    _finding(
                        severity="medium",
                        rule_id="unpinned-dependency-install",
                        title="Unpinned dependency install",
                        description="The docs install a Python package without pinning a version.",
                        evidence=_evidence_from_block(doc, block.section, content[match.start():match.end()]),
                        recommendation=[
                            "Pin package installs to explicit versions or immutable references.",
                            "Prefer reproducible installation instructions over floating installs.",
                        ],
                        confidence=0.8,
                    )
                )
                break
            for match in GO_GET_RE.finditer(content):
                package = match.group(1)
                if "@v" in package.lower():
                    continue
                if "@latest" not in package.lower():
                    continue
                findings.append(
                    _finding(
                        severity="medium",
                        rule_id="unpinned-dependency-install",
                        title="Unpinned dependency install",
                        description="The docs fetch a Go dependency using a floating latest reference.",
                        evidence=_evidence_from_block(doc, block.section, content[match.start():match.end()]),
                        recommendation=[
                            "Pin Go dependencies to explicit tags or commit SHAs.",
                            "Avoid @latest in setup instructions.",
                        ],
                        confidence=0.8,
                    )
                )
                break
            latest_match = LATEST_PKG_RE.search(content)
            if latest_match:
                findings.append(
                    _finding(
                        severity="medium",
                        rule_id="unpinned-dependency-install",
                        title="Unpinned dependency install",
                        description="The docs rely on a floating latest dependency reference.",
                        evidence=_evidence_from_block(doc, block.section, latest_match.group(0)),
                        recommendation=[
                            "Replace floating latest references with explicit versions.",
                            "Use immutable installation instructions for reproducibility.",
                        ],
                        confidence=0.8,
                    )
                )
                break
    return _dedupe_findings(findings)


def _curl_pipe_shell(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, CURL_PIPE_RE)
        if match_context is None:
            continue
        snippet = _evidence_from_match(match_context).snippet.lower()
        severity = "critical" if "|" in snippet or "invoke-expression" in snippet or "iex(" in snippet else "high"
        findings.append(
            _finding(
                severity=severity,
                rule_id="curl-pipe-shell",
                title="Remote content piped into a shell",
                description="The docs pipe remote content directly into a shell or expression evaluator.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Avoid piping remote downloads directly into a shell.",
                    "Download artifacts separately and verify integrity before execution.",
                ],
                confidence=0.95,
            )
        )
    return findings


def _git_clone_main_then_run(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    execution_re = re.compile(r"(\./\S+|install\.sh|setup\.sh|make install)", re.IGNORECASE)
    for doc in docs:
        for block in doc.parsed.code_blocks:
            content = block.content
            if "git clone" in content.lower() and execution_re.search(content):
                findings.append(
                    _finding(
                        severity="high",
                        rule_id="git-clone-main-then-run",
                        title="Git clone followed by immediate execution",
                        description="The docs clone repository content and then execute local scripts or install targets without verification.",
                        evidence=_evidence_from_block(doc, block.section, content),
                        recommendation=[
                            "Pin the cloned revision and verify integrity before execution.",
                            "Avoid immediate execution of freshly cloned scripts in installation docs.",
                        ],
                        confidence=0.85,
                    )
                )
                break
        if findings:
            continue
        lines = doc.text.splitlines()
        for index, line in enumerate(lines):
            if "git clone" not in line.lower():
                continue
            window = "\n".join(lines[index:index + 20])
            if execution_re.search(window):
                findings.append(
                    _finding(
                        severity="high",
                        rule_id="git-clone-main-then-run",
                        title="Git clone followed by immediate execution",
                        description="The docs clone repository content and then execute local scripts or install targets without verification.",
                        evidence=Evidence(
                            doc_url=doc.meta.url,
                            section=doc.parsed.section_for_line(index + 1),
                            snippet=" ".join(window.split())[:280],
                        ),
                        recommendation=[
                            "Pin the cloned revision and verify integrity before execution.",
                            "Separate clone instructions from execution steps unless integrity is documented.",
                        ],
                        confidence=0.85,
                    )
                )
                break
    return findings


def _api_proxy_route_with_key(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        route_match = _match_in_doc(doc, API_ROUTE_RE)
        key_match = _match_in_doc(doc, ENV_KEY_RE)
        if route_match is None or key_match is None:
            continue
        findings.append(
            _finding(
                severity="medium",
                rule_id="api-proxy-route-with-key",
                title="API proxy route with environment key",
                description="The docs describe a proxy/API route that uses an environment key. This pattern needs explicit controls to avoid turning the service into an unauthenticated proxy.",
                evidence=_evidence_from_match(route_match),
                recommendation=[
                    "Require authentication on the route.",
                    "Add rate limiting and origin restrictions.",
                    "Do not log authorization headers or upstream secrets.",
                ],
                confidence=RULE_CONFIDENCE["deterministic"],
            )
        )
    return findings


def _webhook_signature_missing(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        hook_match = _match_in_doc(doc, WEBHOOK_RE)
        if hook_match is None:
            continue
        if WEBHOOK_VERIFY_RE.search(doc.text):
            continue
        endpoint_match = _match_in_doc(doc, WEBHOOK_ENDPOINT_RE)
        severity = "high" if endpoint_match is not None else "medium"
        evidence = _evidence_from_match(endpoint_match or hook_match)
        findings.append(
            _finding(
                severity=severity,
                rule_id="webhook-signature-missing",
                title="Webhook endpoint without signature verification guidance",
                description="The docs describe a webhook or callback endpoint without mentioning signature or HMAC verification.",
                evidence=evidence,
                recommendation=[
                    "Document webhook signature or HMAC verification requirements.",
                    "Require a shared secret or signed callback validation before processing webhook payloads.",
                ],
                confidence=0.6,
            )
        )
        break
    return findings


def _oauth_scope_overreach(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        broad_match = _match_in_doc(doc, BROAD_SCOPE_RE)
        if broad_match is None:
            continue
        nearby = _nearby_text(doc, broad_match.start, broad_match.end)
        if not OAUTH_SCOPE_RE.search(nearby) and not (broad_match.section and OAUTH_SCOPE_RE.search(broad_match.section)):
            continue
        findings.append(
            _finding(
                severity="medium",
                rule_id="oauth-scope-overreach",
                title="Broad OAuth or permission scope",
                description="The docs request broad OAuth or permission scopes that may exceed least privilege.",
                evidence=_evidence_from_match(broad_match),
                recommendation=[
                    "Reduce scopes to the minimum required for the workflow.",
                    "Document why each broad scope is required.",
                ],
                confidence=0.7,
            )
        )
        break
    return findings


def _no_auth_for_network_service(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        service_match = _match_in_doc(doc, NETWORK_SERVICE_RE)
        if service_match is None:
            continue
        if AUTH_TERMS_RE.search(doc.text):
            continue
        findings.append(
            _finding(
                severity="medium",
                rule_id="no-auth-mentioned-for-network-service",
                title="Network service described without auth guidance",
                description="The docs describe a network-reachable service or endpoint without mentioning authentication or access control.",
                evidence=_evidence_from_match(service_match),
                recommendation=[
                    "Document the authentication model next to the service or endpoint instructions.",
                    "Require explicit tokens, auth middleware, or trusted network boundaries.",
                ],
                confidence=0.6,
            )
        )
        break
    return findings


def _sensitive_logging(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    sensitive_terms = re.compile(r"\b(token|api key|secret)\b", re.IGNORECASE)
    for doc in docs:
        match_context = _match_in_doc(doc, LOGGING_RE)
        if match_context is None:
            continue
        if not sensitive_terms.search(doc.text):
            continue
        findings.append(
            _finding(
                severity="medium",
                rule_id="sensitive-logging",
                title="Sensitive logging guidance",
                description="The docs encourage verbose or request/header logging in a context that also mentions tokens or secrets.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Avoid logging credentials, authorization headers, or secret-bearing requests.",
                    "Document redaction requirements for debug logging paths.",
                ],
                confidence=0.7,
            )
        )
        break
    return findings


def _sandbox_disable_instructions(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, SANDBOX_DISABLE_RE)
        if match_context is None:
            continue
        findings.append(
            _finding(
                severity="high",
                rule_id="sandbox-disable-instructions",
                title="Sandbox or runtime hardening disabled",
                description="The docs disable sandboxing or recommend high-risk runtime permissions.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Remove instructions that disable sandboxing or privileged runtime protections.",
                    "Document the least-privilege runtime configuration instead.",
                ],
                confidence=0.9,
            )
        )
    return findings


def _docker_privileged_host_mount(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, DOCKER_PRIV_RE)
        if match_context is None:
            continue
        if not _has_nearby_keywords(doc, match_context.start, match_context.end, DOCKER_CONTEXT_RE):
            continue
        findings.append(
            _finding(
                severity="critical",
                rule_id="docker-privileged-host-mount",
                title="Docker privileged mode or host mount",
                description="The docs run Docker with privileged access or mount sensitive host resources directly into the container.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Avoid --privileged and full-host mounts in routine instructions.",
                    "Use narrowly scoped mounts and least-privilege container settings instead.",
                ],
                confidence=0.95,
            )
        )
    return findings


def _approval_claims_without_mechanism(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _match_in_doc(doc, APPROVAL_CLAIM_RE)
        if match_context is None:
            continue
        if APPROVAL_MECHANISM_RE.search(doc.text):
            continue
        findings.append(
            _finding(
                severity="medium",
                rule_id="approval-claims-without-mechanism",
                title="Approval claim without mechanism",
                description="The docs claim approvals or human oversight without explaining how the approval mechanism is configured or enforced.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Document how approvals are enabled, configured, and enforced.",
                    "Include the exact approval mode or configuration required for the workflow.",
                ],
                confidence=0.6,
            )
        )
        break
    return findings


def _file_upload_capability(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        match_context = _find_capability_match(doc, "file-upload", FILE_UPLOAD_RE)
        if match_context is None:
            continue
        findings.append(
            _finding(
                severity="low",
                rule_id="file-upload-capability",
                title="File upload capability documented",
                description="The docs describe file upload handling, which requires input validation and content controls.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Restrict uploads with file type allowlists and size limits.",
                    "Scan uploaded content for malware.",
                    "Redact or quarantine sensitive uploaded data when possible.",
                ],
                confidence=RULE_CONFIDENCE["capability"],
            )
        )
        break
    return findings


def _client_side_tools_capability(docs: list[DocumentContext]) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\b(client-side tools|tool execution in browser|browser tools?)\b", re.IGNORECASE)
    for doc in docs:
        match_context = _match_in_doc(doc, pattern)
        if match_context is None:
            continue
        findings.append(
            _finding(
                severity="low",
                rule_id="client-side-tools-capability",
                title="Client-side tool execution capability",
                description="The docs describe tool execution in the browser or on the client side, which needs strict scoping and approvals.",
                evidence=_evidence_from_match(match_context),
                recommendation=[
                    "Strictly scope which tools can run client-side.",
                    "Require explicit user approval before tool execution.",
                    "Do not allow arbitrary command or script execution in the browser context.",
                ],
                confidence=RULE_CONFIDENCE["capability"],
            )
        )
        break
    return findings


def _missing_guardrails(docs: list[DocumentContext], guardrails_present: bool, capabilities: list[str]) -> list[Finding]:
    if guardrails_present:
        return []

    findings: list[Finding] = []
    for capability, rule_id, pattern, _ in CAPABILITY_PATTERNS:
        if capability not in capabilities:
            continue
        severity = "medium"
        if capability in {"shell", "filesystem", "docker", "k8s", "payment"}:
            severity = "high"
        elif capability == "email":
            severity = "medium"
        for doc in docs:
            match_context = _find_capability_match(doc, capability, pattern)
            if match_context is None:
                continue
            findings.append(
                _finding(
                    severity=severity,
                    rule_id=f"missing-guardrails-{capability}",
                    title=f"Missing guardrails for documented {capability}",
                    description=f"The docs describe {capability} capability but do not mention allowlists, sandboxing, permissions, authentication, or origin restrictions.",
                    evidence=_evidence_from_match(match_context),
                    recommendation=[
                        "Describe the approval or permission model explicitly.",
                        "Add allowlists, sandboxing constraints, authentication, and logging boundaries to the docs.",
                    ],
                    confidence=RULE_CONFIDENCE["capability"],
                )
            )
            break
    return findings


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.rule_id, finding.evidence.doc_url, finding.evidence.snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _suppress_capability_in_context(
    doc: DocumentContext,
    capability: str,
    section: str | None,
    nearby: str,
) -> bool:
    lowered = nearby.lower()
    if capability == "file-upload":
        if FILE_UPLOAD_FALSE_POSITIVE_RE.search(nearby):
            return True
        if not FILE_UPLOAD_CONTEXT_RE.search(nearby):
            return True
    if capability in {"browser", "browser-automation", "file-upload", "network"} and _is_test_context(doc, section):
        return True
    if capability in {"browser", "browser-automation"} and ("discusses" in lowered or "risks" in lowered or "example" in lowered):
        return True
    if capability == "email" and ("phrase" in lowered or "quote" in lowered):
        return True
    if capability in {"clipboard", "notifications"} and not _capability_context_pattern(capability).search(nearby):
        return True
    if _is_corpus_or_research_doc(doc) and capability in {"file-upload", "network", "browser", "browser-automation", "email", "clipboard", "notifications"}:
        return True
    return False


def _is_prompt_injection_like_doc(doc: DocumentContext) -> bool:
    marker_count = 0
    for _name, pattern in PROMPT_INJECTION_MARKERS:
        if pattern.search(doc.text):
            marker_count += 1
    return marker_count >= 2 and (PROMPT_CORPUS_MARKER_RE.search(doc.text) is not None or len(doc.text) >= 5000)


def _is_corpus_or_research_doc(doc: DocumentContext) -> bool:
    quoted_samples = len(re.findall(r"[\"'`][^\"'`]{8,}[\"'`]", doc.text))
    return bool(
        _is_prompt_injection_like_doc(doc)
        or (
            CORPUS_RESEARCH_MARKER_RE.search(doc.text) is not None
            and (quoted_samples >= 2 or len(doc.text) >= 4000)
        )
    )
