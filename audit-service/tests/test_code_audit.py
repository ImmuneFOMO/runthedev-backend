from __future__ import annotations

import asyncio
from types import SimpleNamespace

from fastapi.testclient import TestClient
import httpx
import pytest
import requests

from app.ai_triage import triage_findings
from app.ai_triage import synthesize_overall_from_triage
from app.code_audit.analyzers import analyze_codebase
from app.code_audit.file_selector import classify_file_context, select_relevant_files
from app.code_audit.github_code_fetcher import GitHubCodeFetcher
from app.code_audit.handoff import build_ai_handoff
from app.code_audit.models import GitHubCodeTarget, RepositoryEntry, ScannedCodeFile
from app.code_audit.scoring import build_code_summary
from app.main import app
from app.models import CodeEvidence, CodeFinding
from scripts.batch_code_audit import build_summary as build_batch_summary


def make_code_file(path: str, text: str, language: str | None = "python", context: str | None = None) -> ScannedCodeFile:
    return ScannedCodeFile(
        path=path,
        url=f"https://raw.githubusercontent.com/acme/demo/main/{path}",
        language=language,
        text=text,
        context=context or classify_file_context(path, text),
    )


def finding_by_rule(findings: list[object], rule_id: str) -> object:
    return next(item for item in findings if item.rule_id == rule_id)


def test_subprocess_run_with_user_input_and_shell_true_is_critical() -> None:
    code = make_code_file(
        "server.py",
        """
from fastapi import FastAPI, Request
import subprocess

app = FastAPI()

@app.post("/run")
async def run_cmd(request: Request):
    payload = await request.json()
    cmd = payload["command"]
    subprocess.run(cmd, shell=True)
""",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "command-execution")
    assert finding.severity == "critical"
    assert "user-controlled" in finding.description


def test_requests_get_with_user_url_triggers_ssrf() -> None:
    code = make_code_file(
        "proxy.py",
        """
from fastapi import FastAPI, Request
import requests

app = FastAPI()

@app.post("/fetch")
async def fetch_anything(request: Request):
    payload = await request.json()
    user_url = payload["url"]
    return requests.get(user_url).text
""",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "ssrf-fetch")
    assert finding.severity == "critical"


def test_fixed_base_url_with_user_query_params_does_not_trigger_ssrf() -> None:
    code = make_code_file(
        "src/services/api.ts",
        """
const DATA_API_URL = "https://api.example.com";

export async function listPositions(params: string) {
  return fetch(`${DATA_API_URL}/positions?${params}`);
}
""",
        language="typescript",
        context="mcp",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "ssrf-fetch" for item in result.findings)


def test_fixed_literal_google_maps_url_does_not_trigger_ssrf() -> None:
    code = make_code_file(
        "src/google-maps/index.ts",
        """
export async function geocode(address: string) {
  const url = new URL("https://maps.googleapis.com/maps/api/geocode/json");
  url.searchParams.append("address", address);
  url.searchParams.append("key", GOOGLE_MAPS_API_KEY);
  return fetch(url.toString());
}
""",
        language="typescript",
        context="mcp",
    )

    result = analyze_codebase([code])
    findings = [item for item in result.findings if item.rule_id == "ssrf-fetch"]
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_oauth_token_exchange_does_not_trigger_ssrf() -> None:
    code = make_code_file(
        "src/mcp_atlassian/utils/oauth.py",
        """
class OAuthClient:
    def refresh(self, payload):
        logger.debug(f"Refreshing access token at {self.token_url}")
        return requests.post(self.token_url, data=payload, timeout=30)
""",
        context="mcp",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "ssrf-fetch" for item in result.findings)


def test_webhook_handler_without_signature_verification_triggers() -> None:
    code = make_code_file(
        "webhook.py",
        """
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/webhook/github")
async def github_webhook(request: Request):
    payload = await request.json()
    return {"ok": True, "event": payload.get("action")}
""",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "missing-webhook-verification")
    assert finding.severity == "high"


def test_usecallback_does_not_trigger_webhook_detection() -> None:
    code = make_code_file(
        "docs-site/src/components/SkillCard.tsx",
        """
import { useCallback } from "react";

export function SkillCard() {
  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText("ok");
  }, []);
  return null;
}
""",
        language="tsx",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "missing-webhook-verification" for item in result.findings)


def test_docker_socket_mount_is_critical() -> None:
    code = make_code_file(
        "docker-compose.yml",
        """
services:
  app:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""",
        language="yaml",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "unsafe-docker-runtime")
    assert finding.severity == "critical"


def test_hardcoded_token_detection() -> None:
    code = make_code_file(
        "config.py",
        'GITHUB_TOKEN = "ghp_1234567890abcdefghij1234567890"\n',
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "hardcoded-secret")
    assert finding.severity == "critical"


def test_hardcoded_secret_suppressed_in_lockfile() -> None:
    code = make_code_file(
        "package-lock.json",
        '{"token":"ghp_1234567890abcdefghij1234567890"}',
        language="json",
        context="library",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "hardcoded-secret" for item in result.findings)


def test_env_secret_interpolation_does_not_trigger_hardcoded_secret() -> None:
    code = make_code_file(
        ".github/workflows/release.yml",
        """
env:
  GITHUB_MCP_SERVER_TOKEN: ${GITHUB_MCP_SERVER_TOKEN}
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
""",
        language="yaml",
        context="ci",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "hardcoded-secret" for item in result.findings)


def test_templated_auth_token_ui_value_does_not_trigger_hardcoded_secret() -> None:
    code = make_code_file(
        "packages/extension/src/ui/authToken.tsx",
        """
const config = {
  env: {
    "PLAYWRIGHT_MCP_EXTENSION_TOKEN": "${authToken}"
  }
};
""",
        language="tsx",
        context="mcp",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "hardcoded-secret" for item in result.findings)


def test_secret_like_type_name_does_not_trigger_hardcoded_secret() -> None:
    code = make_code_file(
        "src/mcp_atlassian/utils/oauth.py",
        'def from_env() -> Optional["BYOAccessTokenOAuthConfig"]:\n    pass\n',
        context="mcp",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "hardcoded-secret" for item in result.findings)


def test_command_execution_ignores_comments_strings_and_types() -> None:
    code = make_code_file(
        "server.ts",
        """
// subprocess.run(userInput)
const example = "exec(payload)";
type Proc = subprocess.Popen;
interface ExecConfig { command: string; }
""",
        language="typescript",
        context="server",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "command-execution" for item in result.findings)


def test_authless_route_handler_triggers() -> None:
    code = make_code_file(
        "api.py",
        """
from fastapi import FastAPI

app = FastAPI()

@app.get("/records")
async def records():
    return {"ok": True}
""",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "auth-missing-on-network-service")
    assert finding.severity == "medium"


def test_authless_route_handler_clusters_repeated_routes() -> None:
    code = make_code_file(
        "server.py",
        """
from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
async def list_items():
    return []

@app.post("/items")
async def create_item():
    return {}

@app.delete("/items/{item_id}")
async def delete_item(item_id: str):
    return {"id": item_id}
""",
    )

    result = analyze_codebase([code])
    findings = [item for item in result.findings if item.rule_id == "auth-missing-on-network-service"]
    assert len(findings) == 3
    assert len({item.cluster_id for item in findings}) == 1
    assert sum(1 for item in findings if item.cluster_role == "primary") == 1
    assert all(item.cluster_size == 3 for item in findings)


def test_auth_missing_suppressed_for_public_docs_routes() -> None:
    code = make_code_file(
        "server.ts",
        """
import express from "express";

const app = express();

app.get("/openapi.json", (_req, res) => {
  res.json({});
});

app.get("/status", (_req, res) => {
  res.json({ ok: true });
});
""",
        language="typescript",
        context="server",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "auth-missing-on-network-service" for item in result.findings)


def test_auth_missing_not_emitted_for_non_entrypoint_module() -> None:
    code = make_code_file(
        "utils/routes.py",
        """
from fastapi import APIRouter

router = APIRouter()

@router.get("/status")
async def status():
    return {"ok": True}
""",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "auth-missing-on-network-service" for item in result.findings)


def test_repo_local_package_metadata_read_is_not_arbitrary_file_access() -> None:
    code = make_code_file(
        "program.ts",
        """
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const packageJSONPath = path.join(__dirname, "..", "package.json");
const packageJSONBuffer = fs.readFileSync(packageJSONPath);
""",
        language="typescript",
    )

    result = analyze_codebase([code])
    rule_ids = {item.rule_id for item in result.findings}
    assert "arbitrary-file-read" not in rule_ids
    assert "arbitrary-file-write" not in rule_ids
    assert "arbitrary-file-delete" not in rule_ids
    assert "tool-approval-missing" not in rule_ids


def test_file_url_to_path_alone_is_not_file_access() -> None:
    code = make_code_file(
        "program.ts",
        """
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
""",
        language="typescript",
    )

    result = analyze_codebase([code])
    rule_ids = {item.rule_id for item in result.findings}
    assert "arbitrary-file-read" not in rule_ids
    assert "arbitrary-file-write" not in rule_ids
    assert "arbitrary-file-delete" not in rule_ids
    assert "tool-approval-missing" not in rule_ids


def test_user_controlled_file_read_still_triggers_arbitrary_file_access() -> None:
    code = make_code_file(
        "reader.ts",
        """
import fs from "node:fs";
import express from "express";

const app = express();

app.get("/read", (req, res) => {
  const filePath = req.query.path;
  const content = fs.readFileSync(filePath, "utf8");
  res.send(content);
});
""",
        language="typescript",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "arbitrary-file-read")
    assert finding.severity == "high"
    assert finding.op_type == "read"


def test_cli_script_path_argument_without_server_exposure_is_not_high_risk_file_access() -> None:
    code = make_code_file(
        "scripts/quick_validate.py",
        """
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--skill-path")
args = parser.parse_args()
skill_path = Path(args.skill_path)
content = skill_path.read_text()
""",
        language="python",
    )

    result = analyze_codebase([code])
    file_findings = [item for item in result.findings if item.rule_id == "arbitrary-file-read"]
    assert file_findings == []
    assert all(item.rule_id != "tool-approval-missing" for item in result.findings)


def test_cli_output_write_is_not_high_severity() -> None:
    code = make_code_file(
        "scripts/report.py",
        """
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output")
args = parser.parse_args()
Path(args.output).write_text("ok")
""",
        language="python",
        context="cli",
    )

    result = analyze_codebase([code])
    findings = [item for item in result.findings if item.rule_id == "arbitrary-file-write"]
    assert findings == []


def test_delete_sink_uses_delete_rule_and_op_type() -> None:
    code = make_code_file(
        "api.py",
        """
from fastapi import FastAPI, Request
import os

app = FastAPI()

@app.post("/delete")
async def delete_file(request: Request):
    payload = await request.json()
    os.remove(payload["path"])
""",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "arbitrary-file-delete")
    assert finding.severity == "high"
    assert finding.op_type == "delete"


def test_hooks_json_does_not_trigger_webhook_verification() -> None:
    code = make_code_file(
        "hooks.json",
        """
{
  "hooks": [
    {
      "event": "postinstall",
      "script": "./scripts/setup.sh"
    }
  ]
}
""",
        language="json",
        context="library",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "missing-webhook-verification" for item in result.findings)


def test_file_selector_skips_docs_frontend_and_generated_noise() -> None:
    selected = select_relevant_files(
        [
            RepositoryEntry(path="docs/_astro/client.Dc9Vh3na.js", type="file"),
            RepositoryEntry(path="docs-site/src/components/SkillCard.tsx", type="file"),
            RepositoryEntry(path="src/server.ts", type="file"),
            RepositoryEntry(path=".vscode/mcp.json", type="file"),
            RepositoryEntry(path="src/tools/session.ts", type="file"),
        ],
        max_files=10,
        include_tests=False,
        include_ci=False,
    )

    assert [item.path for item in selected] == [".vscode/mcp.json", "src/server.ts", "src/tools/session.ts"]


def test_file_selector_excludes_ci_by_default() -> None:
    selected = select_relevant_files(
        [
            RepositoryEntry(path=".github/workflows/release.yml", type="file"),
            RepositoryEntry(path=".github/actions/custom/action.yml", type="file"),
            RepositoryEntry(path="src/server.ts", type="file"),
        ],
        max_files=10,
        include_tests=False,
        include_ci=False,
    )

    assert [item.path for item in selected] == ["src/server.ts"]


def test_file_selector_skips_generated_react_router_types() -> None:
    selected = select_relevant_files(
        [
            RepositoryEntry(path=".react-router/types/app/routes/+types/_index.ts", type="file"),
            RepositoryEntry(path=".react-router/types/app/routes/+types/api.chat.ts", type="file"),
            RepositoryEntry(path="src/index.ts", type="file"),
        ],
        max_files=10,
        include_tests=False,
        include_ci=False,
    )

    assert [item.path for item in selected] == ["src/index.ts"]


def test_ai_handoff_respects_cap_and_priority() -> None:
    findings = [
        CodeFinding(
            severity="medium",
            rule_id="hardcoded-secret",
            title="Hardcoded credential or token",
            description="secret",
            confidence=0.8,
            evidence=CodeEvidence(file_path="a.py", line=10, snippet='TOKEN = "ghp_1234567890abcdefghij1234567890"'),
            recommendation=["remove"],
            cluster_id="hardcoded-secret:a.py:ghp",
            cluster_size=1,
            cluster_role="primary",
            context="library",
            nearby_context='TOKEN = "ghp_1234567890abcdefghij1234567890"',
        ),
        CodeFinding(
            severity="critical",
            rule_id="ssrf-fetch",
            title="Potential SSRF or arbitrary URL fetch",
            description="ssrf",
            confidence=0.9,
            evidence=CodeEvidence(file_path="server.py", line=20, snippet="return requests.get(user_url).text"),
            recommendation=["allowlist"],
            cluster_id="ssrf-fetch:server.py:requests.get:/api",
            cluster_size=2,
            cluster_role="primary",
            context="mcp",
            nearby_context='user_url = payload["url"]\nreturn requests.get(user_url).text',
        ),
        CodeFinding(
            severity="high",
            rule_id="command-execution",
            title="Unsafe command execution",
            description="exec",
            confidence=0.85,
            evidence=CodeEvidence(file_path="server.py", line=40, snippet="subprocess.run(cmd, shell=True)"),
            recommendation=["avoid shell"],
            cluster_id="command-execution:server.py:subprocess.run:shell_true",
            cluster_size=1,
            cluster_role="primary",
            context="mcp",
            nearby_context='cmd = payload["command"]\nsubprocess.run(cmd, shell=True)',
        ),
    ]

    handoff = build_ai_handoff(findings, ["network", "shell"], max_items=2)

    assert handoff.max_items == 2
    assert len(handoff.items) == 2
    assert handoff.items[0].rule_id == "ssrf-fetch"
    assert handoff.items[1].rule_id == "command-execution"
    assert handoff.stats.dropped_total == 1
    assert handoff.stats.dropped_by_rule == {"hardcoded-secret": 1}


def test_ai_handoff_includes_path_area_for_experiment_files() -> None:
    findings = [
        CodeFinding(
            severity="high",
            rule_id="command-execution",
            title="Unsafe command execution",
            description="exec",
            confidence=0.85,
            evidence=CodeEvidence(file_path="tools/experiments/validation_fixed.py", line=40, snippet='subprocess.run(["make", "help"])'),
            recommendation=["avoid shell"],
            cluster_id="command-execution:tools/experiments/validation_fixed.py:subprocess.run:shell_false",
            cluster_size=1,
            cluster_role="primary",
            context="library",
            nearby_context='result = subprocess.run(["make", "help"], capture_output=True, text=True)',
        ),
    ]

    handoff = build_ai_handoff(findings, ["shell"], max_items=5)

    assert handoff.items[0].taint_summary.path_area == "experiments"
    assert handoff.items[0].taint_summary.is_probably_exposed is False


def test_overall_safety_downweights_low_exposure_command_execution_clusters() -> None:
    finding = CodeFinding(
        severity="high",
        rule_id="command-execution",
        title="Unsafe command execution",
        description="exec",
        confidence=0.85,
        evidence=CodeEvidence(file_path="tools/experiments/validation_fixed.py", line=40, snippet='subprocess.run(["make", "help"])'),
        recommendation=["avoid shell"],
        cluster_id="command-execution:tools/experiments/validation_fixed.py:subprocess.run:shell_false",
        cluster_size=1,
        cluster_role="primary",
        context="library",
        nearby_context='result = subprocess.run(["make", "help"], capture_output=True, text=True)',
    )

    overall = synthesize_overall_from_triage(
        [finding],
        [
            {
                "cluster_id": finding.cluster_id,
                "action": "keep",
                "risk": "high",
                "confidence": 0.9,
                "reason": "command execution present",
            }
        ],
    )

    assert overall is not None
    assert overall["risk"] == "medium"


def test_overall_safety_downgrades_ssrf_without_strong_url_taint() -> None:
    finding = CodeFinding(
        severity="critical",
        rule_id="ssrf-fetch",
        title="Potential SSRF or arbitrary URL fetch",
        description="ssrf",
        confidence=0.9,
        evidence=CodeEvidence(file_path="src/services/api.ts", line=82, snippet="const res = await fetch(url);"),
        recommendation=["allowlist"],
        cluster_id="ssrf-fetch:src/services/api.ts:fetch:unknown",
        cluster_size=1,
        cluster_role="primary",
        context="mcp",
        nearby_context="const url = `${DATA_API_URL}/positions?${params}`;\nconst res = await fetch(url);",
    )

    overall = synthesize_overall_from_triage(
        [finding],
        [
            {
                "cluster_id": finding.cluster_id,
                "action": "keep",
                "risk": "critical",
                "confidence": 0.9,
                "reason": "network fetch present",
            }
        ],
    )

    assert overall is not None
    assert overall["risk"] == "high"


def test_overall_safety_keeps_ssrf_critical_with_strong_url_taint() -> None:
    finding = CodeFinding(
        severity="critical",
        rule_id="ssrf-fetch",
        title="Potential SSRF or arbitrary URL fetch",
        description="ssrf",
        confidence=0.92,
        evidence=CodeEvidence(file_path="server.py", line=10, snippet="return requests.get(user_url).text"),
        recommendation=["allowlist"],
        cluster_id="ssrf-fetch:server.py:requests.get:/api",
        cluster_size=1,
        cluster_role="primary",
        context="mcp",
        nearby_context='payload = await request.json()\nuser_url = payload["url"]\nreturn requests.get(user_url).text',
    )

    overall = synthesize_overall_from_triage(
        [finding],
        [
            {
                "cluster_id": finding.cluster_id,
                "action": "keep",
                "risk": "critical",
                "confidence": 0.92,
                "reason": "user-controlled full URL fetch",
            }
        ],
    )

    assert overall is not None
    assert overall["risk"] == "critical"


def test_cli_findings_are_downweighted_in_summary() -> None:
    cli_file = make_code_file(
        "scripts/report.py",
        """
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("--output")
args = parser.parse_args()
Path(args.output).write_text("ok")
""",
        language="python",
        context="cli",
    )
    server_file = make_code_file(
        "api.py",
        """
from fastapi import FastAPI, Request
import requests
app = FastAPI()
@app.post("/fetch")
async def fetch_anything(request: Request):
    payload = await request.json()
    return requests.get(payload["url"]).text
""",
        language="python",
        context="server",
    )

    cli_result = analyze_codebase([cli_file])
    server_result = analyze_codebase([server_file])
    cli_summary, _ = build_code_summary(cli_result.findings, cli_result.capabilities, [cli_file])
    server_summary, _ = build_code_summary(server_result.findings, server_result.capabilities, [server_file])

    assert cli_summary.risk_score < server_summary.risk_score


def test_path_traversal_triggers_on_dot_dot_without_mitigation() -> None:
    code = make_code_file(
        "api.py",
        """
from fastapi import FastAPI, Request
from pathlib import Path

app = FastAPI()
BASE_DIR = Path("/tmp/uploads")

@app.post("/download")
async def download(request: Request):
    payload = await request.json()
    target = BASE_DIR / payload["filename"] / "../secret.txt"
    return target.read_text()
""",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "path-traversal")
    assert finding.severity == "high"


def test_path_traversal_docstring_endpoint_example_is_suppressed() -> None:
    code = make_code_file(
        "src/mcp_atlassian/jira/forms_api.py",
        '''
def api_request(method, endpoint):
    """
    Args:
        endpoint: API endpoint path (e.g., '/issue/PROJ-123/form')
    """
    return endpoint
''',
        context="mcp",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "path-traversal" for item in result.findings)


def test_path_traversal_suppressed_by_base_dir_check() -> None:
    code = make_code_file(
        "api.py",
        """
from fastapi import FastAPI, Request
from pathlib import Path

app = FastAPI()
BASE_DIR = Path("/tmp/uploads").resolve()

@app.post("/download")
async def download(request: Request):
    payload = await request.json()
    target = (BASE_DIR / payload["filename"]).resolve()
    if not target.is_relative_to(BASE_DIR):
        raise ValueError("invalid path")
    return target.read_text()
""",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "path-traversal" for item in result.findings)


def test_path_traversal_suppressed_for_static_repo_local_config_path() -> None:
    code = make_code_file(
        "vite.config.ts",
        """
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const docsPath = resolve(__dirname, "../docs/site");
""",
        language="typescript",
        context="library",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "path-traversal" for item in result.findings)


def test_static_relative_import_does_not_trigger_path_traversal() -> None:
    code = make_code_file(
        "src/api/tools/repoHandlers/handlers.ts",
        """
import type { RepoData, UrlType } from "../../../shared/repoData.js";
import type { RepoHandler } from "./RepoHandler.js";
import { getDefaultRepoHandler } from "./DefaultRepoHandler.js";
""",
        language="typescript",
        context="library",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "path-traversal" for item in result.findings)


def test_multipart_upload_wrapper_does_not_trigger_arbitrary_file_read() -> None:
    code = make_code_file(
        "src/mcp_atlassian/confluence/attachments.py",
        """
def upload_file(file_path, filename):
    # Prepare multipart form data
    files = {"file": (filename, open(file_path, "rb"))}
    return files
""",
        context="mcp",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "arbitrary-file-read" for item in result.findings)


def test_multiline_import_tail_does_not_trigger_path_traversal() -> None:
    code = make_code_file(
        "src/api/tools/repoHandlers/DefaultRepoHandler.ts",
        """
import {
  generateSearchToolName,
  generateSearchToolDescription,
} from "../commonTools.js";
import type { RepoData } from "../../../shared/repoData.js";
""",
        language="typescript",
        context="library",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "path-traversal" for item in result.findings)


def test_typeof_import_does_not_trigger_path_traversal() -> None:
    code = make_code_file(
        ".react-router/types/app/routes/+types/api.chat.ts",
        """
import type { Info as Parent0 } from "../../+types/root.js";

type Module = typeof import("../api.chat.js")
""",
        language="typescript",
        context="library",
    )

    result = analyze_codebase([code])
    assert all(item.rule_id != "path-traversal" for item in result.findings)


def test_file_access_clustering_keeps_at_most_three_evidence_items() -> None:
    repeated_lines = "\n".join([f'    fs.writeFileSync(outputPath, "item-{i}")' for i in range(21)])
    code = make_code_file(
        "api.ts",
        f"""
import express from "express";
import fs from "node:fs";

const app = express();

app.post("/save", (req, res) => {{
    const outputPath = req.body.path;
{repeated_lines}
    res.send("ok");
}});
""",
        language="typescript",
    )

    result = analyze_codebase([code])
    clustered = [item for item in result.findings if item.rule_id == "arbitrary-file-write"]
    assert clustered
    assert len({item.cluster_id for item in clustered}) == 1
    assert sum(1 for item in clustered if item.cluster_role == "primary") == 1
    assert all(item.cluster_size == len(clustered) for item in clustered)


def test_risk_score_is_cluster_based_for_repeated_file_sinks() -> None:
    repeated_lines = "\n".join([f'    fs.writeFileSync(outputPath, "item-{i}")' for i in range(21)])
    repeated_file = make_code_file(
        "api.ts",
        f"""
import express from "express";
import fs from "node:fs";

const app = express();
app.post("/save", (req, res) => {{
    const outputPath = req.body.path;
{repeated_lines}
    res.send("ok");
}});
""",
        language="typescript",
    )
    distinct_file = make_code_file(
        "api2.ts",
        """
import express from "express";
import fs from "node:fs";

const app = express();
app.post("/save", (req, res) => {
    const readPath = req.body.read_path;
    const writePath = req.body.write_path;
    const deletePath = req.body.delete_path;
    fs.readFileSync(readPath, "utf8");
    fs.writeFileSync(writePath, "ok");
    fs.rmSync(deletePath);
    res.send("ok");
});
""",
        language="typescript",
    )

    repeated_result = analyze_codebase([repeated_file])
    distinct_result = analyze_codebase([distinct_file])
    repeated_summary, _ = build_code_summary(repeated_result.findings, repeated_result.capabilities, [repeated_file])
    distinct_summary, _ = build_code_summary(distinct_result.findings, distinct_result.capabilities, [distinct_file])

    assert repeated_summary.risk_score < 100
    assert distinct_summary.risk_score >= repeated_summary.risk_score


def test_tool_approval_missing_suppressed_when_file_action_only_medium_and_untainted() -> None:
    code = make_code_file(
        "server.py",
        """
from fastapi import FastAPI
from pathlib import Path

app = FastAPI()

@app.post("/render")
async def render():
    output_path = Path("out.txt")
    output_path.write_text("ok")
    return {"ok": True}
""",
    )

    result = analyze_codebase([code])
    finding = finding_by_rule(result.findings, "arbitrary-file-write")
    assert finding.severity == "medium"
    assert all(item.rule_id != "tool-approval-missing" for item in result.findings)


def test_repo_url_fetcher_selects_relevant_files_and_skips_tests() -> None:
    async def run() -> None:
        class StubCodeFetcher(GitHubCodeFetcher):
            async def _default_branch(self, owner: str, repo: str) -> str:
                assert owner == "acme"
                assert repo == "demo"
                return "main"

            async def _contents(self, owner: str, repo: str, ref: str, path: str) -> object:
                listing = {
                    "": [
                        {"type": "dir", "path": "src"},
                        {"type": "dir", "path": "tests"},
                        {"type": "file", "path": "README.md"},
                    ],
                    "src": [
                        {"type": "file", "path": "src/server.py"},
                        {"type": "file", "path": "src/helper.py"},
                    ],
                    "tests": [
                        {"type": "file", "path": "tests/test_server.py"},
                    ],
                }
                return listing[path]

            async def _fetch_raw_text(self, target: GitHubCodeTarget, path: str) -> str:
                sources = {
                    "src/server.py": "import subprocess\n",
                    "src/helper.py": "print('ok')\n",
                }
                return sources[path]

        async with StubCodeFetcher() as fetcher:
            target, files = await fetcher.fetch_code_files(
                "https://github.com/acme/demo",
                max_files=5,
                max_total_chars=1000,
                include_tests=False,
                include_ci=False,
            )

        assert target.root_target == "acme/demo@main"
        assert [item.path for item in files] == ["src/server.py", "src/helper.py"]
        assert files[0].context == "library"

    asyncio.run(run())


def test_audit_code_endpoint_returns_structured_report(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_code_files(
        self: GitHubCodeFetcher,
        url: str,
        *,
        max_files: int,
        max_total_chars: int,
        include_tests: bool,
        include_ci: bool,
    ):
        return (
            GitHubCodeTarget(owner="acme", repo="demo", ref="main", path="", target_kind="repo"),
            [
                make_code_file(
                    "server.py",
                    """
from fastapi import FastAPI, Request
import requests

app = FastAPI()

@app.post("/fetch")
async def fetch_anything(request: Request):
    payload = await request.json()
    return requests.get(payload["url"]).text
""",
                )
            ],
        )

    monkeypatch.setattr(GitHubCodeFetcher, "fetch_code_files", fake_fetch_code_files)

    client = TestClient(app)
    response = client.post(
        "/audit/code",
        json={
            "url": "https://github.com/acme/demo",
            "max_files": 40,
            "max_total_chars": 400000,
            "include_tests": False,
            "include_ci": False,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["root_target"] == "acme/demo@main"
    assert payload["scanned_files"][0]["path"] == "server.py"
    assert payload["scanned_files"][0]["context"] == "server"
    assert any(item["rule_id"] == "ssrf-fetch" for item in payload["findings"])
    assert payload["overall_safety"]["source"] == "deterministic"
    assert payload["overall_safety"]["risk"] in {"critical", "high", "medium", "low", "none"}


def test_audit_code_endpoint_filters_ai_likely_false_positives_from_response(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_code_files(
        self: GitHubCodeFetcher,
        url: str,
        *,
        max_files: int,
        max_total_chars: int,
        include_tests: bool,
        include_ci: bool,
    ):
        return (
            GitHubCodeTarget(owner="acme", repo="demo", ref="main", path="", target_kind="repo"),
            [
                make_code_file("server.py", "export default {};", language="typescript", context="mcp"),
            ],
        )

    def fake_analyze_codebase(_files: list[ScannedCodeFile]) -> SimpleNamespace:
        findings = [
            CodeFinding(
                severity="critical",
                rule_id="ssrf-fetch",
                title="Potential SSRF or arbitrary URL fetch",
                description="Network fetch logic appears to use a caller-controlled URL without visible allowlist or private-IP protections.",
                confidence=0.92,
                evidence=CodeEvidence(file_path="server.py", line=10, snippet="return fetch(userUrl)"),
                recommendation=["Require an allowlist of trusted upstreams before making outbound requests."],
                cluster_id="ssrf-fetch:server.py:fetch:/api",
                cluster_size=1,
                cluster_role="primary",
                context="mcp",
                nearby_context="const userUrl = payload.url;\nreturn fetch(userUrl);",
            ),
            CodeFinding(
                severity="medium",
                rule_id="path-traversal",
                title="Path traversal risk",
                description="Path-building logic appears vulnerable to traversal or base-directory escape without a visible containment check.",
                confidence=0.74,
                evidence=CodeEvidence(file_path="server.py", line=20, snippet='import type { Info } from "../../+types/root.js"'),
                recommendation=["Canonicalize the resolved path and verify it stays inside a fixed base directory."],
                cluster_id="path-traversal:server.py:import",
                cluster_size=1,
                cluster_role="primary",
                context="library",
                nearby_context='import type { Info } from "../../+types/root.js"',
            ),
        ]
        return SimpleNamespace(findings=findings, capabilities=["network"])

    monkeypatch.setattr(GitHubCodeFetcher, "fetch_code_files", fake_fetch_code_files)
    monkeypatch.setattr("app.main.analyze_codebase", fake_analyze_codebase)
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.main.triage_findings",
        lambda findings, _model, _batch_size, _budget_mode: {
            "results": [
                {"cluster_id": "ssrf-fetch:server.py:fetch:/api", "action": "keep", "risk": "high", "confidence": 0.8, "reason": ""},
                {"cluster_id": "path-traversal:server.py:import", "action": "suppress", "risk": "low", "confidence": 0.95, "reason": "static import"},
            ],
            "suppressed_cluster_ids": {"path-traversal:server.py:import"},
            "group_count": 2,
            "classified_group_count": 2,
        },
    )

    client = TestClient(app)
    response = client.post(
        "/audit/code",
        json={
            "url": "https://github.com/acme/demo",
            "max_files": 40,
            "max_total_chars": 400000,
            "include_tests": False,
            "include_ci": False,
            "ai_classify": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert [item["rule_id"] for item in payload["findings"]] == ["ssrf-fetch"]
    assert payload["ai_handoff"]["stats"]["total_clusters"] == 2
    assert payload["summary"]["counts"]["critical"] == 0
    assert payload["summary"]["counts"]["high"] == 1
    assert payload["summary"]["counts"]["medium"] == 0
    assert payload["pre_ai_summary"]["counts"]["medium"] == 1
    assert payload["ai_triage"]["filtered_out_count"] == 1
    assert len(payload["ai_triage"]["results"]) == 2
    assert payload["ai_triage"]["results"][0]["action"] == "keep"
    assert payload["ai_triage"]["results"][1]["action"] == "suppress"
    assert len(payload["ai_triage"]["suppressed_findings"]) == 1
    assert len(payload["ai_suppressed_clusters"]) == 1
    assert payload["ai_suppressed_clusters"][0]["cluster_id"] == "path-traversal:server.py:import"
    assert payload["overall_safety"]["source"] == "ai_combined"
    assert payload["overall_safety"]["verdict"] == "unsafe"
    assert payload["overall_safety"]["risk"] == "high"


def test_audit_code_endpoint_reports_safe_when_ai_filters_out_all_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_code_files(
        self: GitHubCodeFetcher,
        url: str,
        *,
        max_files: int,
        max_total_chars: int,
        include_tests: bool,
        include_ci: bool,
    ):
        return (
            GitHubCodeTarget(owner="acme", repo="demo", ref="main", path="", target_kind="repo"),
            [
                make_code_file("server.py", "export default {};", language="typescript", context="library"),
            ],
        )

    def fake_analyze_codebase(_files: list[ScannedCodeFile]) -> SimpleNamespace:
        findings = [
            CodeFinding(
                severity="medium",
                rule_id="path-traversal",
                title="Path traversal risk",
                description="Path-building logic appears vulnerable to traversal or base-directory escape without a visible containment check.",
                confidence=0.74,
                evidence=CodeEvidence(file_path="server.py", line=20, snippet='import type { Info } from "../../+types/root.js"'),
                recommendation=["Canonicalize the resolved path and verify it stays inside a fixed base directory."],
                cluster_id="path-traversal:server.py:import",
                cluster_size=1,
                cluster_role="primary",
                context="library",
                nearby_context='import type { Info } from "../../+types/root.js"',
            ),
        ]
        return SimpleNamespace(findings=findings, capabilities=[])

    monkeypatch.setattr(GitHubCodeFetcher, "fetch_code_files", fake_fetch_code_files)
    monkeypatch.setattr("app.main.analyze_codebase", fake_analyze_codebase)
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.main.triage_findings",
        lambda findings, _model, _batch_size, _budget_mode: {
            "results": [
                {"cluster_id": "path-traversal:server.py:import", "action": "suppress", "risk": "low", "confidence": 0.9, "reason": "generated code"},
            ],
            "suppressed_cluster_ids": {"path-traversal:server.py:import"},
            "group_count": 1,
            "classified_group_count": 1,
        },
    )

    client = TestClient(app)
    response = client.post(
        "/audit/code",
        json={
            "url": "https://github.com/acme/demo",
            "max_files": 40,
            "max_total_chars": 400000,
            "include_tests": False,
            "include_ci": False,
            "ai_classify": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["findings"] == []
    assert payload["summary"]["risk_score"] == 0
    assert payload["pre_ai_summary"]["risk_score"] > 0
    assert payload["coverage_scope"]["version"] == "scope-v1"
    assert "ssrf-fetch" in payload["coverage_scope"]["supported_rules"]
    assert payload["clusters"]["primary"] == []
    assert len(payload["clusters"]["suppressed"]) == 1
    assert payload["ai_triage"]["filtered_out_count"] == 1
    assert len(payload["ai_triage"]["suppressed_findings"]) == 1
    assert len(payload["ai_suppressed_clusters"]) == 1
    assert payload["overall_safety"]["source"] == "ai_combined"
    assert payload["overall_safety"]["verdict"] == "safe"
    assert payload["overall_safety"]["risk"] == "none"


def test_audit_code_summary_endpoint_returns_compact_view(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_code_files(
        self: GitHubCodeFetcher,
        url: str,
        *,
        max_files: int,
        max_total_chars: int,
        include_tests: bool,
        include_ci: bool,
    ):
        return (
            GitHubCodeTarget(owner="acme", repo="demo", ref="main", path="", target_kind="repo"),
            [make_code_file("server.py", "export default {};", language="typescript", context="mcp")],
        )

    def fake_analyze_codebase(_files: list[ScannedCodeFile]) -> SimpleNamespace:
        findings = [
            CodeFinding(
                severity="critical",
                rule_id="ssrf-fetch",
                title="Potential SSRF or arbitrary URL fetch",
                description="ssrf",
                confidence=0.92,
                evidence=CodeEvidence(file_path="server.py", line=10, snippet="return fetch(userUrl)"),
                recommendation=["allowlist"],
                cluster_id="ssrf-fetch:server.py:fetch:/api",
                cluster_size=1,
                cluster_role="primary",
                context="mcp",
                nearby_context='const userUrl = payload["url"];\nreturn fetch(userUrl);',
            ),
            CodeFinding(
                severity="medium",
                rule_id="path-traversal",
                title="Path traversal risk",
                description="path",
                confidence=0.74,
                evidence=CodeEvidence(file_path="server.py", line=20, snippet="open(path)"),
                recommendation=["base dir"],
                cluster_id="path-traversal:server.py:path_build",
                cluster_size=1,
                cluster_role="primary",
                context="mcp",
                nearby_context="open(path)",
            ),
        ]
        return SimpleNamespace(findings=findings, capabilities=["network"])

    monkeypatch.setattr(GitHubCodeFetcher, "fetch_code_files", fake_fetch_code_files)
    monkeypatch.setattr("app.main.analyze_codebase", fake_analyze_codebase)
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.main.triage_findings",
        lambda findings, _model, _batch_size, _budget_mode: {
            "results": [
                {"cluster_id": "ssrf-fetch:server.py:fetch:/api", "action": "keep", "risk": "high", "confidence": 0.8, "reason": "exposed outbound fetch"},
                {"cluster_id": "path-traversal:server.py:path_build", "action": "suppress", "risk": "low", "confidence": 0.9, "reason": "not exploitable here"},
            ],
            "suppressed_cluster_ids": {"path-traversal:server.py:path_build"},
            "group_count": 2,
            "classified_group_count": 2,
        },
    )

    client = TestClient(app)
    response = client.post(
        "/audit/code/summary",
        json={
            "url": "https://github.com/acme/demo",
            "ai_classify": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["audited_by"] == "Run The Dev"
    assert payload["audited_at"]
    assert payload["risk_level"] == "HIGH"
    assert payload["security_score"] == 78
    assert payload["quality_score"] == 84
    assert payload["overall_risk"] == "high"
    assert payload["status"] == "hardening_required"
    assert payload["top_risks"] == ["Outbound requests may forward user-controlled parameters to external services."]
    assert "Restrict outbound network access to trusted domains only and monitor external requests." in payload["safe_usage_recommendations"]
    assert payload["deployment_guidance"]["production"] == "not_recommended"


def test_audit_code_endpoint_removes_all_suppressed_clusters_from_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_code_files(
        self: GitHubCodeFetcher,
        url: str,
        *,
        max_files: int,
        max_total_chars: int,
        include_tests: bool,
        include_ci: bool,
    ):
        return (
            GitHubCodeTarget(owner="acme", repo="demo", ref="main", path="", target_kind="repo"),
            [make_code_file("server.py", "export default {};", language="typescript", context="mcp")],
        )

    def fake_analyze_codebase(_files: list[ScannedCodeFile]) -> SimpleNamespace:
        findings = [
            CodeFinding(
                severity="critical",
                rule_id="ssrf-fetch",
                title="Potential SSRF or arbitrary URL fetch",
                description="ssrf",
                confidence=0.92,
                evidence=CodeEvidence(file_path="server.py", line=10, snippet="return fetch(userUrl)"),
                recommendation=["allowlist"],
                cluster_id="ssrf-fetch:server.py:fetch:/api",
                cluster_size=1,
                cluster_role="primary",
                context="mcp",
                nearby_context="const userUrl = payload.url;\nreturn fetch(userUrl);",
            ),
            CodeFinding(
                severity="medium",
                rule_id="arbitrary-file-delete",
                title="Arbitrary file delete access",
                description="delete",
                confidence=0.74,
                evidence=CodeEvidence(file_path="server.py", line=20, snippet="os.remove(path)"),
                recommendation=["sandbox"],
                cluster_id="arbitrary-file-delete:server.py:remove",
                cluster_size=1,
                cluster_role="primary",
                context="mcp",
                nearby_context="os.remove(path)",
            ),
        ]
        return SimpleNamespace(findings=findings, capabilities=["network", "filesystem"])

    monkeypatch.setattr(GitHubCodeFetcher, "fetch_code_files", fake_fetch_code_files)
    monkeypatch.setattr("app.main.analyze_codebase", fake_analyze_codebase)
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.main.triage_findings",
        lambda findings, _model, _batch_size, _budget_mode: {
            "results": [
                {"cluster_id": "ssrf-fetch:server.py:fetch:/api", "action": "keep", "risk": "high", "confidence": 0.8, "reason": ""},
                {"cluster_id": "arbitrary-file-delete:server.py:remove", "action": "suppress", "risk": "low", "confidence": 0.9, "reason": "cleanup path"},
            ],
            "suppressed_cluster_ids": {"arbitrary-file-delete:server.py:remove"},
            "group_count": 2,
            "classified_group_count": 2,
        },
    )

    client = TestClient(app)
    response = client.post(
        "/audit/code",
        json={
            "url": "https://github.com/acme/demo",
            "max_files": 40,
            "max_total_chars": 400000,
            "include_tests": False,
            "include_ci": False,
            "ai_classify": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert [item["cluster_id"] for item in payload["findings"]] == ["ssrf-fetch:server.py:fetch:/api"]
    assert [item["cluster_id"] for item in payload["clusters"]["primary"]] == ["ssrf-fetch:server.py:fetch:/api"]
    assert [item["cluster_id"] for item in payload["clusters"]["suppressed"]] == ["arbitrary-file-delete:server.py:remove"]
    assert all(item["action"] == "suppress" for item in payload["ai_suppressed_clusters"])
    assert [item["cluster_id"] for item in payload["ai_triage"]["suppressed_findings"]] == ["arbitrary-file-delete:server.py:remove"]
    assert payload["summary"]["counts"]["critical"] == 0
    assert payload["summary"]["counts"]["high"] == 1
    assert payload["summary"]["counts"]["medium"] == 0


def test_audit_code_endpoint_does_not_mutate_frozen_analysis_result(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch_code_files(
        self: GitHubCodeFetcher,
        url: str,
        *,
        max_files: int,
        max_total_chars: int,
        include_tests: bool,
        include_ci: bool,
    ):
        return (
            GitHubCodeTarget(owner="acme", repo="demo", ref="main", path="", target_kind="repo"),
            [make_code_file("server.py", "export default {};", language="typescript", context="library")],
        )

    def fake_analyze_codebase(_files: list[ScannedCodeFile]) -> SimpleNamespace:
        findings = [
            CodeFinding(
                severity="medium",
                rule_id="path-traversal",
                title="Path traversal risk",
                description="Path-building logic appears vulnerable to traversal or base-directory escape without a visible containment check.",
                confidence=0.74,
                evidence=CodeEvidence(file_path="server.py", line=20, snippet='import type { Info } from "../../+types/root.js"'),
                recommendation=["Canonicalize the resolved path and verify it stays inside a fixed base directory."],
                cluster_id="path-traversal:server.py:import",
                cluster_size=1,
                cluster_role="primary",
                context="library",
                nearby_context='import type { Info } from "../../+types/root.js"',
            ),
        ]
        return SimpleNamespace(findings=findings, capabilities=[])

    monkeypatch.setattr(GitHubCodeFetcher, "fetch_code_files", fake_fetch_code_files)
    monkeypatch.setattr("app.main.analyze_codebase", fake_analyze_codebase)
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.main.triage_findings",
        lambda findings, _model, _batch_size, _budget_mode: {
            "results": [
                {"cluster_id": "path-traversal:server.py:import", "action": "suppress", "risk": "low", "confidence": 0.9, "reason": "generated code"},
            ],
            "suppressed_cluster_ids": {"path-traversal:server.py:import"},
            "group_count": 1,
            "classified_group_count": 1,
        },
    )

    client = TestClient(app)
    response = client.post(
        "/audit/code",
        json={
            "url": "https://github.com/acme/demo",
            "max_files": 40,
            "max_total_chars": 400000,
            "include_tests": False,
            "include_ci": False,
            "ai_classify": True,
        },
    )

    assert response.status_code == 200


def test_batch_summary_counts_primary_clusters_not_raw_findings() -> None:
    summary = build_batch_summary(
        [
            {
                "ok": True,
                "report": {
                    "summary": {"risk_score": 40},
                    "overall_safety": {"verdict": "unsafe"},
                    "clusters": {
                        "primary": [{"rule_id": "path-traversal"}],
                        "suppressed": [],
                    },
                    "ai_handoff": {
                        "items": [
                            {"rule_id": "ssrf-fetch"},
                            {"rule_id": "path-traversal"},
                        ]
                    },
                },
            }
        ]
    )

    assert summary["top_rule_counts"] == [{"rule_id": "path-traversal", "count": 1}]


def test_build_code_summary_counts_only_supported_primary_clusters() -> None:
    findings = [
        CodeFinding(
            severity="high",
            rule_id="ssrf-fetch",
            title="Potential SSRF or arbitrary URL fetch",
            description="ssrf",
            confidence=0.9,
            evidence=CodeEvidence(file_path="server.py", line=10, snippet="fetch(userUrl)"),
            recommendation=["allowlist"],
            cluster_id="ssrf-fetch:server.py:fetch:/api",
            cluster_size=2,
            cluster_role="primary",
            context="mcp",
            nearby_context="fetch(userUrl)",
        ),
        CodeFinding(
            severity="high",
            rule_id="ssrf-fetch",
            title="Potential SSRF or arbitrary URL fetch",
            description="ssrf",
            confidence=0.8,
            evidence=CodeEvidence(file_path="server.py", line=11, snippet="fetch(userUrl)"),
            recommendation=["allowlist"],
            cluster_id="ssrf-fetch:server.py:fetch:/api",
            cluster_size=2,
            cluster_role="duplicate",
            context="mcp",
            nearby_context="fetch(userUrl)",
        ),
        CodeFinding(
            severity="high",
            rule_id="tool-approval-missing",
            title="Dangerous capability without approval checks",
            description="approval",
            confidence=0.8,
            evidence=CodeEvidence(file_path="server.py", line=20, snippet="fetch(userUrl)"),
            recommendation=["approval"],
            cluster_id="tool-approval-missing:server.py",
            cluster_size=1,
            cluster_role="primary",
            context="mcp",
            nearby_context="fetch(userUrl)",
        ),
    ]

    summary, drivers = build_code_summary(findings, ["network"], [make_code_file("server.py", "x", language="python", context="mcp")])

    assert summary.counts.high == 1
    assert summary.raw_counts.high == 3
    assert drivers == [
        "20 pts: Potential SSRF or arbitrary URL fetch",
        "2 pts: 1 dangerous capabilities",
    ]


def test_build_code_summary_uses_ai_risk_for_kept_clusters() -> None:
    findings = [
        CodeFinding(
            severity="high",
            rule_id="ssrf-fetch",
            title="Potential SSRF or arbitrary URL fetch",
            description="ssrf",
            confidence=0.9,
            evidence=CodeEvidence(file_path="server.py", line=10, snippet="return fetch(userUrl)"),
            recommendation=["allowlist"],
            cluster_id="ssrf-fetch:server.py:fetch:/api",
            cluster_size=1,
            cluster_role="primary",
            context="mcp",
            nearby_context='const userUrl = payload["url"];\nreturn fetch(userUrl);',
            ai_verdict="keep",
            ai_risk="medium",
            ai_confidence=0.8,
        ),
    ]

    summary, drivers = build_code_summary(findings, ["network"], [make_code_file("server.py", "x", language="python", context="mcp")])

    assert summary.risk_score == 12
    assert summary.counts.medium == 1
    assert drivers == [
        "10 pts: Potential SSRF or arbitrary URL fetch",
        "2 pts: 1 dangerous capabilities",
    ]


def test_fixed_host_vendor_wrapper_ssrf_scores_as_low() -> None:
    findings = [
        CodeFinding(
            severity="high",
            rule_id="ssrf-fetch",
            title="Potential SSRF or arbitrary URL fetch",
            description="ssrf",
            confidence=0.9,
            evidence=CodeEvidence(file_path="src/github/index.ts", line=544, snippet="const response = await fetch(url.toString(), {"),
            recommendation=["allowlist"],
            cluster_id="ssrf-fetch:src/github/index.ts:fetch:unknown",
            cluster_size=1,
            cluster_role="primary",
            context="mcp",
            nearby_context="url.searchParams.append('since', options.since); Authorization: `token ${GITHUB_PERSONAL_ACCESS_TOKEN}`",
            ai_verdict="keep",
            ai_risk="medium",
            ai_confidence=0.8,
        ),
    ]

    summary, drivers = build_code_summary(findings, ["network"], [make_code_file("src/github/index.ts", "x", language="typescript", context="mcp")])

    assert summary.risk_score == 5
    assert summary.counts.low == 1
    assert drivers == [
        "3 pts: Potential SSRF or arbitrary URL fetch",
        "2 pts: 1 dangerous capabilities",
    ]


def test_ai_triage_timeout_falls_back_to_empty_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.ai_triage._classify_batch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(requests.exceptions.ReadTimeout("timed out")),
    )

    payload = triage_findings(
        [
            {
                "cluster_id": "ssrf-fetch:server.py:fetch:/api",
                "rule_id": "ssrf-fetch",
                "deterministic_severity": "critical",
                "context": "mcp",
                "file_path": "server.py",
                "primary_line": 10,
                "primary_snippet": "return fetch(userUrl)",
                "nearby_context": 'const userUrl = payload.url; return fetch(userUrl);',
                "cluster_size": 1,
                "taint_summary": {
                    "source": "user_input",
                    "sink": "network",
                    "is_probably_exposed": True,
                    "guards_seen": [],
                    "path_area": "none",
                },
            }
        ],
        model="mistral-small-latest",
        max_batch=8,
        budget_mode=True,
    )

    assert payload["results"] == []
    assert payload["suppressed_cluster_ids"] == set()


def test_blob_url_prefers_raw_fetch_and_avoids_api_calls() -> None:
    async def run() -> None:
        calls: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            if request.url.host == "raw.githubusercontent.com":
                assert request.url.path == "/acme/demo/main/src/index.ts"
                return httpx.Response(200, text="export const ok = true;\n")
            raise AssertionError(f"unexpected API call: {request.url}")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with GitHubCodeFetcher(client=client) as fetcher:
            target, files = await fetcher.fetch_code_files(
                "https://github.com/acme/demo/blob/main/src/index.ts",
                max_files=1,
                max_total_chars=1000,
                include_tests=False,
                include_ci=False,
            )

        assert target.ref == "main"
        assert target.path == "src/index.ts"
        assert [item.path for item in files] == ["src/index.ts"]
        assert calls == ["https://raw.githubusercontent.com/acme/demo/main/src/index.ts"]

    asyncio.run(run())


def test_code_fetcher_uses_github_token_for_api_requests() -> None:
    async def run() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            assert request.url == "https://api.github.com/repos/acme/demo"
            assert request.headers["Authorization"] == "Bearer test-token"
            return httpx.Response(200, json={"default_branch": "main"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with GitHubCodeFetcher(client=client, github_token="test-token") as fetcher:
            target = await fetcher.resolve_target("https://github.com/acme/demo")

        assert target.root_target == "acme/demo@main"

    asyncio.run(run())
