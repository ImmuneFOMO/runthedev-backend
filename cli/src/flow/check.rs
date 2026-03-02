use std::io::{IsTerminal, stdin, stdout};

use dialoguer::{Confirm, MultiSelect, Select, theme::ColorfulTheme};

use crate::api::client::ApiClient;
use crate::api::types::{AuditProvider, CheckResponse, ItemType};
use crate::clients::{ClientAdapter, OperatingSystem, client_registry, current_os};
use crate::install;
use crate::install::skill::{
    SkillInstallOutcome, build_skill_install_plan, choose_skill_targets, install_skill_to_targets,
};
use crate::install::transport::{InstallTransport, available_transports, build_install_config};
use crate::ui::display;
use crate::{CliError, CliResult};

pub async fn run_check(
    api: &ApiClient,
    identifier: &str,
    forced_type: Option<ItemType>,
) -> CliResult<()> {
    let slug = canonicalize_identifier(identifier)?;
    let interactive = stdin().is_terminal() && stdout().is_terminal();

    let (resolved_type, check) = resolve_item_type(api, &slug, forced_type, interactive).await?;

    if !check.found {
        return Err(CliError::Input(
            "identifier not found; verify slug or pass --type".to_string(),
        ));
    }

    display::show_item_summary(&check);
    display::show_audits(&check.audits);

    let runthedev_status = runthedev_status(&check.audits);
    if runthedev_status == "none" {
        let request = api
            .post_request_audit(&slug, resolved_type, env!("CARGO_PKG_VERSION"))
            .await?;
        display::show_no_audit(request.request_count, &request.message);
        println!(
            "  Auto-audit threshold reached: {}",
            if request.auto_audit_triggered {
                "yes"
            } else {
                "no"
            }
        );
    } else if runthedev_status == "pending" {
        display::show_no_audit(
            check.audit_request_count,
            "RunTheDev audit is pending. Installation can continue.",
        );
    }

    if resolved_type == ItemType::Skill {
        if skill_has_provider_issues(&check.audits) {
            display::show_provider_findings(&check.audits);
            let proceed = if interactive {
                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Risk signals were found for this skill. Continue with install?")
                    .default(false)
                    .interact()
                    .map_err(|err| CliError::Operational(format!("confirmation failed: {err}")))?
            } else {
                false
            };

            if !proceed {
                return Err(CliError::UserDeclined);
            }
        }
        if audits_have_no_meaningful_signals(&check.audits) {
            println!("No meaningful audit signals are available for this skill.");
        }

        let Some(item) = check.item.as_ref() else {
            return Err(CliError::Operational("missing item payload".to_string()));
        };

        let detail = api.get_skill_detail(&slug).await?;
        let plan = build_skill_install_plan(item, &detail)?;
        let os = current_os();
        let targets = choose_skill_targets(os, interactive)?;
        if targets.is_empty() {
            return Err(CliError::NoInstallPath(
                "No compatible install targets remain for skill installation".to_string(),
            ));
        }

        let outcomes = install_skill_to_targets(&plan, os, targets);
        for outcome in outcomes {
            match outcome {
                SkillInstallOutcome::Installed { target, path } => {
                    println!("{target}: skill installed ({})", path.display());
                }
                SkillInstallOutcome::Failed { target, reason } => {
                    println!("{target}: failed ({reason})");
                }
            }
        }

        return Ok(());
    }

    if server_has_security_or_quality_warning(&check.audits) {
        display::show_server_warning();
        display::show_provider_findings(&check.audits);
        let proceed = if interactive {
            Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Risk signals were found. Continue with install?")
                .default(false)
                .interact()
                .map_err(|err| CliError::Operational(format!("confirmation failed: {err}")))?
        } else {
            false
        };

        if !proceed {
            return Err(CliError::UserDeclined);
        }
    } else if audits_have_no_meaningful_signals(&check.audits) {
        display::show_server_caution();
    }

    let connections = check.connections.as_ref().ok_or_else(|| {
        CliError::NoInstallPath(
            "No connection methods are currently published for this server; automatic install is unavailable.".to_string(),
        )
    })?;
    if connections.is_empty() {
        return Err(CliError::NoInstallPath(
            "No connection methods are currently published for this server; automatic install is unavailable.".to_string(),
        ));
    }

    let transports = available_transports(connections);
    if transports.is_empty() {
        return Err(CliError::NoInstallPath(
            "No connection methods are currently published for this server; automatic install is unavailable.".to_string(),
        ));
    }

    let selected_transport = select_transport(&transports, interactive)?;
    let install_config = build_install_config(&slug, selected_transport, connections, interactive)?;

    let os = current_os();
    let registry = client_registry();
    let selected_clients = choose_install_targets(&registry, os, interactive)?;
    if selected_clients.is_empty() {
        return Err(CliError::NoInstallPath(
            "No compatible install targets remain for chosen transport".to_string(),
        ));
    }

    let mut installable: Vec<&dyn ClientAdapter> = Vec::new();
    for client in selected_clients {
        if client.capabilities().supports(selected_transport) {
            installable.push(client);
        } else {
            println!("{}: skipped (unsupported transport)", client.display_name());
        }
    }

    if installable.is_empty() {
        return Err(CliError::NoInstallPath(
            "No compatible install targets remain for chosen transport".to_string(),
        ));
    }

    let Some(item) = check.item.as_ref() else {
        return Err(CliError::Operational("missing item payload".to_string()));
    };

    let outcomes = install::install_to_clients(item, &install_config, os, installable);
    for outcome in outcomes {
        match outcome {
            install::InstallOutcome::Installed { client, path } => {
                println!("{client}: installed ({})", path.display());
            }
            install::InstallOutcome::Failed { client, reason } => {
                println!("{client}: failed ({reason})");
            }
        }
    }

    Ok(())
}

fn canonicalize_identifier(identifier: &str) -> CliResult<String> {
    let raw = identifier.trim();
    if raw.is_empty() {
        return Err(CliError::Input("identifier must not be empty".to_string()));
    }

    if let Ok(url) = url::Url::parse(raw) {
        return canonicalize_github_url(&url);
    }

    if raw.contains("://") {
        return Err(CliError::Input(
            "malformed URL; expected https://github.com/owner/repo".to_string(),
        ));
    }

    if raw.starts_with("github.com/") || raw.starts_with("www.github.com/") {
        let prefixed = format!("https://{raw}");
        let parsed = url::Url::parse(&prefixed).map_err(|_| {
            CliError::Input("malformed URL; expected github.com/owner/repo".to_string())
        })?;
        return canonicalize_github_url(&parsed);
    }

    let parts: Vec<&str> = raw.split('/').collect();
    if parts.len() != 2 {
        return Err(CliError::Input(
            "identifier must be exact owner/repo".to_string(),
        ));
    }

    canonicalize_owner_repo(parts[0], parts[1])
}

fn canonicalize_github_url(url: &url::Url) -> CliResult<String> {
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(CliError::Input(
                "only http(s) github.com URLs are supported".to_string(),
            ));
        }
    }

    match url.host_str() {
        Some("github.com") | Some("www.github.com") => {}
        _ => {
            return Err(CliError::Input(
                "only github.com identifiers are supported".to_string(),
            ));
        }
    }

    if !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::Input(
            "github URL must be plain owner/repo without credentials, query, or fragment"
                .to_string(),
        ));
    }

    let parts: Vec<&str> = url
        .path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
        .unwrap_or_default();

    if parts.len() != 2 {
        return Err(CliError::Input(
            "github identifier must be exact owner/repo".to_string(),
        ));
    }

    canonicalize_owner_repo(parts[0], parts[1])
}

fn canonicalize_owner_repo(owner: &str, repo: &str) -> CliResult<String> {
    let owner = owner.trim();
    let repo = repo.trim_end_matches(".git").trim();

    if !is_valid_owner(owner) {
        return Err(CliError::Input(
            "invalid github owner; expected alphanumeric/hyphen and <=39 chars".to_string(),
        ));
    }

    if !is_valid_repo(repo) {
        return Err(CliError::Input(
            "invalid github repo; expected alphanumeric/._- and <=100 chars".to_string(),
        ));
    }

    Ok(format!(
        "{}/{}",
        owner.to_ascii_lowercase(),
        repo.to_ascii_lowercase()
    ))
}

fn is_valid_owner(owner: &str) -> bool {
    if owner.is_empty() || owner.len() > 39 {
        return false;
    }

    let bytes = owner.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn is_valid_repo(repo: &str) -> bool {
    if repo.is_empty() || repo.len() > 100 {
        return false;
    }

    if repo.starts_with('.') || repo.ends_with('.') {
        return false;
    }

    repo.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.')
}

async fn resolve_item_type(
    api: &ApiClient,
    slug: &str,
    forced_type: Option<ItemType>,
    interactive: bool,
) -> CliResult<(ItemType, CheckResponse)> {
    if let Some(item_type) = forced_type {
        let check = api.get_check(slug, item_type).await?;
        if !check.found {
            return Err(CliError::Input(format!(
                "{} not found as {}",
                slug, item_type
            )));
        }
        return Ok((item_type, check));
    }

    let server = api.get_check(slug, ItemType::Server).await?;
    let skill = api.get_check(slug, ItemType::Skill).await?;

    match (server.found, skill.found) {
        (true, false) => Ok((ItemType::Server, server)),
        (false, true) => Ok((ItemType::Skill, skill)),
        (false, false) => Err(CliError::Input(
            "identifier did not resolve as server or skill; verify slug or pass --type".to_string(),
        )),
        (true, true) => {
            if !interactive {
                return Err(CliError::Input(
                    "ambiguous type: identifier matches both server and skill; pass --type"
                        .to_string(),
                ));
            }
            let options = ["Server", "Skill"];
            let selected = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Identifier matches both server and skill. Choose type")
                .items(&options)
                .default(0)
                .interact()
                .map_err(|err| CliError::Operational(format!("failed to read selection: {err}")))?;
            if selected == 0 {
                Ok((ItemType::Server, server))
            } else {
                Ok((ItemType::Skill, skill))
            }
        }
    }
}

fn select_transport(
    transports: &[InstallTransport],
    interactive: bool,
) -> CliResult<InstallTransport> {
    if transports.len() == 1 {
        return Ok(transports[0]);
    }
    if !interactive {
        return Err(CliError::Operational(
            "multiple transports available; run in interactive mode to choose".to_string(),
        ));
    }

    let labels: Vec<&str> = transports
        .iter()
        .map(|transport| transport.label())
        .collect();
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose install transport")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(|err| CliError::Operational(format!("failed to select transport: {err}")))?;
    Ok(transports[idx])
}

fn choose_install_targets(
    registry: &[Box<dyn ClientAdapter>],
    os: OperatingSystem,
    interactive: bool,
) -> CliResult<Vec<&dyn ClientAdapter>> {
    let mut supported: Vec<&dyn ClientAdapter> = Vec::new();
    for client in registry {
        if client.supports_os(os) {
            supported.push(client.as_ref());
        } else {
            println!(
                "{}: unsupported on this platform ({})",
                client.display_name(),
                os.label()
            );
        }
    }

    if supported.is_empty() {
        return Ok(Vec::new());
    }

    if !interactive {
        return Ok(supported);
    }

    let labels: Vec<&str> = supported
        .iter()
        .map(|client| client.display_name())
        .collect();
    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Install to")
        .items(&labels)
        .interact()
        .map_err(|err| CliError::Operational(format!("failed to select install targets: {err}")))?;

    Ok(selected
        .into_iter()
        .filter_map(|idx| supported.get(idx).copied())
        .collect())
}

fn runthedev_status(audits: &[AuditProvider]) -> &str {
    audits
        .iter()
        .find(|audit| audit.provider == "runthedev")
        .map(|audit| audit.status.as_str())
        .unwrap_or("none")
}

fn skill_has_provider_issues(audits: &[AuditProvider]) -> bool {
    audits.iter().any(|audit| {
        if audit.status == "warn" || audit.status == "fail" {
            return true;
        }

        if audit.findings.iter().any(|finding| {
            finding
                .severity
                .as_deref()
                .map(|severity| {
                    let normalized = severity.to_ascii_lowercase();
                    normalized == "high" || normalized == "critical"
                })
                .unwrap_or(false)
        }) {
            return true;
        }

        false
    })
}

fn server_has_security_or_quality_warning(audits: &[AuditProvider]) -> bool {
    audits.iter().any(|audit| {
        is_bad_grade(audit.security_grade.as_deref())
            || is_bad_grade(audit.quality_grade.as_deref())
            || ((audit.provider == "runthedev" || audit.provider == "security-audit")
                && (audit.status == "warn" || audit.status == "fail")
                && audit.findings.iter().any(|finding| {
                    finding.message.to_ascii_lowercase().contains("security")
                        || finding.message.to_ascii_lowercase().contains("quality")
                }))
    })
}

fn audits_have_no_meaningful_signals(audits: &[AuditProvider]) -> bool {
    let has_meaningful = audits.iter().any(|audit| {
        !matches!(audit.status.as_str(), "none" | "pending" | "unknown")
            || audit.score.is_some()
            || audit.grade.is_some()
            || audit.security_grade.is_some()
            || audit.quality_grade.is_some()
            || audit.license_grade.is_some()
            || !audit.findings.is_empty()
    });

    !has_meaningful
}

fn is_bad_grade(grade: Option<&str>) -> bool {
    grade
        .map(str::trim)
        .map(str::to_ascii_uppercase)
        .map(|value| value.starts_with('D') || value.starts_with('F'))
        .unwrap_or(false)
}
