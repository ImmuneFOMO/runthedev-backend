use dialoguer::{Input, theme::ColorfulTheme};

use crate::CliError;
use crate::api::types::ConnectionPayload;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallTransport {
    Stdio,
    Http,
}

impl InstallTransport {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stdio => "Local (stdio)",
            Self::Http => "Remote (http)",
        }
    }
}

#[derive(Debug, Clone)]
pub enum InstallConfig {
    Stdio {
        command: String,
        args: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
    },
    Http {
        url: String,
    },
}

pub fn available_transports(connections: &[ConnectionPayload]) -> Vec<InstallTransport> {
    let has_stdio = connections
        .iter()
        .any(|conn| conn.connection_type == "stdio");
    let has_http = connections
        .iter()
        .any(|conn| conn.connection_type == "http");

    let mut transports = Vec::new();
    if has_stdio {
        transports.push(InstallTransport::Stdio);
    }
    if has_http {
        transports.push(InstallTransport::Http);
    }
    transports
}

pub fn build_install_config(
    slug: &str,
    transport: InstallTransport,
    connections: &[ConnectionPayload],
    interactive: bool,
) -> Result<InstallConfig, CliError> {
    match transport {
        InstallTransport::Http => {
            let connection = connections
                .iter()
                .find(|conn| conn.connection_type == "http")
                .ok_or_else(|| {
                    CliError::NoInstallPath("http transport not available".to_string())
                })?;
            let url = connection
                .deployment_url
                .as_ref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    CliError::Operational(
                        "http transport selected but deploymentUrl is missing".to_string(),
                    )
                })?
                .trim()
                .to_string();
            Ok(InstallConfig::Http { url })
        }
        InstallTransport::Stdio => {
            let connection = connections
                .iter()
                .find(|conn| conn.connection_type == "stdio")
                .ok_or_else(|| {
                    CliError::NoInstallPath("stdio transport not available".to_string())
                })?;

            let inferred = infer_stdio_command(slug, connection);
            let (command, args) = if let Some((command, args)) = inferred {
                println!(
                    "Using best-effort stdio mapping: {} {}",
                    command,
                    args.join(" ")
                );
                (command, args)
            } else if interactive {
                println!(
                    "Automatic stdio command inference was not reliable. Enter a manual command."
                );
                let raw: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Command")
                    .validate_with(|input: &String| {
                        if input.trim().is_empty() {
                            Err("command cannot be empty")
                        } else {
                            Ok(())
                        }
                    })
                    .interact_text()
                    .map_err(|err| {
                        CliError::Operational(format!("failed to read manual command: {err}"))
                    })?;
                parse_manual_command(&raw)?
            } else {
                return Err(CliError::Operational(
                    "stdio command could not be inferred; re-run interactively to enter a manual command"
                        .to_string(),
                ));
            };

            Ok(InstallConfig::Stdio {
                command,
                args,
                env: std::collections::BTreeMap::new(),
            })
        }
    }
}

fn infer_stdio_command(
    slug: &str,
    connection: &ConnectionPayload,
) -> Option<(String, Vec<String>)> {
    if let Some(command) = &connection.command
        && !command.trim().is_empty()
    {
        return Some((
            command.trim().to_string(),
            connection.args.clone().unwrap_or_default(),
        ));
    }

    let runtime = connection
        .runtime
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if runtime == "node" {
        let parts: Vec<&str> = slug.split('/').collect();
        if parts.len() == 2 {
            let owner = parts[0];
            let repo = parts[1];
            if owner
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                && repo
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            {
                return Some((
                    "npx".to_string(),
                    vec!["-y".to_string(), format!("@{owner}/{repo}")],
                ));
            }
        }
    }

    None
}

fn parse_manual_command(raw: &str) -> Result<(String, Vec<String>), CliError> {
    let mut parts = shell_words::split(raw)
        .map_err(|err| CliError::Input(format!("invalid manual command: {err}")))?;
    if parts.is_empty() {
        return Err(CliError::Input("manual command is empty".to_string()));
    }
    let command = parts.remove(0);
    Ok((command, parts))
}
