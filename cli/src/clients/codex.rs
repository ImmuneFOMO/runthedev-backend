use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::CliError;
use crate::clients::{ClientAdapter, ClientCapabilities, OperatingSystem, home_dir};
use crate::install::transport::InstallConfig;
use crate::install::writer::{read_text_if_exists, write_atomic};

pub struct CodexClient;

impl ClientAdapter for CodexClient {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn display_name(&self) -> &'static str {
        "Codex"
    }

    fn capabilities(&self) -> ClientCapabilities {
        ClientCapabilities {
            supports_stdio: true,
            supports_http: true,
            supports_macos: true,
            supports_linux: true,
        }
    }

    fn config_path(&self, os: OperatingSystem) -> Option<PathBuf> {
        match os {
            OperatingSystem::MacOS | OperatingSystem::Linux => {
                Some(home_dir().ok()?.join(".codex").join("config.toml"))
            }
            OperatingSystem::Other => None,
        }
    }

    fn write_server(
        &self,
        os: OperatingSystem,
        server_name: &str,
        config: &InstallConfig,
    ) -> Result<PathBuf, crate::CliError> {
        let path = self.config_path(os).ok_or_else(|| {
            CliError::Operational("Codex is unsupported on this platform".to_string())
        })?;

        let existing = read_text_if_exists(&path)?.unwrap_or_default();
        let mut root: toml::Value = if existing.trim().is_empty() {
            toml::Value::Table(toml::map::Map::new())
        } else {
            toml::from_str(&existing).unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
        };

        if !root.is_table() {
            root = toml::Value::Table(toml::map::Map::new());
        }
        let root_table = root
            .as_table_mut()
            .ok_or_else(|| CliError::Operational("invalid TOML root".to_string()))?;

        let servers_entry = root_table
            .entry("mcp_servers".to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        if !servers_entry.is_table() {
            *servers_entry = toml::Value::Table(toml::map::Map::new());
        }

        let server_table = codex_server_table(config);
        let servers_table = servers_entry
            .as_table_mut()
            .ok_or_else(|| CliError::Operational("invalid mcp_servers table".to_string()))?;
        servers_table.insert(server_name.to_string(), toml::Value::Table(server_table));

        let serialized = toml::to_string_pretty(&root)
            .map_err(|err| CliError::Operational(format!("failed to serialize TOML: {err}")))?;
        write_atomic(&path, &serialized)?;
        Ok(path)
    }
}

fn codex_server_table(config: &InstallConfig) -> toml::map::Map<String, toml::Value> {
    let mut table = toml::map::Map::new();
    match config {
        InstallConfig::Stdio { command, args, env } => {
            table.insert(
                "command".to_string(),
                toml::Value::String(command.to_string()),
            );
            table.insert(
                "args".to_string(),
                toml::Value::Array(
                    args.iter()
                        .map(|arg| toml::Value::String(arg.clone()))
                        .collect(),
                ),
            );
            if !env.is_empty() {
                let env_table: toml::map::Map<String, toml::Value> = env
                    .iter()
                    .map(|(key, value)| (key.clone(), toml::Value::String(value.clone())))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect();
                table.insert("env".to_string(), toml::Value::Table(env_table));
            }
        }
        InstallConfig::Http { url } => {
            table.insert("url".to_string(), toml::Value::String(url.to_string()));
        }
    }
    table
}
