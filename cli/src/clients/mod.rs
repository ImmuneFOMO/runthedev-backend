use std::path::PathBuf;

use crate::install::transport::{InstallConfig, InstallTransport};
use crate::{CliError, CliResult};

pub mod claude_code;
pub mod codex;
pub mod cursor;
pub mod opencode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystem {
    MacOS,
    Linux,
    Other,
}

impl OperatingSystem {
    pub fn label(self) -> &'static str {
        match self {
            Self::MacOS => "macOS",
            Self::Linux => "Linux",
            Self::Other => "Unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClientCapabilities {
    pub supports_stdio: bool,
    pub supports_http: bool,
    pub supports_macos: bool,
    pub supports_linux: bool,
}

impl ClientCapabilities {
    pub fn supports_os(self, os: OperatingSystem) -> bool {
        match os {
            OperatingSystem::MacOS => self.supports_macos,
            OperatingSystem::Linux => self.supports_linux,
            OperatingSystem::Other => false,
        }
    }

    pub fn supports(self, transport: InstallTransport) -> bool {
        match transport {
            InstallTransport::Stdio => self.supports_stdio,
            InstallTransport::Http => self.supports_http,
        }
    }
}

pub trait ClientAdapter {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn capabilities(&self) -> ClientCapabilities;
    fn config_path(&self, os: OperatingSystem) -> Option<PathBuf>;
    fn write_server(
        &self,
        os: OperatingSystem,
        server_name: &str,
        config: &InstallConfig,
    ) -> CliResult<PathBuf>;

    fn supports_os(&self, os: OperatingSystem) -> bool {
        self.capabilities().supports_os(os)
    }
}

pub fn current_os() -> OperatingSystem {
    match std::env::consts::OS {
        "macos" => OperatingSystem::MacOS,
        "linux" => OperatingSystem::Linux,
        _ => OperatingSystem::Other,
    }
}

pub fn client_registry() -> Vec<Box<dyn ClientAdapter>> {
    vec![
        Box::new(claude_code::ClaudeCodeClient),
        Box::new(codex::CodexClient),
        Box::new(opencode::OpenCodeClient),
        Box::new(cursor::CursorClient),
    ]
}

pub(crate) fn home_dir() -> Result<PathBuf, CliError> {
    dirs::home_dir()
        .ok_or_else(|| CliError::Operational("could not resolve HOME directory".to_string()))
}

pub(crate) fn json_entry_from_config(config: &InstallConfig) -> serde_json::Value {
    match config {
        InstallConfig::Stdio { command, args, env } => {
            serde_json::json!({"command": command, "args": args, "env": env})
        }
        InstallConfig::Http { url } => serde_json::json!({"url": url}),
    }
}

pub(crate) fn ensure_json_object(
    value: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, CliError> {
    if !value.is_object() {
        *value = serde_json::json!({});
    }
    value
        .as_object_mut()
        .ok_or_else(|| CliError::Operational("expected JSON object root".to_string()))
}

pub(crate) fn upsert_json_server_entry(
    root: &mut serde_json::Value,
    parent_key: &str,
    server_name: &str,
    config: &InstallConfig,
) -> Result<(), CliError> {
    let object = ensure_json_object(root)?;
    let parent = object
        .entry(parent_key.to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !parent.is_object() {
        *parent = serde_json::json!({});
    }
    if let Some(parent_obj) = parent.as_object_mut() {
        parent_obj.insert(server_name.to_string(), json_entry_from_config(config));
        return Ok(());
    }

    Err(CliError::Operational(
        "failed to update JSON server map".to_string(),
    ))
}
