use std::path::PathBuf;

use crate::CliError;
use crate::clients::{
    ClientAdapter, ClientCapabilities, OperatingSystem, ensure_json_object, home_dir,
    json_entry_from_config,
};
use crate::install::transport::InstallConfig;
use crate::install::writer::{read_text_if_exists, write_atomic};

pub struct OpenCodeClient;

impl ClientAdapter for OpenCodeClient {
    fn id(&self) -> &'static str {
        "opencode"
    }

    fn display_name(&self) -> &'static str {
        "OpenCode"
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
                Some(home_dir().ok()?.join(".opencode").join("opencode.jsonc"))
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
            CliError::Operational("OpenCode is unsupported on this platform".to_string())
        })?;

        let existing = read_text_if_exists(&path)?.unwrap_or_else(|| "{}".to_string());
        let mut root = json5::from_str::<serde_json::Value>(&existing)
            .unwrap_or_else(|_| serde_json::json!({}));
        let object = ensure_json_object(&mut root)?;
        let mcp = object
            .entry("mcp".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if !mcp.is_object() {
            *mcp = serde_json::json!({});
        }
        let mcp_obj = mcp
            .as_object_mut()
            .ok_or_else(|| CliError::Operational("invalid opencode mcp section".to_string()))?;

        let mut entry = json_entry_from_config(config);
        match config {
            InstallConfig::Stdio { .. } => {
                if let Some(obj) = entry.as_object_mut() {
                    obj.insert("type".to_string(), serde_json::json!("local"));
                }
            }
            InstallConfig::Http { .. } => {
                if let Some(obj) = entry.as_object_mut() {
                    obj.insert("type".to_string(), serde_json::json!("remote"));
                }
            }
        }

        mcp_obj.insert(server_name.to_string(), entry);

        let serialized = serde_json::to_string_pretty(&root)
            .map_err(|err| CliError::Operational(format!("failed to serialize JSONC: {err}")))?;
        write_atomic(&path, &serialized)?;
        Ok(path)
    }
}
