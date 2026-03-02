use std::path::PathBuf;

use crate::CliError;
use crate::clients::{
    ClientAdapter, ClientCapabilities, OperatingSystem, home_dir, upsert_json_server_entry,
};
use crate::install::transport::InstallConfig;
use crate::install::writer::{read_text_if_exists, write_atomic};

pub struct CursorClient;

impl ClientAdapter for CursorClient {
    fn id(&self) -> &'static str {
        "cursor"
    }

    fn display_name(&self) -> &'static str {
        "Cursor"
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
                Some(home_dir().ok()?.join(".cursor").join("mcp.json"))
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
            CliError::Operational("Cursor is unsupported on this platform".to_string())
        })?;

        let existing = read_text_if_exists(&path)?.unwrap_or_else(|| "{}".to_string());
        let mut root = serde_json::from_str::<serde_json::Value>(&existing)
            .unwrap_or_else(|_| serde_json::json!({}));

        upsert_json_server_entry(&mut root, "mcpServers", server_name, config)?;
        let serialized = serde_json::to_string_pretty(&root)
            .map_err(|err| CliError::Operational(format!("failed to serialize JSON: {err}")))?;
        write_atomic(&path, &serialized)?;
        Ok(path)
    }
}
