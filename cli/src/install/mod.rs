pub mod skill;
pub mod transport;
pub mod writer;

use std::path::PathBuf;

use crate::api::types::CheckItem;
use crate::clients::{ClientAdapter, OperatingSystem};
use crate::install::transport::InstallConfig;

pub enum InstallOutcome {
    Installed { client: String, path: PathBuf },
    Failed { client: String, reason: String },
}

pub fn install_to_clients(
    item: &CheckItem,
    config: &InstallConfig,
    os: OperatingSystem,
    clients: Vec<&dyn ClientAdapter>,
) -> Vec<InstallOutcome> {
    let mut results = Vec::with_capacity(clients.len());

    for client in clients {
        match client.write_server(os, &item.dedup_key, config) {
            Ok(path) => results.push(InstallOutcome::Installed {
                client: client.display_name().to_string(),
                path,
            }),
            Err(err) => results.push(InstallOutcome::Failed {
                client: client.display_name().to_string(),
                reason: err.to_string(),
            }),
        }
    }

    results
}
