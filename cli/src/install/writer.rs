use std::fs;
use std::path::{Path, PathBuf};

use crate::{CliError, CliResult};

pub fn read_text_if_exists(path: &Path) -> CliResult<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CliError::Io(err)),
    }
}

pub fn write_atomic(path: &Path, content: &str) -> CliResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Operational(format!("invalid config path: {}", path.display())))?;
    fs::create_dir_all(parent)?;

    let temp_path = temp_path_for(path);
    fs::write(&temp_path, content.as_bytes())?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!(".{file_name}.{nanos}.tmp"))
}
