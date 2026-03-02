pub mod api;
pub mod clients;
pub mod flow;
pub mod install;
pub mod ui;

use thiserror::Error;

pub type CliResult<T> = Result<T, CliError>;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Input(String),
    #[error("{0}")]
    NoInstallPath(String),
    #[error("{0}")]
    Api(String),
    #[error("{0}")]
    Operational(String),
    #[error("Operation cancelled by user")]
    UserDeclined,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] anyhow::Error),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Input(_) => 2,
            Self::NoInstallPath(_) => 3,
            Self::UserDeclined => 1,
            Self::Api(_) | Self::Operational(_) | Self::Io(_) | Self::Parse(_) => 1,
        }
    }
}
