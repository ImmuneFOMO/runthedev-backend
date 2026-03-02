use clap::{CommandFactory, Parser, Subcommand};
use rtd::api::types::ItemType;
use rtd::flow::check::run_check;

#[derive(Debug, Parser)]
#[command(name = "rtd")]
#[command(about = "RunTheDev CLI")]
struct Cli {
    identifier: Option<String>,
    #[arg(long = "type", value_enum)]
    item_type: Option<ItemType>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Check {
        identifier: String,
        #[arg(long = "type", value_enum)]
        item_type: Option<ItemType>,
    },
    Version,
}

async fn execute_check(identifier: &str, item_type: Option<ItemType>) -> i32 {
    let api = rtd::api::client::ApiClient::new_from_env();
    match run_check(&api, identifier, item_type).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {err}");
            err.exit_code()
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let code = match cli.command {
        Some(Commands::Check {
            identifier,
            item_type,
        }) => execute_check(&identifier, item_type).await,
        Some(Commands::Version) => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            0
        }
        None => match cli.identifier {
            Some(identifier) => execute_check(&identifier, cli.item_type).await,
            None => {
                let mut cmd = Cli::command();
                let _ = cmd.print_help();
                eprintln!();
                2
            }
        },
    };

    std::process::exit(code);
}
