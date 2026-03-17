//! CLI command implementations.

use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a new vault
    Init {
        /// Path for the new vault
        #[arg(default_value = "./vault")]
        path: std::path::PathBuf,
    },
    /// Open and unlock an existing vault
    Open {
        /// Path to the vault
        path: std::path::PathBuf,
    },
    /// Manage spaces
    Space {
        #[command(subcommand)]
        action: SpaceCommand,
    },
    /// Show vault diagnostics
    Diag,
}

#[derive(Subcommand)]
pub enum SpaceCommand {
    /// List all spaces
    List,
    /// Create a new space
    Create {
        /// Name of the space
        name: String,
    },
}

pub fn execute(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Init { path } => {
            println!("Would create vault at: {}", path.display());
            println!("Not yet implemented. See PLAN.md Iteration 1.");
            Ok(())
        }
        Command::Open { path } => {
            println!("Would open vault at: {}", path.display());
            println!("Not yet implemented. See PLAN.md Iteration 1.");
            Ok(())
        }
        Command::Space { action } => match action {
            SpaceCommand::List => {
                println!("Space listing not yet implemented.");
                Ok(())
            }
            SpaceCommand::Create { name } => {
                println!("Would create space: {name}");
                println!("Not yet implemented. See PLAN.md Iteration 1.");
                Ok(())
            }
        },
        Command::Diag => {
            println!("semblance v{}", env!("CARGO_PKG_VERSION"));
            println!("Diagnostics not yet implemented.");
            Ok(())
        }
    }
}
