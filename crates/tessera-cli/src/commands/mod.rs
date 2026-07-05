//! CLI command implementations.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::Subcommand;
use tessera_core::crypto::KdfParams;
use tessera_core::{space, SpaceId, Vault};

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a new vault
    Init,
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
        /// Parent space id for nesting
        #[arg(long)]
        parent: Option<String>,
    },
    /// Show the space hierarchy
    Tree,
}

/// Vault path: --vault flag, else $TESSERA_VAULT, else ./vault.tessera.
pub fn resolve_vault_path(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| std::env::var_os("TESSERA_VAULT").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("./vault.tessera"))
}

/// Passphrase: $TESSERA_PASSPHRASE, else interactive prompt.
///
/// The prompt currently echoes input; no-echo entry lands with CLI polish.
fn passphrase() -> anyhow::Result<String> {
    if let Ok(pass) = std::env::var("TESSERA_PASSPHRASE") {
        return Ok(pass);
    }
    print!("Vault passphrase: ");
    std::io::stdout().flush()?;
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass)?;
    Ok(pass.trim_end_matches(['\r', '\n']).to_string())
}

/// KDF parameters. `TESSERA_KDF_PROFILE=insecure-test` selects deliberately
/// weak, fast parameters — for tests ONLY, and loudly named as such.
fn kdf_params() -> KdfParams {
    match std::env::var("TESSERA_KDF_PROFILE").as_deref() {
        Ok("insecure-test") => KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        _ => KdfParams::DEFAULT,
    }
}

fn open_vault(path: &std::path::Path) -> anyhow::Result<Vault> {
    let pass = passphrase()?;
    Vault::open(path, &pass).with_context(|| format!("opening vault at {}", path.display()))
}

pub fn execute(vault_path: PathBuf, command: Command) -> anyhow::Result<()> {
    match command {
        Command::Init => {
            let pass = passphrase()?;
            if pass.is_empty() {
                bail!("refusing to create a vault with an empty passphrase");
            }
            let vault = Vault::create_with_params(&vault_path, &pass, &kdf_params())
                .with_context(|| format!("creating vault at {}", vault_path.display()))?;
            println!("Vault created at {}", vault.path().display());
            Ok(())
        }
        Command::Space { action } => {
            let vault = open_vault(&vault_path)?;
            match action {
                SpaceCommand::List => {
                    for s in space::list(&vault)? {
                        println!("{}  {}", s.id.0, s.name);
                    }
                    Ok(())
                }
                SpaceCommand::Create { name, parent } => {
                    let parent_id = parent.map(SpaceId);
                    let id = space::create(&vault, &name, parent_id.as_ref())?;
                    println!("Created space {}  {name}", id.0);
                    Ok(())
                }
                SpaceCommand::Tree => {
                    let spaces = space::list(&vault)?;
                    fn print_children(
                        spaces: &[tessera_core::Space],
                        parent: Option<&SpaceId>,
                        depth: usize,
                    ) {
                        for s in spaces.iter().filter(|s| s.parent_id.as_ref() == parent) {
                            println!("{}{}", "  ".repeat(depth), s.name);
                            print_children(spaces, Some(&s.id), depth + 1);
                        }
                    }
                    print_children(&spaces, None, 0);
                    Ok(())
                }
            }
        }
        Command::Diag => {
            println!("tessera v{}", env!("CARGO_PKG_VERSION"));
            match Vault::open(&vault_path, &passphrase()?) {
                Ok(vault) => {
                    println!("vault: {}", vault.path().display());
                    println!("format_version: {}", vault.manifest().format_version);
                    println!("spaces: {}", space::list(&vault)?.len());
                }
                Err(e) => println!("vault: unavailable ({e})"),
            }
            Ok(())
        }
    }
}
