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
    /// Stage and ingest content
    Inbox {
        #[command(subcommand)]
        action: InboxCommand,
    },
    /// Review quarantined artifacts
    Review {
        /// Accept every pending artifact without prompting
        #[arg(long)]
        accept_all: bool,
    },
    /// Stage, ingest, and (with --accept) immediately publish files
    Import {
        /// Set artifacts live without review (pre-trusted content)
        #[arg(long)]
        accept: bool,
        /// Target space id (defaults to the sole space if only one exists)
        #[arg(long)]
        space: Option<String>,
        /// Files to import
        paths: Vec<std::path::PathBuf>,
    },
    /// Embed any chunks that don't have vectors yet
    Index,
    /// Semantic search over the vault (owner view unless --lens is given)
    Query {
        /// The question or search text
        text: String,
        /// Number of results
        #[arg(long, default_value_t = 5)]
        top_k: usize,
        /// Retrieve under a lens (policy-filtered) instead of the owner view
        #[arg(long)]
        lens: Option<String>,
    },
    /// Generate or regenerate an artifact's summary
    Summarize {
        /// Artifact id
        artifact: String,
        /// Regenerate even if a summary already exists
        #[arg(long)]
        redo: bool,
    },
    /// Manage lenses (access policies)
    Lens {
        #[command(subcommand)]
        action: LensCommand,
    },
    /// Run golden-set retrieval evaluation (exits non-zero below gate)
    Eval {
        /// Path to the golden set JSON: [{"question": "...", "expected": ["file.md"]}]
        #[arg(long)]
        golden: std::path::PathBuf,
        /// Recall@10 gate threshold
        #[arg(long, default_value_t = 0.70)]
        gate: f64,
    },
    /// Manage local models
    Model {
        #[command(subcommand)]
        action: ModelCommand,
    },
    /// Show vault diagnostics
    Diag {
        /// Print the provenance chain for one artifact
        #[arg(long)]
        artifact: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ModelCommand {
    /// Download the embedding model files (via curl)
    Fetch,
    /// Show model installation status
    Status,
}

#[derive(Subcommand)]
pub enum InboxCommand {
    /// Copy files into the inbox staging area
    Add {
        /// Files to stage
        paths: Vec<std::path::PathBuf>,
    },
    /// List staged files
    Status,
    /// Ingest staged files (intake + extraction + chunking)
    Process {
        /// Target space id (defaults to the sole space if only one exists)
        #[arg(long)]
        space: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum LensCommand {
    /// List all lenses
    List,
    /// Print one lens as JSON
    Show {
        /// Lens id
        id: String,
    },
    /// Create a lens interactively
    Create,
    /// Edit a lens (opens $EDITOR, or use --file for a prepared policy)
    Edit {
        /// Lens id
        id: String,
        /// Read the edited policy JSON from this file instead of $EDITOR
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Delete a lens
    Delete {
        /// Lens id
        id: String,
    },
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

fn load_embedder() -> anyhow::Result<tessera_core::embed::OnnxEmbedder> {
    let dir = tessera_core::embed::onnx::default_model_dir();
    tessera_core::embed::OnnxEmbedder::load(&dir)
        .context("loading embedding model (run `tessera model fetch` first)")
}

/// Resolve the target space: explicit flag, else the sole existing space.
fn resolve_space(vault: &Vault, flag: Option<String>) -> anyhow::Result<SpaceId> {
    if let Some(id) = flag {
        return Ok(SpaceId(id));
    }
    let spaces = space::list(vault)?;
    match spaces.len() {
        0 => bail!("no spaces exist — create one with `tessera space create <name>`"),
        1 => Ok(spaces.into_iter().next().expect("one space").id),
        n => bail!("{n} spaces exist — pass --space <id>"),
    }
}

/// Run the ingestion pipeline on staged files: intake, then extraction and
/// chunking for text types (best-effort; failures leave items pending).
fn run_inbox_pipeline(
    vault: &Vault,
    space: &SpaceId,
) -> anyhow::Result<Vec<tessera_core::ArtifactId>> {
    let report = tessera_core::inbox::process(vault, space)?;
    let mut ingested = Vec::new();
    for (path, artifact_id) in &report.ingested {
        match tessera_core::extract::extract_text(vault, artifact_id) {
            Ok(Some(derived)) => {
                if let Err(e) = tessera_core::chunk::chunk_derived_text(
                    vault,
                    &derived,
                    &tessera_core::chunk::ChunkParams::default(),
                ) {
                    eprintln!("warning: chunking failed for {}: {e}", path.display());
                }
                // Summary powers the `summary` disclosure mode; best-effort.
                if let Err(e) = tessera_core::summary::generate(vault, artifact_id, false) {
                    eprintln!("warning: summary failed for {}: {e}", path.display());
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("warning: extraction failed for {}: {e}", path.display()),
        }
        println!("Ingested {}  {}", artifact_id.0, path.display());
        ingested.push(artifact_id.clone());
    }
    for path in &report.duplicates {
        println!("Duplicate (already in vault): {}", path.display());
    }
    for (path, err) in &report.failures {
        eprintln!("Failed: {} — {err}", path.display());
    }
    Ok(ingested)
}

/// Read one trimmed line from stdin after printing a prompt. SSH-safe.
fn prompt_line(label: &str) -> anyhow::Result<String> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Split a comma-separated answer into trimmed, non-empty values.
fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

/// Build a lens policy through interactive prompts, then persist it. Schema
/// validation runs inside `lens::create`; a rejection prints field-level
/// errors and exits non-zero.
fn lens_create_interactive(vault: &Vault) -> anyhow::Result<()> {
    use tessera_core::artifact::Sensitivity;
    use tessera_core::lens::{self, LensError};
    use tessera_core::{ApprovalRule, DisclosureMode, LensPolicy};

    let name = prompt_line("Name: ")?;
    let spaces = parse_csv(&prompt_line("Space ids (comma-separated): ")?);
    let mut p = LensPolicy::new(name, spaces.into_iter().map(SpaceId).collect());

    p.disclosure_mode =
        match prompt_line("Disclosure mode [summary/excerpt/full] (summary): ")?.as_str() {
            "excerpt" => DisclosureMode::Excerpt,
            "full" => DisclosureMode::Full,
            _ => DisclosureMode::Summary,
        };
    if p.disclosure_mode == DisclosureMode::Excerpt {
        let raw = prompt_line("Max quote chars (800): ")?;
        p.max_quote_chars = Some(raw.parse().unwrap_or(800));
    }

    let ops = parse_csv(&prompt_line(
        "Operations [answer,draft,extract,cite] (answer): ",
    )?);
    if !ops.is_empty() {
        p.operations = ops;
    }

    p.sensitivity_ceiling = match prompt_line(
        "Sensitivity ceiling [public/internal/confidential/restricted] (internal): ",
    )?
    .as_str()
    {
        "public" => Sensitivity::Public,
        "confidential" => Sensitivity::Confidential,
        "restricted" => Sensitivity::Restricted,
        _ => Sensitivity::Internal,
    };

    p.approval_rule =
        match prompt_line("Approval rule [never/always/on_sensitive] (on_sensitive): ")?.as_str() {
            "never" => ApprovalRule::Never,
            "always" => ApprovalRule::Always,
            _ => ApprovalRule::OnSensitive,
        };

    let ttl = prompt_line("Default TTL minutes (60): ")?;
    if let Ok(n) = ttl.parse::<u32>() {
        if n >= 1 {
            p.default_ttl_minutes = n;
        }
    }

    p.media_types = parse_csv(&prompt_line(
        "Media types (MIME, comma-separated, optional): ",
    )?);
    p.tag_include = parse_csv(&prompt_line("Include tags (optional): ")?);
    p.tag_exclude = parse_csv(&prompt_line("Exclude tags (optional): ")?);

    match lens::create(vault, &p) {
        Ok(id) => {
            println!("Created lens {}  {}", id.0, p.name);
            Ok(())
        }
        Err(LensError::Invalid(msg)) => bail!("policy rejected:\n{msg}"),
        Err(e) => Err(e.into()),
    }
}

/// Open `initial` in `$EDITOR` (fallback `vi`) and return the edited text.
fn edit_in_editor(initial: &str, id: &str) -> anyhow::Result<String> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let path = std::env::temp_dir().join(format!("tessera-lens-{id}-{}.json", std::process::id()));
    std::fs::write(&path, initial)?;
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .with_context(|| format!("launching editor '{editor}'"))?;
    let contents = std::fs::read_to_string(&path);
    let _ = std::fs::remove_file(&path);
    if !status.success() {
        bail!("editor '{editor}' exited with failure; lens unchanged");
    }
    Ok(contents?)
}

/// Interactive review loop over pending artifacts. SSH-safe: plain stdin.
fn review_interactive(vault: &Vault) -> anyhow::Result<()> {
    use tessera_core::artifact::{self, ArtifactState, Sensitivity};

    let pending = artifact::list_by_state(vault, ArtifactState::Pending)?;
    if pending.is_empty() {
        println!("No pending artifacts.");
        return Ok(());
    }

    let stdin = std::io::stdin();
    for art in pending {
        println!(
            "\n{}  {}  [{}]  space={}  sensitivity={}",
            art.id.0,
            art.filename,
            art.media_type,
            art.space_id.0,
            art.sensitivity.as_str()
        );
        print!("[a]ccept  [t]ags+accept  [s]ensitivity+accept  [x]archive  [enter]skip  [q]uit > ");
        std::io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break; // EOF: stop reviewing
        }
        match line.trim() {
            "a" => {
                artifact::set_state(vault, &art.id, ArtifactState::Live)?;
                println!("{} → live", art.id.0);
            }
            "t" => {
                print!("tags (comma-separated) > ");
                std::io::stdout().flush()?;
                let mut tags = String::new();
                stdin.read_line(&mut tags)?;
                for tag in tags.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                    artifact::tag(vault, &art.id, tag)?;
                }
                artifact::set_state(vault, &art.id, ArtifactState::Live)?;
                println!("{} → live (tagged)", art.id.0);
            }
            "s" => {
                print!("sensitivity (public/internal/confidential/restricted) > ");
                std::io::stdout().flush()?;
                let mut level = String::new();
                stdin.read_line(&mut level)?;
                let sensitivity = match level.trim() {
                    "public" => Sensitivity::Public,
                    "confidential" => Sensitivity::Confidential,
                    "restricted" => Sensitivity::Restricted,
                    _ => Sensitivity::Internal,
                };
                artifact::set_sensitivity(vault, &art.id, sensitivity)?;
                artifact::set_state(vault, &art.id, ArtifactState::Live)?;
                println!("{} → live ({})", art.id.0, sensitivity.as_str());
            }
            "x" => {
                artifact::set_state(vault, &art.id, ArtifactState::Archived)?;
                println!("{} → archived", art.id.0);
            }
            "q" => break,
            _ => println!("skipped"),
        }
    }
    Ok(())
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
        Command::Inbox { action } => {
            let vault = open_vault(&vault_path)?;
            match action {
                InboxCommand::Add { paths } => {
                    let staged = tessera_core::inbox::add(&vault, &paths)?;
                    for path in staged {
                        println!("Staged {}", path.display());
                    }
                    Ok(())
                }
                InboxCommand::Status => {
                    let staged = tessera_core::inbox::status(&vault)?;
                    if staged.is_empty() {
                        println!("Inbox is empty.");
                    } else {
                        for path in staged {
                            println!("{}", path.display());
                        }
                    }
                    Ok(())
                }
                InboxCommand::Process { space } => {
                    let space = resolve_space(&vault, space)?;
                    run_inbox_pipeline(&vault, &space)?;
                    Ok(())
                }
            }
        }
        Command::Review { accept_all } => {
            let vault = open_vault(&vault_path)?;
            if accept_all {
                use tessera_core::artifact::{self, ArtifactState};
                let pending = artifact::list_by_state(&vault, ArtifactState::Pending)?;
                if pending.is_empty() {
                    println!("No pending artifacts.");
                    return Ok(());
                }
                let count = pending.len();
                for art in pending {
                    artifact::set_state(&vault, &art.id, ArtifactState::Live)?;
                }
                println!("{count} artifact(s) → live");
                Ok(())
            } else {
                review_interactive(&vault)
            }
        }
        Command::Import {
            accept,
            space,
            paths,
        } => {
            let vault = open_vault(&vault_path)?;
            let space = resolve_space(&vault, space)?;
            tessera_core::inbox::add(&vault, &paths)?;
            let ingested = run_inbox_pipeline(&vault, &space)?;
            if accept {
                for id in &ingested {
                    tessera_core::artifact::set_state(
                        &vault,
                        id,
                        tessera_core::artifact::ArtifactState::Live,
                    )?;
                    println!("{} → live", id.0);
                }
            }
            Ok(())
        }
        Command::Index => {
            let vault = open_vault(&vault_path)?;
            let embedder = load_embedder()?;
            let count = tessera_core::search::embed_missing(&vault, &embedder)?;
            println!("Embedded {count} chunk(s).");
            Ok(())
        }
        Command::Query { text, top_k, lens } => {
            let vault = open_vault(&vault_path)?;
            let embedder = load_embedder()?;
            let results = match lens {
                Some(lens_id) => {
                    let policy = tessera_core::lens::get(&vault, &tessera_core::LensId(lens_id))?;
                    eprintln!(
                        "(lens {}  {}  disclosure={})",
                        policy.id.0,
                        policy.name,
                        policy.disclosure_mode.as_str()
                    );
                    tessera_core::search::search_with_lens(
                        &vault, &embedder, &policy, &text, top_k,
                    )?
                }
                None => tessera_core::search::query(
                    &vault,
                    &embedder,
                    &text,
                    &tessera_core::search::owner_constraints(),
                    top_k,
                )?,
            };
            if results.is_empty() {
                println!("No results.");
            }
            for (rank, r) in results.iter().enumerate() {
                println!(
                    "{}. {}  (score {:.3})\n   {}  bytes {}..{}",
                    rank + 1,
                    r.artifact_title,
                    r.relevance_score,
                    r.chunk_id,
                    r.byte_range.0,
                    r.byte_range.1
                );
            }
            Ok(())
        }
        Command::Summarize { artifact, redo } => {
            let vault = open_vault(&vault_path)?;
            let id = tessera_core::ArtifactId(artifact);
            let summary = tessera_core::summary::generate(&vault, &id, redo)?;
            let text = tessera_core::summary::get_summary_text(&vault, &id)?.unwrap_or_default();
            println!(
                "{}  ({}@{}, {})",
                summary.blob_hash, summary.summarizer, summary.summarizer_version, summary.locality
            );
            println!("{text}");
            Ok(())
        }
        Command::Lens { action } => {
            use tessera_core::lens::{self, LensError};
            use tessera_core::LensId;
            let vault = open_vault(&vault_path)?;
            match action {
                LensCommand::List => {
                    for l in lens::list(&vault)? {
                        println!(
                            "{}  {}  [{}]  spaces={}",
                            l.id.0,
                            l.name,
                            l.disclosure_mode.as_str(),
                            l.space_ids.len()
                        );
                    }
                    Ok(())
                }
                LensCommand::Show { id } => {
                    let p = lens::get(&vault, &LensId(id))?;
                    println!("{}", lens::to_json(&p)?);
                    Ok(())
                }
                LensCommand::Create => lens_create_interactive(&vault),
                LensCommand::Edit { id, file } => {
                    let lid = LensId(id.clone());
                    let current = lens::get(&vault, &lid)?;
                    let new_json = match file {
                        Some(path) => std::fs::read_to_string(&path)
                            .with_context(|| format!("reading {}", path.display()))?,
                        None => edit_in_editor(&lens::to_json(&current)?, &id)?,
                    };
                    let mut edited = match lens::from_json(&new_json) {
                        Ok(p) => p,
                        Err(LensError::Invalid(msg)) => bail!("policy rejected:\n{msg}"),
                        Err(e) => return Err(e.into()),
                    };
                    // The row is selected by id; an edit must not retarget it.
                    edited.id = lid;
                    lens::update(&vault, &edited)?;
                    println!("Updated lens {id}");
                    Ok(())
                }
                LensCommand::Delete { id } => {
                    lens::delete(&vault, &LensId(id.clone()))?;
                    println!("Deleted lens {id}");
                    Ok(())
                }
            }
        }
        Command::Eval { golden, gate } => {
            let vault = open_vault(&vault_path)?;
            let embedder = load_embedder()?;
            let items = tessera_core::eval::parse_golden(&std::fs::read_to_string(&golden)?)?;
            let report = tessera_core::eval::run(
                &vault,
                &embedder,
                &items,
                &tessera_core::search::owner_constraints(),
            )?;

            println!("questions:  {}", report.questions);
            println!("Recall@5:   {:.3}", report.recall_at_5);
            println!("Recall@10:  {:.3}", report.recall_at_10);
            println!("MRR:        {:.3}", report.mrr);
            for q in &report.per_question {
                println!(
                    "  r@10={:.2} rr={:.2}  {}",
                    q.recall_at_10, q.reciprocal_rank, q.question
                );
            }
            println!("{}", serde_json::to_string(&report)?);

            if report.recall_at_10 < gate {
                bail!(
                    "gate FAILED: Recall@10 {:.3} < {gate:.2}",
                    report.recall_at_10
                );
            }
            println!("gate PASSED (Recall@10 ≥ {gate:.2})");
            Ok(())
        }
        Command::Model { action } => {
            use tessera_core::embed::onnx;
            let dir = onnx::default_model_dir();
            match action {
                ModelCommand::Status => {
                    println!(
                        "{} at {}: {}",
                        onnx::MODEL_NAME,
                        dir.display(),
                        if onnx::model_present(&dir) {
                            "installed"
                        } else {
                            "missing — run `tessera model fetch`"
                        }
                    );
                    Ok(())
                }
                ModelCommand::Fetch => {
                    std::fs::create_dir_all(&dir)?;
                    let mut lock = String::new();
                    for (name, url) in onnx::MODEL_FILES {
                        let target = dir.join(name);
                        if target.is_file() {
                            println!("{name}: already present");
                        } else {
                            println!("Fetching {name} …");
                            let status = std::process::Command::new("curl")
                                .args(["-L", "--fail", "--progress-bar", "-o"])
                                .arg(&target)
                                .arg(url)
                                .status()
                                .context("running curl")?;
                            if !status.success() {
                                bail!("download failed for {name}");
                            }
                        }
                        let hash = blake3::hash(&std::fs::read(&target)?);
                        lock.push_str(&format!("{}  {}\n", hash.to_hex(), name));
                    }
                    // Trust-on-first-fetch: pin what we downloaded.
                    std::fs::write(dir.join("models.lock"), lock)?;
                    println!("Model ready at {}", dir.display());
                    Ok(())
                }
            }
        }
        Command::Diag { artifact } => {
            println!("tessera v{}", env!("CARGO_PKG_VERSION"));
            println!(
                "pandoc: {}",
                if tessera_core::extract::pandoc_available() {
                    "available"
                } else {
                    "missing (DOCX extraction disabled)"
                }
            );
            match Vault::open(&vault_path, &passphrase()?) {
                Ok(vault) => {
                    println!("vault: {}", vault.path().display());
                    println!("format_version: {}", vault.manifest().format_version);
                    println!("spaces: {}", space::list(&vault)?.len());
                    let orphans = tessera_core::provenance::orphaned_derivations(&vault)?;
                    println!(
                        "provenance: {}",
                        if orphans.is_empty() {
                            "ok (no orphaned derivations)".to_string()
                        } else {
                            format!("⚠ {} orphaned derivation(s)", orphans.len())
                        }
                    );
                    if let Some(id) = artifact {
                        let artifact_id = tessera_core::ArtifactId(id);
                        println!("provenance chain:");
                        for rec in tessera_core::provenance::chain_for(&vault, &artifact_id)? {
                            println!(
                                "  {} ← {} ({}, {})",
                                rec.derived_blob_hash,
                                rec.tool,
                                rec.tool_version.as_deref().unwrap_or("?"),
                                rec.locality
                            );
                        }
                    }
                }
                Err(e) => println!("vault: unavailable ({e})"),
            }
            Ok(())
        }
    }
}
