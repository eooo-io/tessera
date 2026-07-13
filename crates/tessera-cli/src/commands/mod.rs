//! CLI command implementations.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::Subcommand;
use tessera_core::crypto::KdfParams;
use tessera_core::{space, SpaceId, Vault};
use zeroize::Zeroizing;

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
    /// Inspect conversation ingestion runs and per-item quarantine results
    Conversation {
        #[command(subcommand)]
        action: ConversationCommand,
    },
    /// Review quarantined artifacts
    Review {
        /// Review and accept every pending artifact as one explicit batch
        #[arg(long)]
        accept_all: bool,
        /// Confirm the displayed batch non-interactively
        #[arg(long, requires = "accept_all")]
        yes: bool,
        /// Permit promotion of unsupported, failed, or empty processing results
        #[arg(long, requires = "accept_all")]
        allow_incomplete: bool,
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
        /// Declared purpose recorded in the receipt (with --lens)
        #[arg(long, default_value = "cli query")]
        purpose: String,
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
    /// Authorize agent pairings for the guardian
    Pair {
        #[command(subcommand)]
        action: PairCommand,
    },
    /// Inspect and verify access receipts
    Receipts {
        #[command(subcommand)]
        action: ReceiptsCommand,
    },
    /// Inspect and revoke live guardian sessions
    Sessions {
        #[command(subcommand)]
        action: SessionsCommand,
    },
    /// Guardian management (lock / status)
    Guardian {
        #[command(subcommand)]
        action: GuardianCommand,
    },
    /// Manage portable recovery/rotation keyslots
    Key {
        #[command(subcommand)]
        action: KeyCommand,
    },
    /// Run golden-set retrieval evaluation (exits non-zero below gate)
    Eval {
        /// Path to the golden set JSON: [{"question": "...", "expected": ["file.md"]}]
        #[arg(long)]
        golden: std::path::PathBuf,
        /// Recall@10 gate threshold
        #[arg(long, default_value_t = 0.70)]
        gate: f64,
        /// Write a sanitized aggregate report (private-eval-v1 plans only)
        #[arg(long)]
        report: Option<std::path::PathBuf>,
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
        /// Emit the versioned, content-free integrity report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Create and verify a consistency-barrier portable vault backup
    Backup {
        /// New .tessera bundle path; must not already exist
        destination: std::path::PathBuf,
    },
    /// Rebuild only derived text/chunks/summaries from authenticated originals
    RepairDerived {
        /// Confirm artifacts will return to pending and require review/reindex
        #[arg(long)]
        yes: bool,
    },
}

#[cfg(test)]
mod model_install_tests {
    use super::activate_model;

    #[test]
    fn failed_verification_leaves_current_installation_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("all-MiniLM-L6-v2");
        std::fs::create_dir(&target).expect("active dir");
        std::fs::write(target.join("active-marker"), b"last working install").expect("marker");

        let error = activate_model(&target, |staging| {
            std::fs::write(staging.join("model.onnx"), b"substituted")?;
            std::fs::write(staging.join("tokenizer.json"), b"{}")?;
            Ok(())
        })
        .expect_err("untrusted stage must fail");

        assert!(error.to_string().contains("verification"));
        assert_eq!(
            std::fs::read(target.join("active-marker")).expect("active marker"),
            b"last working install"
        );
    }
}

#[derive(Subcommand)]
pub enum ModelCommand {
    /// Download and verify the embedding model from its pinned source
    Fetch,
    /// Verify and atomically activate model files copied from another machine
    Install {
        /// Directory containing model.onnx and tokenizer.json
        #[arg(long)]
        source: std::path::PathBuf,
    },
    /// Build or resume a shadow vector index, then atomically activate it
    Reindex {
        /// Pause after this many new chunks; rerun to resume
        #[arg(long)]
        max_chunks: Option<usize>,
    },
    /// Show durable shadow-index progress
    ReindexStatus,
    /// Request cooperative cancellation without touching the active index
    ReindexCancel,
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
    /// Fetch one explicit public article URL and stage clean Markdown
    AddUrl {
        /// Canonical article URL (redirects are not followed)
        url: String,
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
pub enum ConversationCommand {
    /// Encrypt and import a Claude Code JSONL session export
    ImportClaudeCode {
        /// Claude Code session JSONL file
        path: PathBuf,
        /// Target space id (defaults to the sole space if only one exists)
        #[arg(long)]
        space: Option<String>,
        /// Stop cleanly after this many pending sessions
        #[arg(long)]
        max_items: Option<usize>,
        /// Emit the content-free run report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Resume an interrupted Claude Code ingestion run from its encrypted source
    ResumeClaudeCode {
        /// Existing interrupted ingestion run id
        run_id: String,
        /// Stop cleanly after this many additional pending sessions
        #[arg(long)]
        max_items: Option<usize>,
        /// Emit the content-free run report as JSON
        #[arg(long)]
        json: bool,
    },
    /// Filter whitelisted conversation source metadata
    Metadata {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        repository: Option<String>,
        #[arg(long)]
        git_branch: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List source-neutral ingestion runs, newest first
    Runs {
        /// Emit complete content-free run reports as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show one ingestion run and every per-conversation outcome
    Show {
        /// Ingestion run id
        id: String,
        /// Emit the content-free run report as JSON
        #[arg(long)]
        json: bool,
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
pub enum PairCommand {
    /// Approve an immutable lens revision + audit-purpose pairing
    Add {
        /// Lens id the pairing grants access through
        #[arg(long)]
        lens: String,
        /// Declared purpose for the pairing
        #[arg(long)]
        purpose: String,
        /// Agent name (free text, recorded in receipts)
        #[arg(long, default_value = "agent")]
        agent: String,
        /// Session TTL in minutes (defaults to the lens's default)
        #[arg(long)]
        ttl: Option<u32>,
        /// Registered OAuth client id for remote HTTP access
        #[arg(long)]
        oauth_client: Option<String>,
    },
    /// List all pairings
    List,
    /// Revoke a pairing
    Revoke {
        /// Pairing id
        id: String,
    },
}

#[derive(Subcommand)]
pub enum SessionsCommand {
    /// List all sessions and their status
    List,
    /// Revoke a session (takes effect on the guardian's next tool call)
    Revoke {
        /// Session id (omit when using --all)
        id: Option<String>,
        /// Revoke every active session
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
pub enum GuardianCommand {
    /// Signal every running Guardian to exit and drop its unlocked key
    Lock,
    /// Show active sessions
    Status,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Show keyslot indexes (never key material)
    List,
    /// Add a new recovery/rotation passphrase
    Add,
    /// Remove a keyslot after verifying another slot opens the vault
    Remove {
        index: usize,
        /// Confirm the recovery-sensitive removal
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum ReceiptsCommand {
    /// List all receipts, oldest first
    List,
    /// Print one receipt as JSON
    Show {
        /// Receipt id
        id: String,
    },
    /// Export a receipt as JSON (default) or standalone HTML
    Export {
        /// Receipt id
        id: String,
        /// Emit HTML instead of JSON
        #[arg(long)]
        html: bool,
        /// Write to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify the hash chain over all receipts
    Verify,
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

/// Owner CLI passphrase: explicit automation environment fallback, otherwise
/// a no-echo prompt on the controlling terminal. The returned buffer zeroizes
/// on drop after the vault has derived/unwrapped its DEK.
fn passphrase() -> anyhow::Result<Zeroizing<String>> {
    if let Ok(pass) = std::env::var("TESSERA_PASSPHRASE") {
        return Ok(Zeroizing::new(pass));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(
        "Vault passphrase: ",
    )?))
}

fn confirmed_new_passphrase() -> anyhow::Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password("New keyslot passphrase: ")?);
    if first.is_empty() {
        bail!("refusing an empty keyslot passphrase");
    }
    let second = Zeroizing::new(rpassword::prompt_password("Confirm new passphrase: ")?);
    if first.as_str() != second.as_str() {
        bail!("new keyslot passphrases do not match");
    }
    Ok(first)
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
                tessera_core::review::resolve_processing_error(vault, artifact_id, "extract")?;
                if let Err(e) = tessera_core::chunk::chunk_derived_text(
                    vault,
                    &derived,
                    &tessera_core::chunk::ChunkParams::default(),
                ) {
                    tessera_core::review::record_processing_error(
                        vault,
                        artifact_id,
                        "chunk",
                        &e.to_string(),
                    )?;
                    eprintln!("warning: chunking failed for {}: {e}", path.display());
                } else {
                    tessera_core::review::resolve_processing_error(vault, artifact_id, "chunk")?;
                }
                // Summary powers the `summary` disclosure mode; best-effort.
                if let Err(e) = tessera_core::summary::generate(vault, artifact_id, false) {
                    tessera_core::review::record_processing_error(
                        vault,
                        artifact_id,
                        "summary",
                        &e.to_string(),
                    )?;
                    eprintln!("warning: summary failed for {}: {e}", path.display());
                } else {
                    tessera_core::review::resolve_processing_error(vault, artifact_id, "summary")?;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tessera_core::review::record_processing_error(
                    vault,
                    artifact_id,
                    "extract",
                    &e.to_string(),
                )?;
                eprintln!("warning: extraction failed for {}: {e}", path.display());
            }
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

/// Populate a sibling staging directory, verify every byte, then switch it
/// into place. The current installation remains active until verification
/// succeeds, and is restored if activation itself fails.
fn activate_model(
    target: &std::path::Path,
    populate: impl FnOnce(&std::path::Path) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use tessera_core::embed::onnx;

    let parent = target
        .parent()
        .context("model target has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let stem = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("model");
    let staging = parent.join(format!(".{stem}.staging-{}-{nonce}", std::process::id()));
    let backup = parent.join(format!(".{stem}.backup-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&staging)?;

    let prepared = (|| {
        populate(&staging)?;
        onnx::verify_model_dir(&staging)?;
        std::fs::write(
            staging.join("trusted-manifest.json"),
            onnx::TRUSTED_MANIFEST_JSON,
        )?;
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = prepared {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }

    let had_active = target.exists();
    if had_active {
        std::fs::rename(target, &backup).context("moving current model to rollback slot")?;
    }
    if let Err(error) = std::fs::rename(&staging, target) {
        if had_active {
            let _ = std::fs::rename(&backup, target);
        }
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error).context("activating verified model");
    }
    if had_active {
        std::fs::remove_dir_all(&backup).context("removing retired model installation")?;
    }
    Ok(())
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

fn terminal_safe(text: &str) -> String {
    text.chars()
        .flat_map(|ch| match ch {
            '\n' | '\t' => ch.to_string().chars().collect::<Vec<_>>(),
            ch if ch.is_control() => ch.escape_default().collect(),
            ch => vec![ch],
        })
        .collect()
}

fn print_review_item(item: &tessera_core::review::ReviewItem) {
    println!(
        "\n{}  {}  [{}]  version={}  space={}  sensitivity={}",
        item.artifact.id.0,
        terminal_safe(&item.artifact.filename),
        terminal_safe(&item.artifact.media_type),
        item.version,
        item.artifact.space_id.0,
        item.artifact.sensitivity.as_str()
    );
    println!(
        "original: encrypted={} artifact_version={} size={} hash={} behavior={}",
        item.encrypted_original_present,
        item.artifact_version_id,
        item.original_size_bytes,
        item.original_blob_hash,
        if item.version == 1 {
            "initial"
        } else {
            "replacement/versioned"
        }
    );
    println!(
        "processing: extractor={} chunks={} embeddings={} summary={}",
        item.extractor
            .as_deref()
            .map(|name| format!(
                "{}@{}",
                terminal_safe(name),
                terminal_safe(item.extractor_version.as_deref().unwrap_or("unknown"))
            ))
            .unwrap_or_else(|| "none".into()),
        item.chunk_count,
        item.embedding_count,
        item.summary_present
    );
    println!(
        "classification: tags={}  suggested=none (v0.1)",
        if item.tags.is_empty() {
            "(none)".into()
        } else {
            item.tags
                .iter()
                .map(|tag| terminal_safe(tag))
                .collect::<Vec<_>>()
                .join(",")
        }
    );
    if let Some(preview) = &item.preview {
        println!("owner preview:\n{}", terminal_safe(preview));
    } else {
        println!("owner preview: unavailable");
    }
    for provenance in &item.provenance {
        println!(
            "provenance: {} {}@{} locality={} source={}",
            provenance.id,
            terminal_safe(&provenance.tool),
            terminal_safe(provenance.tool_version.as_deref().unwrap_or("unknown")),
            terminal_safe(&provenance.locality),
            provenance
                .source_artifact_version_id
                .as_deref()
                .unwrap_or("none")
        );
        if let Some(source_url) = &provenance.source_url {
            println!("  web source: {}", terminal_safe(source_url));
        }
    }
    for error in &item.processing_errors {
        println!(
            "processing error: stage={} at={} detail={}",
            terminal_safe(&error.stage),
            terminal_safe(&error.occurred_at),
            terminal_safe(&error.message)
        );
    }
    for warning in &item.warnings {
        println!("WARNING: {}", terminal_safe(warning));
    }
}

fn confirm_incomplete(item: &tessera_core::review::ReviewItem) -> anyhow::Result<bool> {
    if item.ready_for_promotion {
        return Ok(true);
    }
    Ok(prompt_line("Type ACCEPT INCOMPLETE to override > ")? == "ACCEPT INCOMPLETE")
}

/// Interactive review loop over pending artifacts. SSH-safe: plain stdin.
fn review_interactive(vault: &Vault) -> anyhow::Result<()> {
    use tessera_core::artifact::{self, ArtifactState, Sensitivity};

    let pending = artifact::list_by_state(vault, ArtifactState::Pending)?;
    if pending.is_empty() {
        println!("No pending artifacts.");
        return Ok(());
    }

    for art in pending {
        let mut item = tessera_core::review::inspect(vault, &art.id, 400)?;
        loop {
            print_review_item(&item);
            let action = prompt_line(
                "[a]ccept  [e]dit+accept  longer [p]review  [r]etry  [x]archive  [enter]skip  [q]uit > ",
            )?;
            match action.as_str() {
                "a" => {
                    if !confirm_incomplete(&item)? {
                        println!("not promoted");
                        continue;
                    }
                    tessera_core::review::classify_and_promote(
                        vault,
                        &art.id,
                        None,
                        None,
                        None,
                        "owner:review_accept",
                    )?;
                    println!("{} → live", art.id.0);
                    break;
                }
                "e" => {
                    if !confirm_incomplete(&item)? {
                        println!("not promoted");
                        continue;
                    }
                    let space = prompt_line("space id (blank keeps current) > ")?;
                    let tags = prompt_line("tags, comma-separated (blank keeps current) > ")?;
                    let sensitivity = prompt_line(
                        "sensitivity public/internal/confidential/restricted (blank keeps current) > ",
                    )?;
                    let space = (!space.is_empty()).then_some(SpaceId(space));
                    let tags = (!tags.is_empty()).then(|| parse_csv(&tags));
                    let sensitivity = match sensitivity.as_str() {
                        "public" => Some(Sensitivity::Public),
                        "internal" => Some(Sensitivity::Internal),
                        "confidential" => Some(Sensitivity::Confidential),
                        "restricted" => Some(Sensitivity::Restricted),
                        "" => None,
                        _ => bail!("unknown sensitivity; artifact remains pending"),
                    };
                    tessera_core::review::classify_and_promote(
                        vault,
                        &art.id,
                        space.as_ref(),
                        tags.as_deref(),
                        sensitivity,
                        "owner:review_edit_accept",
                    )?;
                    println!("{} → live (classification updated)", art.id.0);
                    break;
                }
                "p" => {
                    item = tessera_core::review::inspect(vault, &art.id, 4000)?;
                }
                "r" => match tessera_core::review::retry_processing(vault, &art.id) {
                    Ok(retried) => {
                        item = retried;
                        println!("processing retry completed");
                    }
                    Err(error) => println!("processing retry failed: {error}"),
                },
                "x" => {
                    artifact::set_state_by(
                        vault,
                        &art.id,
                        ArtifactState::Archived,
                        "owner:review_archive",
                    )?;
                    println!("{} → archived", art.id.0);
                    break;
                }
                "q" => return Ok(()),
                _ => {
                    println!("skipped");
                    break;
                }
            }
        }
    }
    Ok(())
}

fn review_batch(vault: &Vault, yes: bool, allow_incomplete: bool) -> anyhow::Result<()> {
    use tessera_core::artifact::{self, ArtifactState};

    let pending = artifact::list_by_state(vault, ArtifactState::Pending)?;
    if pending.is_empty() {
        println!("No pending artifacts.");
        return Ok(());
    }
    let mut items = Vec::with_capacity(pending.len());
    println!("Pending batch:");
    for artifact in pending {
        let item = tessera_core::review::inspect(vault, &artifact.id, 160)?;
        println!(
            "- {} {} ready={} warnings={}",
            artifact.id.0,
            terminal_safe(&artifact.filename),
            item.ready_for_promotion,
            item.warnings.len()
        );
        items.push(item);
    }
    let incomplete = items
        .iter()
        .filter(|item| !item.ready_for_promotion)
        .count();
    if incomplete > 0 && !allow_incomplete {
        bail!(
            "refusing bulk promotion: {incomplete} artifact(s) have unsupported, failed, or empty processing; inspect individually or pass --allow-incomplete"
        );
    }
    if !yes {
        let expected = format!("PROMOTE {}", items.len());
        if prompt_line(&format!("Type {expected} to confirm > "))? != expected {
            println!("batch cancelled; all artifacts remain pending");
            return Ok(());
        }
    }
    let artifact_ids = items
        .iter()
        .map(|item| item.artifact.id.clone())
        .collect::<Vec<_>>();
    tessera_core::review::promote_batch(vault, &artifact_ids, "owner:review_batch_accept")?;
    println!("{} artifact(s) → live", items.len());
    Ok(())
}

fn print_conversation_run(run: &tessera_core::conversation::IngestionRunReport, items: bool) {
    println!(
        "{}  {:?}  source={} space={} parser={}@{} normalizer={}@{} discovered={} imported={} unchanged={} updated={} quarantined={} failed={} checkpoint={} retries={}",
        run.id,
        run.status,
        run.source_product.as_str(),
        run.target_space_id,
        run.parser.name,
        run.parser.version,
        run.normalizer.name,
        run.normalizer.version,
        run.discovered,
        run.imported,
        run.unchanged,
        run.updated,
        run.quarantined,
        run.failed,
        run.checkpoint_ordinal,
        run.retry_count,
    );
    if let Some(summary) = &run.safe_error_summary {
        println!(
            "  run error: {} — {}",
            run.error_code.as_deref().unwrap_or("unknown"),
            terminal_safe(summary)
        );
    }
    if items {
        for item in &run.items {
            println!(
                "  [{}] {}  {:?}  conversation={} persisted={} previous={} retries={}",
                item.ordinal,
                item.id,
                item.status,
                terminal_safe(&item.source_conversation_id),
                item.persisted_conversation_id.as_deref().unwrap_or("-"),
                item.previous_persisted_conversation_id
                    .as_deref()
                    .unwrap_or("-"),
                item.retry_count,
            );
            if let Some(summary) = &item.safe_error_summary {
                println!(
                    "       action: inspect the source structure and target classification; after correction, start a new run; {} — {}",
                    item.error_code.as_deref().unwrap_or("unknown"),
                    terminal_safe(summary)
                );
            }
        }
    }
    match run.status {
        tessera_core::conversation::IngestionRunStatus::Interrupted => println!(
            "  next: resume run {} through its source adapter; completed items remain idempotent",
            run.id
        ),
        tessera_core::conversation::IngestionRunStatus::Failed => println!(
            "  next: correct or upgrade the source adapter, then start a new run; this run remains immutable evidence"
        ),
        tessera_core::conversation::IngestionRunStatus::Running
        | tessera_core::conversation::IngestionRunStatus::Completed => {}
    }
}

fn print_conversation_metadata(item: &tessera_core::conversation::ConversationMetadata) {
    println!(
        "{} source={} session={} project={} repository={} branch={} created={} updated={}",
        item.persisted_conversation_id,
        item.source_product.as_str(),
        terminal_safe(&item.session_id),
        item.project
            .as_deref()
            .map(terminal_safe)
            .unwrap_or_else(|| "-".into()),
        item.repository
            .as_deref()
            .map(terminal_safe)
            .unwrap_or_else(|| "-".into()),
        item.git_branch
            .as_deref()
            .map(terminal_safe)
            .unwrap_or_else(|| "-".into()),
        item.source_created_at.as_deref().unwrap_or("-"),
        item.source_updated_at.as_deref().unwrap_or("-"),
    );
}

fn parse_source_product(
    value: Option<String>,
) -> anyhow::Result<Option<tessera_core::conversation::SourceProduct>> {
    value
        .map(|value| match value.as_str() {
            "claude_code" => Ok(tessera_core::conversation::SourceProduct::ClaudeCode),
            "claude" => Ok(tessera_core::conversation::SourceProduct::Claude),
            "chatgpt" => Ok(tessera_core::conversation::SourceProduct::Chatgpt),
            _ => bail!(
                "unknown conversation source {value}; expected claude_code, claude, or chatgpt"
            ),
        })
        .transpose()
}

fn stage_claude_code_source(
    vault: &Vault,
    space: &SpaceId,
    path: &std::path::Path,
) -> anyhow::Result<(String, String)> {
    let source = std::fs::read(path)
        .with_context(|| format!("reading Claude Code source {}", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("claude-code-session.jsonl")
        .to_owned();
    let (_, version) = tessera_core::artifact::register_encrypted_bytes(
        vault,
        space,
        &filename,
        "application/x-ndjson",
        tessera_core::artifact::Sensitivity::Restricted,
        &source,
    )?;
    Ok((version.id, filename))
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
            match action {
                InboxCommand::Add { paths } => {
                    let vault = open_vault(&vault_path)?;
                    let staged = tessera_core::inbox::add(&vault, &paths)?;
                    for path in staged {
                        println!("Staged {}", path.display());
                    }
                    Ok(())
                }
                InboxCommand::AddUrl { url } => {
                    // Fetch before unlocking the vault so network activity
                    // never extends the lifetime of the in-memory DEK.
                    let fetched = tessera_core::web::fetch_article(&url)?;
                    let title = fetched.article.title.clone();
                    let vault = open_vault(&vault_path)?;
                    let staged = tessera_core::web::stage_article(&vault, &fetched)?;
                    println!(
                        "Staged web article {}  {}",
                        terminal_safe(&title),
                        staged.display()
                    );
                    Ok(())
                }
                InboxCommand::Status => {
                    let vault = open_vault(&vault_path)?;
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
                    let vault = open_vault(&vault_path)?;
                    let space = resolve_space(&vault, space)?;
                    run_inbox_pipeline(&vault, &space)?;
                    Ok(())
                }
            }
        }
        Command::Conversation { action } => {
            let vault = open_vault(&vault_path)?;
            match action {
                ConversationCommand::ImportClaudeCode {
                    path,
                    space,
                    max_items,
                    json,
                } => {
                    let space = resolve_space(&vault, space)?;
                    let (source_version, source_identity) =
                        stage_claude_code_source(&vault, &space, &path)?;
                    let report = tessera_core::conversation::ingest(
                        &vault,
                        &space,
                        &source_version,
                        &tessera_core::conversation::ClaudeCodeParser::new(Some(source_identity)),
                        &tessera_core::conversation::IngestionOptions {
                            max_items,
                            resume_run_id: None,
                        },
                    )?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        print_conversation_run(&report, true);
                    }
                    Ok(())
                }
                ConversationCommand::ResumeClaudeCode {
                    run_id,
                    max_items,
                    json,
                } => {
                    let prior = tessera_core::conversation::get_ingestion_run(&vault, &run_id)?;
                    if prior.source_product != tessera_core::conversation::SourceProduct::ClaudeCode
                    {
                        bail!("ingestion run {run_id} is not a Claude Code source");
                    }
                    let report = tessera_core::conversation::ingest(
                        &vault,
                        &SpaceId(prior.target_space_id),
                        &prior.source_artifact_version_id,
                        &tessera_core::conversation::ClaudeCodeParser::new(prior.source_export_id),
                        &tessera_core::conversation::IngestionOptions {
                            max_items,
                            resume_run_id: Some(run_id),
                        },
                    )?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        print_conversation_run(&report, true);
                    }
                    Ok(())
                }
                ConversationCommand::Metadata {
                    source,
                    session,
                    project,
                    repository,
                    git_branch,
                    json,
                } => {
                    let metadata = tessera_core::conversation::list_conversation_metadata(
                        &vault,
                        &tessera_core::conversation::ConversationMetadataFilter {
                            source_product: parse_source_product(source)?,
                            session_id: session,
                            project,
                            repository,
                            git_branch,
                        },
                    )?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&metadata)?);
                    } else if metadata.is_empty() {
                        println!("No matching conversation metadata.");
                    } else {
                        for item in &metadata {
                            print_conversation_metadata(item);
                        }
                    }
                    Ok(())
                }
                ConversationCommand::Runs { json } => {
                    let runs = tessera_core::conversation::list_ingestion_runs(&vault)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&runs)?);
                    } else if runs.is_empty() {
                        println!("No conversation ingestion runs.");
                    } else {
                        for run in &runs {
                            print_conversation_run(run, false);
                        }
                    }
                    Ok(())
                }
                ConversationCommand::Show { id, json } => {
                    let run = tessera_core::conversation::get_ingestion_run(&vault, &id)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&run)?);
                    } else {
                        print_conversation_run(&run, true);
                    }
                    Ok(())
                }
            }
        }
        Command::Review {
            accept_all,
            yes,
            allow_incomplete,
        } => {
            let vault = open_vault(&vault_path)?;
            if accept_all {
                review_batch(&vault, yes, allow_incomplete)
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
        Command::Query {
            text,
            top_k,
            lens,
            purpose,
        } => {
            let vault = open_vault(&vault_path)?;
            let embedder = load_embedder()?;
            match lens {
                // Under a lens, the query runs inside a recording Session:
                // retrieval + disclosure + receipt journaling are one step.
                Some(lens_id) => {
                    let policy = tessera_core::lens::get(&vault, &tessera_core::LensId(lens_id))?;
                    eprintln!(
                        "(lens {}  {}  disclosure={})",
                        policy.id.0,
                        policy.name,
                        policy.disclosure_mode.as_str()
                    );
                    let agent = tessera_core::receipt::AgentRef {
                        agent_id: "cli".into(),
                        name: "cli-user".into(),
                    };
                    let mut session = tessera_core::receipt::Session::open(
                        &vault, agent, &policy, purpose, false,
                    )?;
                    let rendered = session.query(&embedder, &text, top_k)?;
                    if rendered.is_empty() {
                        println!("No results.");
                    }
                    for (rank, rc) in rendered.iter().enumerate() {
                        let title = rc.title.as_deref().unwrap_or("(metadata withheld)");
                        println!("{}. {}  [{}]", rank + 1, title, rc.mode.as_str());
                        if rc.full_disclosure {
                            eprintln!("   ⚠ FULL disclosure — {} bytes", rc.bytes_disclosed);
                        }
                        println!("   {}", rc.body.replace('\n', "\n   "));
                        if let Some((s, e)) = rc.disclosed_range {
                            println!("   (bytes {s}..{e})");
                        }
                        if let Some(range) = rc.timestamp_range {
                            println!("   (media {}..{})", range.start_label(), range.end_label());
                        }
                        if let Some(source_url) = &rc.source_url {
                            println!("   source {}", terminal_safe(source_url));
                        }
                    }
                    let receipt = session.finalize()?;
                    eprintln!(
                        "(receipt {} — verify with `tessera receipts verify`)",
                        receipt.receipt_id
                    );
                }
                // Owner view: raw citations, everything live.
                None => {
                    let results = tessera_core::search::query(
                        &vault,
                        &embedder,
                        &text,
                        &tessera_core::search::owner_constraints(),
                        top_k,
                    )?;
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
                        if let Some(range) = r.timestamp_range {
                            println!("   media {}..{}", range.start_label(), range.end_label());
                        }
                        if let Some(source_url) = &r.source_url {
                            println!("   source {}", terminal_safe(source_url));
                        }
                    }
                }
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
        Command::Pair { action } => {
            use tessera_core::pairing;
            use tessera_core::LensId;
            let vault = open_vault(&vault_path)?;
            match action {
                PairCommand::Add {
                    lens,
                    purpose,
                    agent,
                    ttl,
                    oauth_client,
                } => {
                    let lens_id = LensId(lens);
                    // Default the TTL to the lens's own default when unset.
                    let ttl = match ttl {
                        Some(t) => t,
                        None => tessera_core::lens::get(&vault, &lens_id)?.default_ttl_minutes,
                    };
                    let p = match oauth_client.as_deref() {
                        Some(client_id) => pairing::approve_remote(
                            &vault, &lens_id, &purpose, &agent, ttl, client_id,
                        )?,
                        None => pairing::approve(&vault, &lens_id, &purpose, &agent, ttl)?,
                    };
                    println!("Approved pairing {}", p.id);
                    println!(
                        "  lens={}  lens_revision={}  purpose={:?}  agent={}  ttl={}min  oauth_client={}",
                        p.lens_id,
                        p.lens_updated_at.as_deref().unwrap_or("unavailable"),
                        p.purpose,
                        p.agent_name,
                        p.ttl_minutes,
                        p.oauth_client_id.as_deref().unwrap_or("stdio")
                    );
                    if p.oauth_client_id.is_some() {
                        println!(
                            "The registered OAuth client may now request scope lens:{}; editing the lens requires a new pairing.",
                            p.lens_id
                        );
                    } else {
                        println!(
                            "Launch the guardian with: tessera-guardian --vault <path> --pairing {}",
                            p.id
                        );
                    }
                    Ok(())
                }
                PairCommand::List => {
                    for p in pairing::list(&vault)? {
                        let status = if !p.is_active() {
                            "revoked"
                        } else if pairing::approved_lens(&vault, &p).is_ok() {
                            "active"
                        } else {
                            "stale"
                        };
                        println!(
                            "{}  lens={}  lens_revision={}  purpose={:?}  agent={}  oauth_client={}  {}",
                            p.id,
                            p.lens_id,
                            p.lens_updated_at.as_deref().unwrap_or("unavailable"),
                            p.purpose,
                            p.agent_name,
                            p.oauth_client_id.as_deref().unwrap_or("stdio"),
                            status
                        );
                    }
                    Ok(())
                }
                PairCommand::Revoke { id } => {
                    pairing::revoke(&vault, &id)?;
                    println!("Revoked pairing {id}");
                    Ok(())
                }
            }
        }
        Command::Receipts { action } => {
            use tessera_core::receipt;
            let vault = open_vault(&vault_path)?;
            match action {
                ReceiptsCommand::List => {
                    let receipts = receipt::list(&vault)?;
                    if receipts.is_empty() {
                        println!("No receipts.");
                    }
                    for r in &receipts {
                        println!(
                            "#{}  {}  lens={}  purpose={:?}  queries={}  bytes={}",
                            r.seq,
                            r.receipt_id,
                            r.lens.name,
                            r.purpose,
                            r.summary.total_queries,
                            r.summary.total_bytes_disclosed
                        );
                    }
                    Ok(())
                }
                ReceiptsCommand::Show { id } => {
                    let r = receipt::load(&vault, &id)?;
                    println!("{}", serde_json::to_string_pretty(&r)?);
                    Ok(())
                }
                ReceiptsCommand::Export { id, html, out } => {
                    let r = receipt::load(&vault, &id)?;
                    let content = if html {
                        receipt::export_html(&r)
                    } else {
                        serde_json::to_string_pretty(&r)?
                    };
                    match out {
                        Some(path) => {
                            std::fs::write(&path, content)
                                .with_context(|| format!("writing {}", path.display()))?;
                            println!("Wrote {}", path.display());
                        }
                        None => println!("{content}"),
                    }
                    Ok(())
                }
                ReceiptsCommand::Verify => {
                    let n = receipt::verify(&vault)?;
                    println!("OK — {n} receipt(s) verified, chain intact");
                    Ok(())
                }
            }
        }
        Command::Sessions { action } => {
            use tessera_core::session;
            let vault = open_vault(&vault_path)?;
            match action {
                SessionsCommand::List => {
                    for s in session::list(&vault)? {
                        println!(
                            "{}  [{}]  lens={}  purpose={:?}  expires={}",
                            s.id,
                            s.effective_status().as_str(),
                            s.lens_id,
                            s.purpose,
                            s.expires_at
                        );
                    }
                    Ok(())
                }
                SessionsCommand::Revoke { id, all } => {
                    if all {
                        let n = session::revoke_all(&vault)?;
                        println!("Revoked {n} active session(s).");
                    } else if let Some(id) = id {
                        session::revoke(&vault, &id)?;
                        println!("Revoked session {id}");
                    } else {
                        bail!("provide a session id or --all");
                    }
                    Ok(())
                }
            }
        }
        Command::Guardian { action } => {
            use tessera_core::session::{self, SessionStatus};
            let vault = open_vault(&vault_path)?;
            match action {
                GuardianCommand::Lock => {
                    let n = session::lock_all(&vault)?;
                    println!(
                        "Lock signaled: revoked {n} active session(s). Running guardians \
                         exit and drop their key within the monitoring interval."
                    );
                    Ok(())
                }
                GuardianCommand::Status => {
                    let active: Vec<_> = session::list(&vault)?
                        .into_iter()
                        .filter(|s| s.effective_status() == SessionStatus::Active)
                        .collect();
                    if active.is_empty() {
                        println!("No active sessions.");
                    }
                    for s in active {
                        println!(
                            "{}  lens={}  purpose={:?}  agent={}  expires={}",
                            s.id, s.lens_id, s.purpose, s.agent_name, s.expires_at
                        );
                    }
                    Ok(())
                }
            }
        }
        Command::Key { action } => {
            let vault = open_vault(&vault_path)?;
            match action {
                KeyCommand::List => {
                    let count = vault.keyslot_count()?;
                    println!("{count} keyslot(s):");
                    for index in 0..count {
                        println!("  {index}");
                    }
                    Ok(())
                }
                KeyCommand::Add => {
                    let new_passphrase = confirmed_new_passphrase()?;
                    let index = vault.add_keyslot(new_passphrase.as_str(), &kdf_params())?;
                    println!(
                        "Added keyslot {index}. Verify it opens a copied vault before removing an older slot."
                    );
                    Ok(())
                }
                KeyCommand::Remove { index, yes } => {
                    if !yes {
                        bail!(
                            "keyslot removal can make the vault unrecoverable; verify another slot, then re-run with --yes"
                        );
                    }
                    vault.remove_keyslot(index)?;
                    println!("Removed keyslot {index}.");
                    Ok(())
                }
            }
        }
        Command::Eval {
            golden,
            gate,
            report,
        } => {
            let vault = open_vault(&vault_path)?;
            let embedder = load_embedder()?;
            let source = std::fs::read_to_string(&golden)?;
            let value: serde_json::Value = serde_json::from_str(&source)?;
            if value["schema_version"] == "private-eval-v1" {
                let plan = tessera_core::eval::private::parse_plan(&source)?;
                let plan_checksum = blake3::hash(source.as_bytes()).to_hex().to_string();
                let private_report =
                    tessera_core::eval::private::run(&vault, &embedder, &plan, plan_checksum)?;
                let json = serde_json::to_string_pretty(&private_report)?;
                if let Some(path) = report {
                    std::fs::write(&path, &json)?;
                    eprintln!("sanitized report written to {}", path.display());
                }
                println!("{json}");
                if private_report.recommendation
                    != tessera_core::eval::private::Recommendation::Proceed
                {
                    bail!(
                        "private evaluation gate {:?}: thresholds were not all satisfied",
                        private_report.recommendation
                    );
                }
                return Ok(());
            }
            if report.is_some() {
                bail!("--report is only valid for a private-eval-v1 plan");
            }
            let items = tessera_core::eval::parse_golden(&source)?;
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
                    let manifest = onnx::trusted_manifest()?;
                    println!("model:    {}", manifest.model_version);
                    println!("path:     {}", dir.display());
                    println!("source:   {}", manifest.source_repository);
                    println!("revision: {}", manifest.revision);
                    println!("license:  {}", manifest.license);
                    println!("tokenizer: {}", manifest.tokenizer_version);
                    println!("runtime:  {}", manifest.runtime_versions);
                    println!("provenance: {}", manifest.provenance);
                    match onnx::verify_model_dir(&dir) {
                        Ok(_) => {
                            println!("status:   verified");
                            Ok(())
                        }
                        Err(error) => {
                            println!("status:   unavailable — {error}");
                            println!("recovery: `tessera model fetch` (online) or `tessera model install --source DIR` (offline)");
                            bail!("model is not verified")
                        }
                    }
                }
                ModelCommand::Fetch => {
                    if onnx::verify_model_dir(&dir).is_ok() {
                        println!("Verified model already active at {}", dir.display());
                        return Ok(());
                    }
                    let manifest = onnx::trusted_manifest()?;
                    activate_model(&dir, |staging| {
                        for file in &manifest.files {
                            let target = staging.join(&file.path);
                            let partial = staging.join(format!("{}.part", file.path));
                            let url = onnx::download_url(&manifest, file);
                            println!(
                                "Fetching {} from pinned revision {} …",
                                file.path, manifest.revision
                            );
                            let status = std::process::Command::new("curl")
                                .args(["-L", "--fail", "--progress-bar", "-o"])
                                .arg(&partial)
                                .arg(&url)
                                .status()
                                .context("running curl")?;
                            if !status.success() {
                                bail!("download failed for {}", file.path);
                            }
                            std::fs::rename(partial, target)?;
                        }
                        Ok(())
                    })?;
                    println!("Verified model activated at {}", dir.display());
                    Ok(())
                }
                ModelCommand::Install { source } => {
                    let manifest = onnx::trusted_manifest()?;
                    activate_model(&dir, |staging| {
                        for file in &manifest.files {
                            std::fs::copy(source.join(&file.path), staging.join(&file.path))
                                .with_context(|| {
                                    format!("copying {} from {}", file.path, source.display())
                                })?;
                        }
                        Ok(())
                    })?;
                    println!("Verified offline model activated at {}", dir.display());
                    Ok(())
                }
                ModelCommand::Reindex { max_chunks } => {
                    onnx::verify_model_dir(&dir)?;
                    let vault = Vault::open(&vault_path, &passphrase()?)?;
                    let embedder = onnx::OnnxEmbedder::load(&dir)?;
                    let progress = tessera_core::search::reindex(&vault, &embedder, max_chunks)?;
                    println!(
                        "reindex: {} {}/{} ({})",
                        progress.model_version,
                        progress.processed_chunks,
                        progress.total_chunks,
                        progress.status
                    );
                    if progress.status == "cancel_requested" {
                        println!("active index preserved; rerun `tessera model reindex` to resume");
                    } else if progress.status != "complete" {
                        println!("shadow index saved; rerun `tessera model reindex` to resume");
                    }
                    Ok(())
                }
                ModelCommand::ReindexStatus => {
                    let vault = Vault::open(&vault_path, &passphrase()?)?;
                    match tessera_core::search::reindex_progress(&vault)? {
                        Some(progress) => println!(
                            "reindex: {} {}/{} ({})",
                            progress.model_version,
                            progress.processed_chunks,
                            progress.total_chunks,
                            progress.status
                        ),
                        None => println!("reindex: never started; active index unchanged"),
                    }
                    Ok(())
                }
                ModelCommand::ReindexCancel => {
                    let vault = Vault::open(&vault_path, &passphrase()?)?;
                    if tessera_core::search::cancel_reindex(&vault)? {
                        println!("cancellation requested; active index remains unchanged");
                    } else {
                        println!("no running reindex to cancel");
                    }
                    Ok(())
                }
            }
        }
        Command::Diag { artifact, json } => {
            if !json {
                println!("tessera v{}", env!("CARGO_PKG_VERSION"));
                println!(
                    "pandoc: {}",
                    if tessera_core::extract::pandoc_available() {
                        "available"
                    } else {
                        "missing (DOCX extraction disabled)"
                    }
                );
            }
            match Vault::open(&vault_path, &passphrase()?) {
                Ok(vault) => {
                    let report = tessera_core::recovery::diagnose(&vault)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                        if report.has_fatal() {
                            bail!("fatal vault integrity failure");
                        }
                        return Ok(());
                    }
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
                    for check in &report.checks {
                        println!(
                            "integrity.{}: {:?} (affected: {}) — {}",
                            check.component, check.class, check.affected, check.action
                        );
                    }
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
                            if let Some(source_url) = rec.source_url {
                                println!("    source {}", terminal_safe(&source_url));
                            }
                        }
                    }
                    if report.has_fatal() {
                        bail!("fatal vault integrity failure");
                    }
                }
                Err(e) => bail!("vault unavailable or partial: {e}"),
            }
            Ok(())
        }
        Command::Backup { destination } => {
            let secret = passphrase()?;
            let vault = Vault::open(&vault_path, &secret)?;
            let source_report = tessera_core::recovery::diagnose(&vault)?;
            if source_report.has_fatal() {
                bail!("source vault has fatal integrity failures; backup refused");
            }
            tessera_core::recovery::backup(&vault, &destination)?;
            let restored = Vault::open(&destination, &secret)
                .context("opening completed backup for restore verification")?;
            let restored_report = tessera_core::recovery::diagnose(&restored)?;
            if restored_report.has_fatal() {
                bail!("backup copied but restore verification reported fatal integrity findings");
            }
            println!(
                "Backup verified at {} (database, blobs, policies, sessions, and receipt chain)",
                destination.display()
            );
            Ok(())
        }
        Command::RepairDerived { yes } => {
            if !yes {
                bail!(
                    "refusing derived rebuild without --yes; live artifacts return to pending, old derived blobs are retained, and review plus model reindex are required"
                );
            }
            let vault = Vault::open(&vault_path, &passphrase()?)?;
            let report = tessera_core::recovery::rebuild_derived(&vault)?;
            println!(
                "Derived rebuild complete: pending={}, extracted={}, chunked={}, summarized={}, failed={}",
                report.artifacts_moved_to_pending,
                report.extracted,
                report.chunked,
                report.summarized,
                report.failed
            );
            println!("Next: `tessera review`, then `tessera model reindex` after approval");
            Ok(())
        }
    }
}
