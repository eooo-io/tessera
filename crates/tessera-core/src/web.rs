//! Explicit web clipping: bounded fetch, Readability extraction, staging, and
//! source provenance. There is no crawler or background scheduler.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;

use dom_smoothie::{Config, Readability, TextMode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::artifact::ArtifactId;
use crate::vault::Vault;

const MAX_HTML_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Error, Debug)]
pub enum WebError {
    #[error("invalid web URL: {0}")]
    InvalidUrl(String),
    #[error("refusing a non-public web destination")]
    NonPublicDestination,
    #[error("web destination did not resolve")]
    ResolutionFailed,
    #[error("fetch failed: {0}")]
    Fetch(String),
    #[error("article extraction failed: {0}")]
    Extraction(String),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedArticle {
    pub title: String,
    pub byline: Option<String>,
    pub published_at: Option<String>,
    pub markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedArticle {
    pub source_url: String,
    pub final_url: String,
    pub fetched_at: String,
    pub article: ExtractedArticle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSource {
    pub source_url: String,
    pub final_url: String,
    pub title: String,
    pub published_at: Option<String>,
    pub fetched_at: String,
}

pub fn extract_article(html: &str, document_url: &str) -> Result<ExtractedArticle, WebError> {
    let config = Config {
        text_mode: TextMode::Markdown,
        max_elements_to_parse: 100_000,
        ..Config::default()
    };
    let mut readability = Readability::new(html, Some(document_url), Some(config))
        .map_err(|error| WebError::Extraction(error.to_string()))?;
    let article = readability
        .parse()
        .map_err(|error| WebError::Extraction(error.to_string()))?;
    let title = article.title.trim().to_owned();
    let markdown = article.text_content.to_string().trim().to_owned();
    if title.is_empty() || markdown.is_empty() {
        return Err(WebError::Extraction(
            "readability returned an empty title or body".into(),
        ));
    }
    Ok(ExtractedArticle {
        title,
        byline: article.byline.filter(|value| !value.trim().is_empty()),
        published_at: article
            .published_time
            .filter(|value| !value.trim().is_empty()),
        markdown,
    })
}

/// Fetch one explicitly requested public URL. Redirects are deliberately not
/// followed: each network destination must be owner-visible and independently
/// validated rather than turning the clipper into an SSRF redirect gadget.
pub fn fetch_article(input: &str) -> Result<FetchedArticle, WebError> {
    let (url, address) = validate_public_url(input)?;
    let host = url
        .host_str()
        .ok_or_else(|| WebError::InvalidUrl("host is required".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| WebError::InvalidUrl("port is required".into()))?;
    let resolved = match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    let directory = tempfile::tempdir()?;
    crate::vault::permissions::directory(directory.path())?;
    let headers_path = directory.path().join("headers.txt");
    let headers_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&headers_path)?;
    crate::vault::permissions::file(&headers_path)?;
    drop(headers_file);
    let output = Command::new("curl")
        .args([
            "--disable",
            "--silent",
            "--show-error",
            "--proto",
            "=http,https",
            "--noproxy",
            "*",
            "--max-redirs",
            "0",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--max-filesize",
            &MAX_HTML_BYTES.to_string(),
            "--user-agent",
            "Tessera/0.2 explicit-owner-web-clip",
            "--header",
            "Accept-Encoding: identity",
            "--resolve",
            &format!("{host}:{port}:{resolved}"),
            "--dump-header",
            headers_path.to_str().expect("temporary UTF-8 path"),
            "--write-out",
            "%{http_code}",
            url.as_str(),
        ])
        .output()
        .map_err(|error| WebError::Fetch(format!("cannot run curl: {error}")))?;
    if !output.status.success() {
        return Err(WebError::Fetch(format!(
            "curl exited unsuccessfully ({})",
            output.status
        )));
    }
    if output.stdout.len() < 3 {
        return Err(WebError::Fetch("curl returned no HTTP status".into()));
    }
    let (bytes, status_bytes) = output.stdout.split_at(output.stdout.len() - 3);
    let status: u16 = String::from_utf8_lossy(status_bytes)
        .parse()
        .map_err(|_| WebError::Fetch("curl returned an invalid HTTP status".into()))?;
    if !(200..300).contains(&status) {
        return Err(WebError::Fetch(format!(
            "HTTP {status}; redirects are not followed, provide the canonical article URL"
        )));
    }
    let headers = std::fs::read_to_string(&headers_path)?;
    let content_type = headers.lines().rev().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_ascii_lowercase())
        })
    });
    if !content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("text/html"))
    {
        return Err(WebError::Fetch(
            "response Content-Type is not text/html".into(),
        ));
    }
    if bytes.len() as u64 > MAX_HTML_BYTES {
        return Err(WebError::Fetch("response exceeds 10 MiB limit".into()));
    }
    let html = String::from_utf8(bytes.to_vec())
        .map_err(|_| WebError::Fetch("response is not UTF-8 HTML".into()))?;
    let article = extract_article(&html, url.as_str())?;
    Ok(FetchedArticle {
        source_url: url.to_string(),
        final_url: url.to_string(),
        fetched_at: chrono::Utc::now().to_rfc3339(),
        article,
    })
}

fn validate_public_url(input: &str) -> Result<(Url, IpAddr), WebError> {
    let mut url = Url::parse(input).map_err(|error| WebError::InvalidUrl(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(WebError::InvalidUrl(
            "only http and https are allowed".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WebError::InvalidUrl(
            "embedded credentials are not allowed".into(),
        ));
    }
    url.set_fragment(None);
    let host = url
        .host_str()
        .ok_or_else(|| WebError::InvalidUrl("host is required".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| WebError::InvalidUrl("port is required".into()))?;
    let addresses: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| WebError::ResolutionFailed)?
        .map(|address| address.ip())
        .collect();
    if addresses.is_empty() {
        return Err(WebError::ResolutionFailed);
    }
    if addresses.iter().any(|address| !is_public_ip(*address)) {
        return Err(WebError::NonPublicDestination);
    }
    Ok((url, addresses[0]))
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            !address.is_unspecified()
                && !address.is_loopback()
                && (segments[0] & 0xfe00) != 0xfc00
                && (segments[0] & 0xffc0) != 0xfe80
                && (segments[0] & 0xff00) != 0xff00
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && address
                    .to_ipv4_mapped()
                    .is_none_or(|mapped| is_public_ip(IpAddr::V4(mapped)))
        }
    }
}

pub fn stage_article(vault: &Vault, fetched: &FetchedArticle) -> Result<PathBuf, WebError> {
    let mut slug = fetched
        .article
        .title
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug = slug.trim_matches('-').chars().take(60).collect();
    if slug.is_empty() {
        slug = "web-clip".into();
    }
    let url_hash = blake3::hash(fetched.source_url.as_bytes()).to_hex();
    let filename = format!("{slug}-{}.md", &url_hash[..12]);
    let inbox = vault.path().join("inbox");
    let target = inbox.join(&filename);
    if target.exists() {
        return Err(WebError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "this URL is already staged",
        )));
    }
    // Recover a crash after metadata commit but before the final staging-file
    // rename. Partial files remain ignored evidence; the stale association
    // must not permanently prevent an explicit retry.
    vault.conn().execute(
        "DELETE FROM web_staging WHERE staged_filename = ?1",
        [&filename],
    )?;
    let partial = inbox.join(format!(".{filename}.{}.partial", ulid::Ulid::new()));
    let mut markdown = format!("# {}\n\n", fetched.article.title);
    if let Some(byline) = &fetched.article.byline {
        markdown.push_str(&format!("By {byline}\n\n"));
    }
    if let Some(published) = &fetched.article.published_at {
        markdown.push_str(&format!("Published: {published}\n\n"));
    }
    markdown.push_str(fetched.article.markdown.trim());
    markdown.push('\n');
    std::fs::write(&partial, markdown)?;
    crate::vault::permissions::file(&partial)?;
    std::fs::File::open(&partial)?.sync_all()?;
    let inserted = vault.conn().execute(
        "INSERT INTO web_staging
         (staged_filename, source_url, final_url, title, published_at, fetched_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            filename,
            fetched.source_url,
            fetched.final_url,
            fetched.article.title,
            fetched.article.published_at,
            fetched.fetched_at,
        ],
    );
    if let Err(error) = inserted {
        let _ = std::fs::remove_file(&partial);
        return Err(error.into());
    }
    if let Err(error) = std::fs::rename(&partial, &target) {
        let _ = vault.conn().execute(
            "DELETE FROM web_staging WHERE staged_filename = ?1",
            [&filename],
        );
        let _ = std::fs::remove_file(&partial);
        return Err(error.into());
    }
    std::fs::File::open(&inbox)?.sync_all()?;
    crate::vault::permissions::file(&target)?;
    Ok(target)
}

pub(crate) fn attach_staged_to_version(
    vault: &Vault,
    staged_filename: &str,
    artifact_version_id: &str,
) -> Result<(), WebError> {
    vault.conn().execute(
        "INSERT INTO web_sources
         (artifact_version_id, source_url, final_url, title, published_at, fetched_at)
         SELECT ?1, source_url, final_url, title, published_at, fetched_at
         FROM web_staging WHERE staged_filename = ?2",
        rusqlite::params![artifact_version_id, staged_filename],
    )?;
    vault.conn().execute(
        "DELETE FROM web_staging WHERE staged_filename = ?1",
        [staged_filename],
    )?;
    Ok(())
}

pub(crate) fn discard_staged(vault: &Vault, staged_filename: &str) -> Result<(), WebError> {
    vault.conn().execute(
        "DELETE FROM web_staging WHERE staged_filename = ?1",
        [staged_filename],
    )?;
    Ok(())
}

pub fn source_for_artifact(
    vault: &Vault,
    artifact_id: &ArtifactId,
) -> Result<Option<WebSource>, WebError> {
    let result = vault.conn().query_row(
        "SELECT ws.source_url, ws.final_url, ws.title, ws.published_at, ws.fetched_at
         FROM artifact_versions av
         LEFT JOIN web_sources ws ON ws.artifact_version_id = av.id
         WHERE av.artifact_id = ?1
         ORDER BY av.version DESC LIMIT 1",
        [artifact_id.0.as_str()],
        |row| {
            let source_url: Option<String> = row.get(0)?;
            let Some(source_url) = source_url else {
                return Ok(None);
            };
            let final_url: Option<String> = row.get(1)?;
            let title: Option<String> = row.get(2)?;
            let fetched_at: Option<String> = row.get(4)?;
            Ok(Some(WebSource {
                source_url,
                final_url: final_url.ok_or(rusqlite::Error::InvalidQuery)?,
                title: title.ok_or(rusqlite::Error::InvalidQuery)?,
                published_at: row.get(3)?,
                fetched_at: fetched_at.ok_or(rusqlite::Error::InvalidQuery)?,
            }))
        },
    );
    match result {
        Ok(source) => Ok(source),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactState;
    use crate::crypto::KdfParams;
    use crate::lens::{DisclosureMode, LensPolicy};
    use crate::{artifact, chunk, disclosure, extract, inbox, space};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn readability_extracts_article_markdown_without_navigation() {
        let html = include_str!("../../../tests/fixtures/web-article.html");
        let article =
            extract_article(html, "https://example.com/research/article").expect("extract article");
        assert_eq!(article.title, "Tessera Article Fixture");
        assert_eq!(article.byline.as_deref(), Some("Ada Example"));
        assert_eq!(article.published_at.as_deref(), Some("2026-07-12"));
        assert!(article.markdown.contains("Evidence-first article body"));
        assert!(article.markdown.contains("## Durable context"));
        assert!(!article.markdown.contains("Buy dubious supplements"));
        assert!(!article.markdown.contains("Site navigation"));
    }

    #[test]
    fn private_and_credentialed_urls_fail_before_fetch() {
        assert!(matches!(
            validate_public_url("http://127.0.0.1/private"),
            Err(WebError::NonPublicDestination)
        ));
        assert!(matches!(
            validate_public_url("https://user:secret@example.com/article"),
            Err(WebError::InvalidUrl(_))
        ));
        assert!(matches!(
            validate_public_url("file:///etc/passwd"),
            Err(WebError::InvalidUrl(_))
        ));
    }

    #[test]
    fn staged_clip_preserves_source_through_quarantine_and_citation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault =
            Vault::create_with_params(&directory.path().join("Web.tessera"), "pass", &TEST_PARAMS)
                .expect("vault");
        let space_id = space::create(&vault, "Web", None).expect("space");
        let article = extract_article(
            include_str!("../../../tests/fixtures/web-article.html"),
            "https://example.com/research/article",
        )
        .expect("article");
        let fetched = FetchedArticle {
            source_url: "https://example.com/research/article".into(),
            final_url: "https://example.com/research/article".into(),
            fetched_at: "2026-07-12T00:00:00Z".into(),
            article,
        };
        let interrupted = stage_article(&vault, &fetched).expect("initial stage");
        std::fs::remove_file(interrupted).expect("simulate pre-rename crash state");
        let staged = stage_article(&vault, &fetched).expect("retry stale stage");
        assert!(staged.is_file());
        let report = inbox::process(&vault, &space_id).expect("intake");
        let artifact_id = report.ingested[0].1.clone();
        let source = source_for_artifact(&vault, &artifact_id)
            .expect("source")
            .expect("web source");
        assert_eq!(source.final_url, fetched.final_url);
        assert_eq!(source.title, "Tessera Article Fixture");
        let staged_rows: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM web_staging", [], |row| row.get(0))
            .expect("staging count");
        assert_eq!(staged_rows, 0);

        let derived = extract::extract_text(&vault, &artifact_id)
            .expect("extract")
            .expect("markdown");
        chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
        artifact::set_state(&vault, &artifact_id, ArtifactState::Live).expect("live");
        let mut lens = LensPolicy::new("Web lens", vec![space_id]);
        lens.disclosure_mode = DisclosureMode::Excerpt;
        lens.max_quote_chars = Some(10_000);
        let rendered =
            disclosure::render_item(&vault, &lens, &artifact_id, false).expect("render web clip");
        assert_eq!(
            rendered.source_url.as_deref(),
            Some(fetched.final_url.as_str())
        );
        assert!(rendered.body.contains("Evidence-first article body"));

        lens.allow_metadata = false;
        let hidden = disclosure::render_item(&vault, &lens, &artifact_id, false)
            .expect("metadata-hidden render");
        assert!(hidden.source_url.is_none());

        let replacement = vault
            .blobs()
            .put(vault.dek().expect("dek"), b"later non-web version")
            .expect("replacement blob");
        artifact::record_version(&vault, &artifact_id, &replacement, 21).expect("later version");
        assert!(
            source_for_artifact(&vault, &artifact_id)
                .expect("latest source")
                .is_none(),
            "an older web URL must not attach to a newer non-web version"
        );
    }
}
