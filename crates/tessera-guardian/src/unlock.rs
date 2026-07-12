//! One-shot Guardian passphrase delivery.
//!
//! Secrets are read from an inherited descriptor, a tightly permissioned
//! regular file, or an explicit no-echo TTY prompt. The environment, process
//! arguments, MCP stdin/stdout, logs, and receipts are never secret sources.

use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context};
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSPHRASE_BYTES: usize = 4096;

pub fn acquire(
    passphrase_fd: Option<i32>,
    passphrase_file: Option<&Path>,
    prompt_passphrase: bool,
) -> anyhow::Result<Zeroizing<String>> {
    let selected = usize::from(passphrase_fd.is_some())
        + usize::from(passphrase_file.is_some())
        + usize::from(prompt_passphrase);
    if selected != 1 {
        bail!(
            "select exactly one unlock source: --passphrase-fd, --passphrase-file, or --prompt-passphrase"
        );
    }
    if let Some(fd) = passphrase_fd {
        return read_fd(fd);
    }
    if let Some(path) = passphrase_file {
        return read_file(path);
    }

    let passphrase = rpassword::prompt_password("Vault passphrase: ")
        .context("reading passphrase from the controlling terminal")?;
    validate(Zeroizing::new(passphrase))
}

fn read_fd(fd: i32) -> anyhow::Result<Zeroizing<String>> {
    if fd < 3 {
        bail!("--passphrase-fd must be 3 or greater; stdin/stdout/stderr are reserved");
    }
    let path = format!("/dev/fd/{fd}");
    let file = std::fs::File::open(&path)
        .with_context(|| format!("opening inherited passphrase descriptor {fd}"))?;
    read_secret(file).with_context(|| format!("reading inherited passphrase descriptor {fd}"))
}

fn read_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting passphrase file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("passphrase file must be a regular file, not a symlink or device");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "passphrase file permissions must deny group/other access (mode 0600 recommended; found {mode:04o})"
            );
        }
    }
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening passphrase file {}", path.display()))?;
    read_secret(file).with_context(|| format!("reading passphrase file {}", path.display()))
}

fn read_secret(reader: impl Read) -> anyhow::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_PASSPHRASE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PASSPHRASE_BYTES {
        bail!("passphrase exceeds {MAX_PASSPHRASE_BYTES} bytes");
    }
    let value = std::str::from_utf8(bytes.as_slice()).context("passphrase is not valid UTF-8")?;
    let mut passphrase = Zeroizing::new(value.to_owned());
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    if passphrase
        .chars()
        .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        passphrase.zeroize();
        bail!("passphrase source must contain exactly one UTF-8 line without NUL bytes");
    }
    validate(passphrase)
}

fn validate(mut passphrase: Zeroizing<String>) -> anyhow::Result<Zeroizing<String>> {
    if passphrase.is_empty() {
        passphrase.zeroize();
        bail!("refusing an empty vault passphrase");
    }
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        passphrase.zeroize();
        bail!("passphrase exceeds {MAX_PASSPHRASE_BYTES} bytes");
    }
    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn secret_reader_trims_one_line_ending_and_rejects_multiline_and_oversize() {
        assert_eq!(
            read_secret(Cursor::new(b"correct horse\r\n"))
                .expect("secret")
                .as_str(),
            "correct horse"
        );
        assert!(read_secret(Cursor::new(b"first\nsecond\n")).is_err());
        assert!(read_secret(Cursor::new(vec![b'x'; MAX_PASSPHRASE_BYTES + 1])).is_err());
        assert!(read_secret(Cursor::new(Vec::<u8>::new())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_source_requires_private_permissions_and_fd_source_reads_once() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        std::fs::write(&path, "portable passphrase\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("permissions");
        assert!(read_file(&path).is_err(), "world-readable secret refused");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
        assert_eq!(
            read_file(&path).expect("file").as_str(),
            "portable passphrase"
        );

        let file = std::fs::File::open(&path).expect("open");
        assert_eq!(
            read_fd(file.as_raw_fd()).expect("fd").as_str(),
            "portable passphrase"
        );
    }

    #[test]
    fn selection_is_explicit_and_environment_is_not_an_unlock_source() {
        assert!(acquire(None, None, false).is_err());
        assert!(acquire(Some(3), Some(Path::new("unused")), false).is_err());
    }
}
