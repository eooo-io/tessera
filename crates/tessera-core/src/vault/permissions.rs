//! Portable best-effort owner-only filesystem permissions.

use std::path::Path;

pub(crate) fn validate_bundle_layout(path: &Path) -> Result<(), std::io::Error> {
    validate_bundle_layout_inner(path, false)
}

pub(crate) fn validate_migration_layout(path: &Path) -> Result<(), std::io::Error> {
    validate_bundle_layout_inner(path, true)
}

fn validate_bundle_layout_inner(
    path: &Path,
    allow_retired_database: bool,
) -> Result<(), std::io::Error> {
    for name in ["tessera.json", "keyslot.bin"] {
        let entry = path.join(name);
        let metadata = std::fs::symlink_metadata(&entry)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("vault component is not a regular file: {name}"),
            ));
        }
    }
    let database = path.join("vault.db");
    let selected = if database.exists() {
        database
    } else if allow_retired_database {
        path.join(".vault.db.v2.retired")
    } else {
        database
    };
    let metadata = std::fs::symlink_metadata(&selected)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "vault database authority is not a regular file",
        ));
    }
    for name in ["blobs", "receipts", "inbox"] {
        let entry = path.join(name);
        let metadata = std::fs::symlink_metadata(&entry)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("vault component is not a directory: {name}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn harden_tree(path: &Path) -> Result<(), std::io::Error> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "symbolic links are not permitted inside a vault bundle",
        ));
    }
    if metadata.is_dir() {
        directory(path)?;
        for entry in std::fs::read_dir(path)? {
            harden_tree(&entry?.path())?;
        }
    } else if metadata.is_file() {
        file(path)?;
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported filesystem entry inside vault bundle",
        ));
    }
    Ok(())
}

pub(crate) fn directory(path: &Path) -> Result<(), std::io::Error> {
    let existed = path.exists();
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let current = std::fs::metadata(path)?.permissions().mode();
        let mode = if existed { current & !0o077 } else { 0o700 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = existed;
    Ok(())
}

pub(crate) fn file(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let current = std::fs::metadata(path)?.permissions().mode();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(current & !0o077))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
