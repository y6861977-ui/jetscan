//! Read-only filesystem guard. Mutation needs additional platform transaction guards.
use super::*;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};
pub(crate) const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub(crate) fn linked(m: &Metadata) -> bool {
    if m.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}
pub(crate) fn checked_path(root: &Path, relative: &str) -> Result<PathBuf, ResolveError> {
    model::relative(relative)?;
    if fs::canonicalize(root).map_err(|_| ResolveError("root_unavailable"))? != root {
        return Err(ResolveError("root_changed"));
    }
    // Inspect every existing ancestor, including the root itself.
    for ancestor in root.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| ResolveError("root_unavailable"))?;
        if linked(&meta) || !meta.is_dir() {
            return Err(ResolveError("linked_or_invalid_root"));
        }
    }
    let mut path = root.to_path_buf();
    let parts = relative.split('/').collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        let meta = fs::symlink_metadata(&path).map_err(|_| ResolveError("file_unavailable"))?;
        if linked(&meta) {
            return Err(ResolveError("linked_path"));
        }
        if index + 1 < parts.len() && !meta.is_dir() {
            return Err(ResolveError("invalid_parent"));
        }
        if index + 1 == parts.len() && (!meta.is_file() || meta.len() > MAX_FILE_BYTES) {
            return Err(ResolveError("invalid_or_large_file"));
        }
    }
    let canonical = fs::canonicalize(&path).map_err(|_| ResolveError("file_unavailable"))?;
    if !canonical.starts_with(root) {
        return Err(ResolveError("path_escape"));
    }
    Ok(path)
}
pub(crate) fn open_read(path: &Path) -> Result<File, ResolveError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000).share_mode(1);
    }
    let file = options
        .open(path)
        .map_err(|_| ResolveError("file_unavailable_or_busy"))?;
    let meta = file
        .metadata()
        .map_err(|_| ResolveError("file_unavailable"))?;
    if linked(&meta) || !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return Err(ResolveError("invalid_or_large_file"));
    }
    Ok(file)
}
pub(crate) fn read(root: &Path, relative: &str) -> Result<Vec<u8>, ResolveError> {
    let path = checked_path(root, relative)?;
    let file = open_read(&path)?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ResolveError("read_failed"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(ResolveError("file_limit"));
    }
    checked_path(root, relative)?;
    Ok(bytes)
}
