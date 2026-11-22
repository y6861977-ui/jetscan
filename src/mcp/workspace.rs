//! The workspace: which folders the MCP tools may read, and turning a tool's `path`
//! argument into a checked, canonical path inside one of them.
//!
//! Rules (all enforced here, nowhere else):
//! - roots are canonical directories: `--root` folders if given (fixed, the client cannot
//!   change them), otherwise the client's `roots/list` answer, otherwise the working
//!   directory at startup;
//! - a tool path is resolved against the first root when relative, then canonicalized
//!   (symlinks and `..` resolved by the OS) and must lie inside a root — so a link that
//!   points outside is refused, not followed;
//! - a whole home folder or a filesystem root is never scanned implicitly.

use jetscan::ui;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `jetscan mcp --root <dir>`: the user's explicit choice; client roots are ignored.
    Configured,
    /// The client answered `roots/list`.
    Client,
    /// The working directory the client started the server in.
    Cwd,
}

#[derive(Clone, Debug)]
pub struct Workspace {
    roots: Vec<PathBuf>,
    source: Source,
    /// Startup roots, restored when the client later reports no usable roots.
    fallback: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    // Only the jetscan Pro APK tool asks for a file today.
    #[cfg_attr(not(feature = "pro"), allow(dead_code))]
    File,
    Any,
}

impl Workspace {
    /// `configured` empty = use `cwd`. Errors name the folder that is not usable.
    pub fn new(configured: &[PathBuf], cwd: &Path) -> Result<Workspace, String> {
        let (list, source) = if configured.is_empty() {
            (vec![cwd.to_path_buf()], Source::Cwd)
        } else {
            (configured.to_vec(), Source::Configured)
        };
        let mut roots = Vec::new();
        for dir in &list {
            let dir = if dir.is_absolute() {
                dir.clone()
            } else {
                cwd.join(dir)
            };
            let canon = std::fs::canonicalize(&dir)
                .ok()
                .filter(|p| p.is_dir())
                .ok_or_else(|| format!("workspace root {} is not a folder", show(&dir)))?;
            if !roots.contains(&canon) {
                roots.push(canon);
            }
        }
        Ok(Workspace {
            fallback: roots.clone(),
            roots,
            source,
        })
    }

    #[cfg(test)]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    #[cfg(test)]
    pub fn source(&self) -> Source {
        self.source
    }

    /// Whether a `roots/list` answer may replace the roots (not with `--root`).
    pub fn accepts_client_roots(&self) -> bool {
        self.source != Source::Configured
    }

    /// Applies the client's `roots/list` URIs. Only `file:` URIs of existing folders
    /// count; with none usable the startup roots stay. Returns how many were taken.
    pub fn set_client_roots(&mut self, uris: &[String]) -> usize {
        if !self.accepts_client_roots() {
            return 0;
        }
        let mut roots = Vec::new();
        for uri in uris {
            if let Some(canon) = file_uri_to_path(uri)
                .and_then(|p| std::fs::canonicalize(p).ok())
                .filter(|p| p.is_dir())
                && !roots.contains(&canon)
            {
                roots.push(canon);
            }
        }
        if roots.is_empty() {
            self.roots = self.fallback.clone();
            self.source = Source::Cwd;
            0
        } else {
            let n = roots.len();
            self.roots = roots;
            self.source = Source::Client;
            n
        }
    }

    /// Resolves a tool's path argument (`None` = the first root) to a canonical path
    /// inside a root, of the wanted kind. The error is a sentence for the AI.
    pub fn resolve(&self, arg: Option<&str>, kind: Kind) -> Result<PathBuf, String> {
        let Some(first) = self.roots.first() else {
            return Err("the server has no workspace folder".into());
        };
        let target = match arg {
            None => first.clone(),
            Some(text) => {
                if text.trim().is_empty() || text.chars().any(char::is_control) {
                    return Err("path must be a non-empty file or folder name".into());
                }
                let p = Path::new(text);
                if p.is_absolute() {
                    p.to_path_buf()
                } else if has_prefix(p) {
                    // `C:foo` / `\foo` on Windows: drive-relative, ambiguous. Refuse.
                    return Err(format!(
                        "path '{}' is not a plain relative or absolute path",
                        ui::sanitize_line(text)
                    ));
                } else {
                    first.join(p)
                }
            }
        };
        let shown_arg = arg.map_or_else(|| show(first), ui::sanitize_line);
        let canon = std::fs::canonicalize(&target)
            .map_err(|_| format!("path '{shown_arg}' does not exist or cannot be read"))?;
        if !self.roots.iter().any(|r| canon.starts_with(r)) {
            return Err(format!(
                "refused: '{shown_arg}' is outside the workspace ({}). jetscan's MCP server \
                 only reads inside the workspace folder(s); symbolic links that point \
                 outside are not followed. To scan another folder, start `jetscan mcp` \
                 there or add `--root <folder>`.",
                self.describe()
            ));
        }
        match kind {
            Kind::Dir if !canon.is_dir() => {
                return Err(format!("'{shown_arg}' is not a folder"));
            }
            Kind::File if !canon.is_file() => {
                return Err(format!("'{shown_arg}' is not a regular file"));
            }
            _ => {}
        }
        if canon.is_dir() && too_broad(&canon) {
            return Err(format!(
                "refused: '{}' is your home folder or a whole drive, not a project. Pass the \
                 project folder in `path` (for example \"path\": \"my-app\"), or start \
                 `jetscan mcp` in the project folder / with `--root <project>`.",
                show(&canon)
            ));
        }
        Ok(canon)
    }

    /// The roots for a message, readable (`C:\x`, not `\\?\C:\x`).
    pub fn describe(&self) -> String {
        self.roots
            .iter()
            .map(|r| show(r))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `path` relative to the root that contains it, with `/` (for summaries).
    pub fn relative(&self, path: &Path) -> String {
        for root in &self.roots {
            if let Ok(rest) = path.strip_prefix(root) {
                let text = rest.to_string_lossy().replace('\\', "/");
                return if text.is_empty() { ".".into() } else { text };
            }
        }
        show(path)
    }
}

fn has_prefix(p: &Path) -> bool {
    p.components()
        .next()
        .is_some_and(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
}

/// Home folder or a path with no parent (`/`, `C:\`).
fn too_broad(canon: &Path) -> bool {
    if canon.parent().is_none() {
        return true;
    }
    jetscan::secrets::machine::home_dir()
        .and_then(|h| std::fs::canonicalize(h).ok())
        .is_some_and(|h| h == canon)
}

/// For display and for handing to scanners: `\\?\C:\x` -> `C:\x` (verbatim UNC kept).
/// git and other tools do not all accept the verbatim prefix that `canonicalize`
/// returns on Windows.
pub fn plain(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

pub fn show(path: &Path) -> String {
    ui::sanitize_line(&plain(path).display().to_string())
}

/// `file:///home/u/app`, `file:///C:/Users/u/app`, `file://server/share` (Windows only),
/// percent-decoded. Anything else (other schemes, query/fragment, bad escapes) -> None.
pub fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri
        .strip_prefix("file://")
        .or_else(|| uri.strip_prefix("FILE://"))?;
    if rest.contains(['?', '#']) {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = percent_decode(path)?;
    if path.contains('\0') {
        return None;
    }
    let authority = percent_decode(authority)?;
    let local = authority.is_empty() || authority.eq_ignore_ascii_case("localhost");
    if cfg!(windows) {
        if local {
            // `/C:/x` -> `C:/x`
            let trimmed = path.strip_prefix('/').unwrap_or(&path);
            let b = trimmed.as_bytes();
            if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                return Some(PathBuf::from(trimmed.replace('/', "\\")));
            }
            None
        } else {
            Some(PathBuf::from(format!(
                r"\\{}{}",
                authority,
                path.replace('/', "\\")
            )))
        }
    } else if local && path.starts_with('/') {
        Some(PathBuf::from(path))
    } else {
        None
    }
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(PathBuf);
    impl Temp {
        fn new(tag: &str) -> Temp {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!(
                "jetscan-mcp-ws-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Temp(std::fs::canonicalize(p).unwrap())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn paths_resolve_inside_the_root_and_never_outside() {
        let t = Temp::new("resolve");
        let root = t.0.join("project");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.js"), "x").unwrap();
        std::fs::write(t.0.join("outside.txt"), "x").unwrap();
        let ws = Workspace::new(&[], &root).unwrap();
        assert_eq!(ws.source(), Source::Cwd);
        let canon_root = std::fs::canonicalize(&root).unwrap();
        assert_eq!(ws.resolve(None, Kind::Dir).unwrap(), canon_root);
        assert_eq!(
            ws.resolve(Some("src/a.js"), Kind::File).unwrap(),
            canon_root.join("src").join("a.js")
        );
        assert_eq!(ws.relative(&canon_root.join("src")), "src");
        assert!(ws.resolve(Some("src"), Kind::File).is_err());
        assert!(ws.resolve(Some("src/a.js"), Kind::Dir).is_err());
        for bad in ["../outside.txt", "..", "", "  ", "a\nb"] {
            assert!(ws.resolve(Some(bad), Kind::Any).is_err(), "{bad:?}");
        }
        let abs = t.0.join("outside.txt").display().to_string();
        let e = ws.resolve(Some(&abs), Kind::Any).unwrap_err();
        assert!(e.starts_with("refused:"), "{e}");
        assert!(ws.resolve(Some("missing"), Kind::Any).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        let t = Temp::new("link");
        let root = t.0.join("project");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(t.0.join("secret-dir")).unwrap();
        std::os::unix::fs::symlink(t.0.join("secret-dir"), root.join("link")).unwrap();
        let ws = Workspace::new(&[], &root).unwrap();
        let e = ws.resolve(Some("link"), Kind::Dir).unwrap_err();
        assert!(e.starts_with("refused:"), "{e}");
    }

    #[test]
    fn client_roots_replace_cwd_but_not_configured_roots() {
        let t = Temp::new("roots");
        let a = t.0.join("a");
        let b = t.0.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let uri = path_to_uri(&b);
        let mut ws = Workspace::new(&[], &a).unwrap();
        assert_eq!(ws.set_client_roots(&[uri.clone(), "https://x/y".into()]), 1);
        assert_eq!(ws.source(), Source::Client);
        assert!(ws.resolve(None, Kind::Dir).unwrap().ends_with("b"));
        // `a` is no longer a root.
        let a_abs = a.display().to_string();
        assert!(ws.resolve(Some(&a_abs), Kind::Dir).is_err());
        // No usable roots: back to the startup folder.
        assert_eq!(
            ws.set_client_roots(&["file:///definitely/missing".into()]),
            0
        );
        assert!(ws.resolve(None, Kind::Dir).unwrap().ends_with("a"));

        let mut fixed = Workspace::new(std::slice::from_ref(&a), &b).unwrap();
        assert_eq!(fixed.source(), Source::Configured);
        assert_eq!(fixed.set_client_roots(&[uri]), 0);
        assert!(fixed.resolve(None, Kind::Dir).unwrap().ends_with("a"));
        assert!(Workspace::new(&[t.0.join("missing")], &a).is_err());
    }

    fn path_to_uri(p: &Path) -> String {
        let text = plain(&std::fs::canonicalize(p).unwrap())
            .display()
            .to_string()
            .replace('\\', "/")
            .replace(' ', "%20");
        if text.starts_with('/') {
            format!("file://{text}")
        } else {
            format!("file:///{text}")
        }
    }

    #[test]
    fn file_uris() {
        assert_eq!(file_uri_to_path("http://x/y"), None);
        assert_eq!(file_uri_to_path("file:///a%2"), None);
        assert_eq!(file_uri_to_path("file:///a?b"), None);
        if cfg!(windows) {
            assert_eq!(
                file_uri_to_path("file:///C:/Users/My%20App"),
                Some(PathBuf::from(r"C:\Users\My App"))
            );
            assert_eq!(
                file_uri_to_path("file:///c%3A/x"),
                Some(PathBuf::from(r"c:\x"))
            );
            assert_eq!(file_uri_to_path("file:///home/x"), None);
        } else {
            assert_eq!(
                file_uri_to_path("file:///home/u/my%20app"),
                Some(PathBuf::from("/home/u/my app"))
            );
            assert_eq!(
                file_uri_to_path("file://localhost/srv"),
                Some(PathBuf::from("/srv"))
            );
            assert_eq!(file_uri_to_path("file://host/srv"), None);
        }
    }

    #[test]
    fn plain_strips_only_the_local_verbatim_prefix() {
        assert_eq!(plain(Path::new(r"\\?\C:\x")), PathBuf::from(r"C:\x"));
        assert_eq!(
            plain(Path::new(r"\\?\UNC\srv\share")),
            PathBuf::from(r"\\?\UNC\srv\share")
        );
        assert_eq!(plain(Path::new("/home/u")), PathBuf::from("/home/u"));
    }
}
