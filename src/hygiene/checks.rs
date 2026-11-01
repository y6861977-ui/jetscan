//! Проверки гигиены. Контракт — в `mod.rs`.

use super::{Issue, Level};
use crate::json::{self, Json};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

// Deliberately inspect only conventional credential locations, never a recursive
// home scan. Skip links/reparse points, special files, oversized and invalid UTF-8
// files. Limits also apply if a file grows between metadata() and read().
const MAX_BYTES: u64 = 1024 * 1024;

pub fn run(home: &Path) -> Vec<Issue> {
    let mut issues = Vec::new();
    if !directory(home) {
        return issues;
    }
    let ssh = home.join(".ssh");
    if directory(&ssh)
        && let Ok(entries) = fs::read_dir(&ssh)
    {
        for entry in entries.flatten() {
            let Some((text, meta)) = read_file(&entry.path()) else {
                continue;
            };
            let Some(clear) = private_key(&text) else {
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let path = format!("~/.ssh/{name}");
            if clear {
                issues.push(issue(
                    "ssh-key-no-passphrase",
                    Level::High,
                    &path,
                    0,
                    "SSH private key is stored without passphrase encryption.",
                    &key_fix(&path, false),
                ));
            }
            if exposed_permissions(&meta) {
                issues.push(issue(
                    "ssh-key-permissions",
                    Level::Medium,
                    &path,
                    0,
                    "SSH private key has group or other permission bits set.",
                    &key_fix(&path, true),
                ));
            }
        }
    }
    if let Some((text, _)) = read_file(&home.join(".npmrc")) {
        npmrc(&text, &mut issues);
    }
    if directory(&home.join(".docker"))
        && let Some((text, _)) = read_file(&home.join(".docker/config.json"))
    {
        docker(&text, &mut issues);
    }
    for (file, check) in [
        (".pypirc", pypirc as fn(&str, &mut Vec<Issue>)),
        (".git-credentials", git_credentials),
    ] {
        if let Some((text, _)) = read_file(&home.join(file)) {
            check(&text, &mut issues);
        }
    }
    for file in [".netrc", "_netrc"] {
        if let Some((text, _)) = read_file(&home.join(file)) {
            netrc(&text, &format!("~/{file}"), &mut issues);
        }
    }
    if directory(&home.join(".cargo")) {
        for file in ["credentials.toml", "credentials"] {
            if let Some((text, _)) = read_file(&home.join(".cargo").join(file)) {
                cargo_credentials(&text, &format!("~/.cargo/{file}"), &mut issues);
            }
        }
    }
    if directory(&home.join(".kube"))
        && let Some((text, _)) = read_file(&home.join(".kube/config"))
    {
        kubeconfig(&text, &mut issues);
    }
    if directory(&home.join(".aws"))
        && let Some((text, _)) = read_file(&home.join(".aws/credentials"))
    {
        aws_credentials(&text, &mut issues);
    }
    issues.sort_by(|a, b| (&a.path, a.line, a.id).cmp(&(&b.path, b.line, b.id)));
    issues
}

fn key_fix(path: &str, permissions: bool) -> String {
    // Report text can become a copy/pasted shell command. Quote metacharacters,
    // not just spaces; never put terminal controls into a suggested command.
    if path.chars().any(char::is_control) {
        return format!(
            "Select the key at {} and {}.",
            path.escape_debug(),
            if permissions {
                "restrict its permissions to owner read/write"
            } else {
                "set a passphrase with ssh-keygen"
            }
        );
    }
    let simple = path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "~/_-.".contains(c));
    let arg = if cfg!(windows) {
        // PowerShell 5.1 passes `~` to native programs literally (checked: ssh-keygen
        // gets "~/.ssh/..." and fails). $HOME works in PowerShell 5.1 and 7.
        let relative = path.strip_prefix("~/").unwrap_or(path);
        format!(
            "\"$HOME\\{}\"",
            relative
                .replace('/', "\\")
                .replace('`', "``")
                .replace('$', "`$")
                .replace('"', "`\"")
        )
    } else if simple {
        path.to_owned()
    } else {
        // A quoted tilde does not expand in POSIX shells; expand HOME instead.
        let relative = path.strip_prefix("~/").unwrap_or(path);
        format!(
            "\"$HOME/{}\"",
            relative
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$")
                .replace('`', "\\`")
        )
    };
    if permissions {
        format!("Restrict the private key to its owner with chmod 600 {arg}.")
    } else {
        format!("Set a passphrase with ssh-keygen -p -f {arg}; use ssh-agent for convenience.")
    }
}

fn issue(
    id: &'static str,
    level: Level,
    path: &str,
    line: usize,
    message: &str,
    fix: &str,
) -> Issue {
    Issue {
        id,
        level,
        path: path.into(),
        line,
        message: message.into(),
        fix: fix.into(),
    }
}

fn linked(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0 // Includes directory junctions.
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !linked(&m))
}

fn read_file(path: &Path) -> Option<(String, Metadata)> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || linked(&meta) || meta.len() > MAX_BYTES {
        return None;
    }
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    Some((String::from_utf8(bytes).ok()?, meta))
}

fn exposed_permissions(meta: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o077 != 0
    }
    // Windows readonly is not an ACL; do not infer exposure from it.
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

fn literal(value: &str) -> bool {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    !value.is_empty()
        && !value.contains("${")
        && !value.contains("{{")
        && !(value.starts_with('<') && value.ends_with('>'))
        && !matches!(
            lower.as_str(),
            "null" | "undefined" | "true" | "false" | "changeme" | "example" | "token" | "password"
        )
        && ![
            "your_", "your-", "replace_", "replace-", "insert_", "example_", "example-",
        ]
        .iter()
        .any(|p| lower.starts_with(p))
        && !value
            .bytes()
            .all(|b| matches!(b, b'x' | b'X' | b'*' | b'.'))
}

// npm config may interpolate ${ENV}; those are references, not tokens on disk.
// https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/
fn npmrc(text: &str, issues: &mut Vec<Issue>) {
    for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = line.trim();
        if line.starts_with(['#', ';', '[']) {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let key = if let Some((scope, field)) = key.rsplit_once(':') {
            if !scope.starts_with("//") || scope.len() <= 2 {
                continue;
            }
            field
        } else {
            key
        };
        if !matches!(key, "_authToken" | "_auth" | "_password") {
            continue;
        }
        let value = value.trim();
        let value = if value.starts_with(['\'', '"']) {
            let quote = value.as_bytes()[0] as char;
            let Some(end) = value[1..].find(quote).map(|n| n + 1) else {
                continue;
            };
            let tail = value[end + 1..].trim();
            if !tail.is_empty() && !tail.starts_with(['#', ';']) {
                continue;
            }
            &value[1..end]
        } else {
            value.split(['#', ';']).next().unwrap_or("").trim()
        };
        if !literal(value) {
            continue;
        }
        let stored = match key {
            "_auth" => basic_auth(value),
            "_password" => decode64(value)
                .and_then(|b| String::from_utf8(b).ok())
                .is_some_and(|s| literal(&s)),
            _ => !value.chars().any(char::is_whitespace),
        };
        if stored {
            issues.push(issue("npmrc-plaintext-token", Level::High, "~/.npmrc", index + 1,
                "npm credentials are stored unencrypted; validity was not checked.",
                "Remove the literal credential; use an environment reference such as ${NPM_TOKEN}, supplied by a secret store."));
        }
    }
}

// Conservative single-line scalar reader. Unsupported escaping/multiline forms
// are skipped rather than mistaken for a stored credential.
fn scalar(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.starts_with(['\'', '"']) {
        let quote = value.as_bytes()[0] as char;
        let end = value[1..].find(quote)? + 1;
        let inner = &value[1..end];
        let tail = value[end + 1..].trim();
        if inner.contains('\\') || (!tail.is_empty() && !tail.starts_with(['#', ';'])) {
            return None;
        }
        Some(inner)
    } else {
        Some(value.split(['#', ';']).next()?.trim())
    }
}

// Keep section names internal. Indented continuation lines are not INI keys.
fn ini_fields(text: &str) -> Vec<(&str, &str, &str, usize)> {
    let (mut section, mut option_indent) = (None, None);
    let mut fields = Vec::new();
    for (index, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if option_indent.is_some_and(|last| indent > last) {
            continue;
        }
        if line.starts_with('[') {
            section = line.find(']').and_then(|end| {
                let tail = line[end + 1..].trim();
                (!line[1..end].trim().is_empty()
                    && (tail.is_empty() || tail.starts_with(['#', ';'])))
                .then_some(line[1..end].trim())
            });
            option_indent = None;
            continue;
        }
        let Some((key, value)) = line.split_once(['=', ':']) else {
            continue;
        };
        option_indent = Some(indent);
        if let (Some(section), Some(value)) = (section, scalar(value)) {
            fields.push((section, key.trim(), value, index + 1));
        }
    }
    fields
}

fn pypirc(text: &str, issues: &mut Vec<Issue>) {
    for (_, key, value, line) in ini_fields(text) {
        if key.eq_ignore_ascii_case("password") && literal(value) {
            issues.push(issue("pypirc-plaintext-password", Level::High, "~/.pypirc", line,
                "Python package registry password is stored unencrypted; validity was not checked.",
                "Remove the password line from ~/.pypirc; use keyring (pip install keyring; Twine reads it) or supply TWINE_PASSWORD from a secret store."));
        }
    }
}

fn git_credentials(text: &str, issues: &mut Vec<Issue>) {
    let helper = if cfg!(windows) {
        "manager"
    } else if cfg!(target_os = "macos") {
        "osxkeychain"
    } else {
        "libsecret"
    };
    for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') || line.chars().any(char::is_whitespace) {
            continue;
        }
        let Some((scheme, rest)) = line.split_once("://") else {
            continue;
        };
        if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
        {
            continue;
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let Some((userinfo, host)) = authority.rsplit_once('@') else {
            continue;
        };
        if host.is_empty() || userinfo.contains('@') {
            continue;
        }
        let Some((user, secret)) = userinfo.split_once(':') else {
            continue;
        };
        if user.is_empty() {
            continue;
        }
        let Some(secret) = percent_decode(secret) else {
            continue;
        };
        if literal(&secret) {
            issues.push(issue("git-credentials-plaintext", Level::High, "~/.git-credentials", index + 1,
                "Git credentials are stored unencrypted; validity was not checked.",
                &format!("Run git config --global credential.helper {helper}, then remove ~/.git-credentials and authenticate again.")));
        }
    }
}

fn percent_decode(text: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut rest = text.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%' {
            let a = (*tail.first()? as char).to_digit(16)?;
            let b = (*tail.get(1)? as char).to_digit(16)?;
            bytes.push((a * 16 + b) as u8);
            rest = &tail[2..];
        } else {
            bytes.push(first);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok()
}

// Tokenize one netrc line, preserving whether a value was quoted. Macro bodies
// are skipped before this function is called. Quoted spaces and escapes follow
// https://everything.curl.dev/usingcurl/netrc.html .
fn netrc_words(line: &str) -> Option<Vec<(String, bool)>> {
    let mut chars = line.chars().peekable();
    let mut words = Vec::new();
    while let Some(&first) = chars.peek() {
        if first.is_whitespace() {
            chars.next();
            continue;
        }
        if first == '#' {
            break;
        }
        let quoted = matches!(first, '\'' | '"');
        if quoted {
            chars.next();
        }
        let mut word = String::new();
        let mut closed = !quoted;
        while let Some(c) = chars.next() {
            if quoted && c == first {
                closed = true;
                break;
            }
            if !quoted && c.is_whitespace() {
                break;
            }
            if c == '\\' {
                word.push(match chars.next()? {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    c => c,
                });
            } else {
                word.push(c);
            }
        }
        if !closed
            || (quoted
                && chars
                    .peek()
                    .is_some_and(|c| !c.is_whitespace() && *c != '#'))
        {
            return None;
        }
        words.push((word, quoted));
    }
    Some(words)
}

fn netrc(text: &str, path: &str, issues: &mut Vec<Issue>) {
    let (mut in_macro, mut active, mut pending) = (false, false, None);
    for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        if in_macro {
            if line.trim().is_empty() {
                in_macro = false;
            }
            continue;
        }
        let Some(words) = netrc_words(line) else {
            active = false;
            pending = None;
            continue;
        };
        for (word, quoted) in words {
            if let Some((key, key_line)) = pending.take() {
                // A missing password must not turn the next record's keyword
                // into a password. Other fields consume their values verbatim.
                if key != "password"
                    || quoted
                    || !matches!(
                        word.as_str(),
                        "machine" | "default" | "login" | "password" | "account" | "macdef"
                    )
                {
                    if key == "machine" {
                        active = !word.is_empty();
                    }
                    if key == "password" && active && literal(&word) {
                        issues.push(issue("netrc-plaintext-password", Level::High, path, key_line,
                            "netrc password is stored unencrypted; validity was not checked.",
                            &format!("Move credentials to a password manager or credential helper, then remove {path}.")));
                    }
                    continue;
                }
            }
            if quoted {
                continue;
            }
            match word.as_str() {
                "machine" => {
                    active = false;
                    pending = Some(("machine", index + 1));
                }
                "default" => active = true,
                "login" => pending = Some(("login", index + 1)),
                "account" => pending = Some(("account", index + 1)),
                "password" => pending = Some(("password", index + 1)),
                "macdef" => {
                    in_macro = true;
                    pending = None;
                    break;
                }
                _ => {}
            }
        }
    }
}

fn cargo_credentials(text: &str, path: &str, issues: &mut Vec<Issue>) {
    let provider = if cfg!(windows) {
        "cargo:wincred"
    } else if cfg!(target_os = "macos") {
        "cargo:macos-keychain"
    } else {
        "cargo:libsecret"
    };
    let (mut section, mut multiline) = (false, None);
    for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = line.trim();
        if let Some(delimiter) = multiline {
            if line.contains(delimiter) {
                multiline = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line.find(']').is_some_and(|end| {
                end > 1
                    && !line.starts_with("[[")
                    && (line[end + 1..].trim().is_empty()
                        || line[end + 1..].trim().starts_with('#'))
            });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if let Some(delimiter) = ["\"\"\"", "'''"].into_iter().find(|d| value.starts_with(d)) {
            if !value[3..].contains(delimiter) {
                multiline = Some(delimiter);
            }
            continue;
        }
        if section
            && matches!(key.trim(), "token" | "\"token\"" | "'token'")
            && value.starts_with(['\'', '"'])
            && scalar(value).is_some_and(literal)
        {
            issues.push(issue("cargo-plaintext-token", Level::High, path, index + 1,
                "Cargo registry token is stored unencrypted; validity was not checked.",
                &format!("Run cargo logout (for each affected registry); in ~/.cargo/config.toml set [registry] global-credential-providers = [\"{provider}\"], then run cargo login again.")));
        }
    }
}

// Deliberately a block-style YAML subset: users -> list item -> user -> field.
// Depth matters: a token/password inside exec env, auth-provider config,
// extensions, or another top-level section is not a static AuthInfo credential.
fn kubeconfig(text: &str, issues: &mut Vec<Issue>) {
    let (mut users, mut item_indent, mut user_indent, mut field_indent, mut block_indent) =
        (false, None, None, None, None);
    let mut lines = text
        .trim_start_matches('\u{feff}')
        .lines()
        .enumerate()
        .peekable();
    while let Some((index, raw)) = lines.next() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        if raw[..raw.len() - raw.trim_start().len()].contains('\t') {
            users = false;
            continue;
        }
        if block_indent.is_some_and(|parent| indent > parent) {
            continue;
        }
        block_indent = None;
        if indent == 0 && !line.starts_with("- ") {
            users = line
                .strip_prefix("users:")
                .is_some_and(|v| v.trim().is_empty() || v.trim().starts_with('#'));
            item_indent = None;
            user_indent = None;
            field_indent = None;
            continue;
        }
        if !users {
            continue;
        }
        let (content, key_indent) = if let Some(content) = line.strip_prefix("- ") {
            if item_indent.is_some_and(|item| indent != item) {
                continue;
            }
            item_indent = Some(indent);
            user_indent = None;
            field_indent = None;
            (content.trim_start(), indent + 2)
        } else {
            (line, indent)
        };
        let Some((key, value)) = content.split_once(':') else {
            continue;
        };
        if !value.is_empty() && !value.starts_with(char::is_whitespace) {
            continue; // A colon without following whitespace is part of a YAML scalar.
        }
        let key = key.trim();
        let value = value.trim();
        let is_block = matches!(
            value.split_whitespace().next(),
            Some("|" | "|-" | "|+" | ">" | ">-" | ">+")
        );
        if is_block {
            block_indent = Some(key_indent);
        }
        if user_indent.is_some_and(|parent| key_indent <= parent) {
            user_indent = None;
            field_indent = None;
        }
        if key == "user"
            && item_indent.is_some_and(|item| key_indent == item + 2)
            && (value.is_empty() || value.starts_with('#'))
        {
            user_indent = Some(key_indent);
            continue;
        }
        let Some(parent) = user_indent else { continue };
        if key_indent <= parent {
            continue;
        }
        let direct = *field_indent.get_or_insert(key_indent);
        if key_indent != direct || !matches!(key, "token" | "client-key-data" | "password") {
            continue;
        }
        let stored = if is_block {
            let mut body = String::new();
            while let Some((_, next)) = lines.peek() {
                let next_indent = next.len() - next.trim_start_matches(' ').len();
                if !next.trim().is_empty() && next_indent <= key_indent {
                    break;
                }
                body.push_str(next.trim());
                body.push('\n');
                lines.next();
            }
            literal(&body)
        } else {
            !value.starts_with(['{', '[', '&', '*', '!'])
                && scalar(value).is_some_and(|s| s != "~" && literal(s))
        };
        if stored {
            issues.push(issue("kubeconfig-embedded-credentials", Level::Medium, "~/.kube/config", index + 1,
                "Kubeconfig embeds a static credential; validity was not checked.",
                "Use an exec authentication plugin (aws eks get-token, gke-gcloud-auth-plugin, or kubelogin) instead of a static token or client key."));
            return;
        }
    }
}

fn aws_credentials(text: &str, issues: &mut Vec<Issue>) {
    let mut reported = std::collections::HashSet::new();
    for (profile, key, value, line) in ini_fields(text) {
        if key == "aws_secret_access_key" && literal(value) && reported.insert(profile) {
            issues.push(issue("aws-plaintext-keys", Level::High, "~/.aws/credentials", line,
                "AWS secret access key is stored unencrypted; validity was not checked.",
                "Use aws configure sso (or aws-vault), then remove static keys from ~/.aws/credentials."));
        }
    }
}

fn basic_auth(value: &str) -> bool {
    decode64(value)
        .and_then(|b| String::from_utf8(b).ok())
        .is_some_and(|s| {
            s.split_once(':')
                .is_some_and(|(user, secret)| !user.is_empty() && literal(secret))
        })
}

// Docker auth is reversible base64, not encryption. Even with a helper configured,
// a leftover auth entry still stores credentials on disk.
// https://docs.docker.com/reference/cli/docker/login/
fn docker(text: &str, issues: &mut Vec<Issue>) {
    if !bounded_json(text) {
        return;
    }
    let Ok(root) = json::parse(text) else { return };
    let Some(auths) = root.get("auths").and_then(Json::as_object) else {
        return;
    };
    if auths.values().any(|entry| {
        entry
            .get("auth")
            .and_then(Json::as_str)
            .is_some_and(basic_auth)
            || ["identitytoken", "registrytoken", "password"]
                .iter()
                .any(|key| entry.get(key).and_then(Json::as_str).is_some_and(literal))
    }) {
        issues.push(issue("docker-plaintext-auth", Level::High, "~/.docker/config.json", 0,
            "Docker registry credentials are stored unencrypted; validity was not checked.",
            "Configure Docker credsStore or credHelpers with an OS credential store; remove stored auth entries and log in again."));
    }
}

// Bound recursion before passing untrusted input to the shared JSON parser.
fn bounded_json(text: &str) -> bool {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for b in text.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 64 {
                        return false;
                    }
                }
                b'}' | b']' => {
                    if depth == 0 {
                        return false;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
    }
    depth == 0 && !quoted
}

fn decode64(text: &str) -> Option<Vec<u8>> {
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (i, chunk) in text.as_bytes().as_chunks::<4>().0.iter().enumerate() {
        let a = digit(chunk[0])?;
        let b = digit(chunk[1])?;
        out.push(a << 2 | b >> 4);
        let last = (i + 1) * 4 == text.len();
        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || b & 15 != 0 {
                return None;
            }
        } else {
            let c = digit(chunk[2])?;
            out.push(b << 4 | c >> 2);
            if chunk[3] == b'=' {
                if !last || c & 3 != 0 {
                    return None;
                }
            } else {
                out.push(c << 6 | digit(chunk[3])?);
            }
        }
    }
    Some(out)
}

// Some(true): structurally recognizable unencrypted private key; Some(false):
// encrypted container. None: unsupported, public-only, malformed or incomplete.
// This checks storage, not whether a key is cryptographically valid or authorized.
fn private_key(text: &str) -> Option<bool> {
    let mut lines = text.trim_start_matches('\u{feff}').trim().lines();
    let label = lines
        .next()?
        .trim()
        .strip_prefix("-----BEGIN ")?
        .strip_suffix("-----")?;
    if !matches!(
        label,
        "OPENSSH PRIVATE KEY"
            | "RSA PRIVATE KEY"
            | "DSA PRIVATE KEY"
            | "EC PRIVATE KEY"
            | "PRIVATE KEY"
            | "ENCRYPTED PRIVATE KEY"
    ) {
        return None;
    }
    let end = format!("-----END {label}-----");
    let (mut body, mut proc_type, mut block_size, mut ended) = (String::new(), false, None, false);
    for line in lines.by_ref() {
        let line = line.trim();
        if line == end {
            ended = true;
            break;
        }
        if line.is_empty() {
            continue;
        }
        if line == "Proc-Type: 4,ENCRYPTED" && body.is_empty() && !proc_type {
            proc_type = true;
        } else if let Some(info) = line.strip_prefix("DEK-Info: ") {
            if !body.is_empty() || block_size.is_some() {
                return None;
            }
            let (cipher, iv) = info.split_once(',')?;
            let len = match cipher {
                "AES-128-CBC" | "AES-192-CBC" | "AES-256-CBC" => 32,
                "DES-EDE3-CBC" | "DES-CBC" => 16,
                _ => return None,
            };
            if iv.len() != len || !iv.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            block_size = Some(len / 2);
        } else {
            body.push_str(line);
        }
    }
    if !ended || lines.any(|l| !l.trim().is_empty()) {
        return None;
    }
    let data = decode64(&body)?;
    if proc_type || block_size.is_some() {
        return (proc_type
            && matches!(
                label,
                "RSA PRIVATE KEY" | "DSA PRIVATE KEY" | "EC PRIVATE KEY"
            )
            && block_size.is_some_and(|n| data.len() >= n && data.len().is_multiple_of(n)))
        .then_some(false);
    }
    match label {
        "OPENSSH PRIVATE KEY" => openssh(&data),
        "RSA PRIVATE KEY" => integer_key(&data, 9).then_some(true),
        "DSA PRIVATE KEY" => integer_key(&data, 6).then_some(true),
        "EC PRIVATE KEY" => ec_der(&data).then_some(true),
        "PRIVATE KEY" => pkcs8(&data).then_some(true),
        "ENCRYPTED PRIVATE KEY" => encrypted_der(&data).then_some(false),
        _ => None,
    }
}

struct Ssh<'a>(&'a [u8]);
impl<'a> Ssh<'a> {
    fn number(&mut self) -> Option<u32> {
        let (value, rest) = self.0.split_at_checked(4)?;
        self.0 = rest;
        Some(u32::from_be_bytes(value.try_into().ok()?))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.number()? as usize;
        let (value, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(value)
    }
}

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
fn openssh(data: &[u8]) -> Option<bool> {
    let mut outer = Ssh(data.strip_prefix(b"openssh-key-v1\0")?);
    let cipher = outer.string()?;
    let kdf = outer.string()?;
    let options = outer.string()?;
    if outer.number()? != 1 {
        return None;
    }
    let mut public = Ssh(outer.string()?);
    let private = outer.string()?;
    if !outer.0.is_empty() {
        return None;
    }
    let kind = public.string()?;
    let count = match kind {
        b"ssh-ed25519" => 1,
        b"ssh-rsa" => 2,
        b"ssh-dss" => 4,
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => 2,
        _ => return None, // In particular, hardware-backed keys are not plain private keys.
    };
    let mut fields = Vec::new();
    for _ in 0..count {
        let value = public.string()?;
        if value.is_empty() {
            return None;
        }
        fields.push(value);
    }
    if !public.0.is_empty() {
        return None;
    }
    if cipher != b"none" {
        let block = match cipher {
            b"aes128-ctr" | b"aes192-ctr" | b"aes256-ctr" | b"aes128-cbc" | b"aes192-cbc"
            | b"aes256-cbc" => 16,
            b"3des-cbc" => 8,
            _ => return None,
        };
        let mut options = Ssh(options);
        return (kdf == b"bcrypt"
            && !options.string()?.is_empty()
            && options.number()? > 0
            && options.0.is_empty()
            && private.len() >= block
            && private.len().is_multiple_of(block))
        .then_some(false);
    }
    if kdf != b"none" || !options.is_empty() || !private.len().is_multiple_of(8) {
        return None;
    }
    let mut private = Ssh(private);
    if private.number()? != private.number()? || private.string()? != kind {
        return None;
    }
    match kind {
        b"ssh-ed25519" => {
            if fields[0].len() != 32 || private.string()? != fields[0] {
                return None;
            }
            let secret = private.string()?;
            if secret.len() != 64 || &secret[32..] != fields[0] {
                return None;
            }
        }
        b"ssh-rsa" => {
            if !fields.iter().all(|f| positive(f))
                || private.string()? != fields[1]
                || private.string()? != fields[0]
            {
                return None;
            }
            for _ in 0..4 {
                if !positive(private.string()?) {
                    return None;
                }
            }
        }
        b"ssh-dss" => {
            for field in fields {
                if !positive(field) || private.string()? != field {
                    return None;
                }
            }
            if !positive(private.string()?) {
                return None;
            }
        }
        _ => {
            let size = match fields[0] {
                b"nistp256" => 32,
                b"nistp384" => 48,
                b"nistp521" => 66,
                _ => return None,
            };
            if !kind.ends_with(fields[0])
                || fields[1].len() != 1 + 2 * size
                || fields[1][0] != 4
                || private.string()? != fields[0]
                || private.string()? != fields[1]
                || !positive(private.string()?)
            {
                return None;
            }
        }
    }
    private.string()?; // Comment is never copied into Issue.
    (private.0.len() < 8
        && private
            .0
            .iter()
            .enumerate()
            .all(|(i, b)| *b as usize == i + 1))
    .then_some(true)
}

fn positive(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes[0] & 0x80 == 0
        && bytes.iter().any(|b| *b != 0)
        && (bytes[0] != 0 || bytes.get(1).is_some_and(|b| b & 0x80 != 0))
}

// Minimal definite-length DER readers for PKCS#1 (RFC 8017), PKCS#8
// (RFC 5208), and SEC1 (RFC 5915). Never infer encryption from the PEM label alone.
fn der<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    if *input.first()? != tag {
        return None;
    }
    let first = *input.get(1)?;
    let (len, offset) = if first < 128 {
        (first as usize, 2)
    } else {
        let n = (first & 127) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let length = input.get(2..2 + n)?;
        if length[0] == 0 {
            return None;
        }
        let mut len = 0usize;
        for b in length {
            len = len.checked_mul(256)?.checked_add(*b as usize)?;
        }
        if len < 128 {
            return None;
        }
        (len, 2 + n)
    };
    let (value, rest) = input.get(offset..)?.split_at_checked(len)?;
    *input = rest;
    Some(value)
}

fn sequence(mut data: &[u8]) -> Option<&[u8]> {
    let inner = der(&mut data, 0x30)?;
    data.is_empty().then_some(inner)
}

fn integer_key(data: &[u8], count: usize) -> bool {
    let Some(mut inner) = sequence(data) else {
        return false;
    };
    if der(&mut inner, 2) != Some(&[0][..]) {
        return false;
    }
    for _ in 1..count {
        if !der(&mut inner, 2).is_some_and(positive) {
            return false;
        }
    }
    inner.is_empty()
}

fn ec_der(data: &[u8]) -> bool {
    let Some(mut inner) = sequence(data) else {
        return false;
    };
    if der(&mut inner, 2) != Some(&[1][..])
        || !der(&mut inner, 4).is_some_and(|b| matches!(b.len(), 32 | 48 | 66))
    {
        return false;
    }
    if inner.first() == Some(&0xa0) {
        let Some(mut params) = der(&mut inner, 0xa0) else {
            return false;
        };
        if !der(&mut params, 6).is_some_and(|b| !b.is_empty()) || !params.is_empty() {
            return false;
        }
    }
    if inner.first() == Some(&0xa1) {
        let Some(mut point) = der(&mut inner, 0xa1) else {
            return false;
        };
        if !der(&mut point, 3).is_some_and(|b| b.len() >= 2 && b[0] == 0) || !point.is_empty() {
            return false;
        }
    }
    inner.is_empty()
}

fn pkcs8(data: &[u8]) -> bool {
    let Some(mut inner) = sequence(data) else {
        return false;
    };
    if der(&mut inner, 2) != Some(&[0][..]) {
        return false;
    }
    let Some(mut algorithm) = der(&mut inner, 0x30) else {
        return false;
    };
    let Some(oid) = der(&mut algorithm, 6) else {
        return false;
    };
    let Some(mut key) = der(&mut inner, 4) else {
        return false;
    };
    if !inner.is_empty() {
        return false;
    }
    match oid {
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" => {
            if !algorithm.is_empty() && der(&mut algorithm, 5) != Some(&[][..]) {
                return false;
            }
            algorithm.is_empty() && integer_key(key, 9)
        }
        b"\x2a\x86\x48\xce\x3d\x02\x01" => {
            der(&mut algorithm, 6).is_some_and(|b| !b.is_empty())
                && algorithm.is_empty()
                && ec_der(key)
        }
        b"\x2b\x65\x70" => {
            algorithm.is_empty()
                && der(&mut key, 4).is_some_and(|b| b.len() == 32)
                && key.is_empty()
        }
        _ => false,
    }
}

fn encrypted_der(data: &[u8]) -> bool {
    let Some(mut inner) = sequence(data) else {
        return false;
    };
    let Some(mut algorithm) = der(&mut inner, 0x30) else {
        return false;
    };
    der(&mut algorithm, 6) == Some(&b"\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d"[..])
        && der(&mut algorithm, 0x30).is_some_and(|b| !b.is_empty())
        && algorithm.is_empty()
        && der(&mut inner, 4).is_some_and(|b| b.len() >= 8)
        && inner.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // All credential-shaped fixtures are synthetic and assembled at runtime.
    fn base64(bytes: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            out.push(alphabet[(a >> 2) as usize] as char);
            out.push(alphabet[((a & 3) << 4 | b >> 4) as usize] as char);
            out.push(if chunk.len() > 1 {
                alphabet[((b & 15) << 2 | c >> 6) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                alphabet[(c & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }
    fn pem(label: &str, data: &[u8]) -> String {
        format!(
            "-----{} {label}-----\n{}\n-----{} {label}-----\n",
            "BEGIN",
            base64(data),
            "END"
        )
    }
    fn string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    fn openssh_parts() -> (Vec<u8>, Vec<u8>) {
        let mut public = Vec::new();
        string(&mut public, b"ssh-ed25519");
        string(&mut public, &[42; 32]);
        let mut private = Vec::new();
        private.extend_from_slice(&17u32.to_be_bytes());
        private.extend_from_slice(&17u32.to_be_bytes());
        string(&mut private, b"ssh-ed25519");
        string(&mut private, &[42; 32]);
        string(&mut private, &[[19; 32], [42; 32]].concat());
        string(&mut private, b"synthetic-comment-canary");
        let padding = (8 - private.len() % 8) % 8;
        private.extend(1..=padding as u8);
        (public, private)
    }
    fn container(
        cipher: &[u8],
        kdf: &[u8],
        options: &[u8],
        public: &[u8],
        private: &[u8],
    ) -> Vec<u8> {
        let mut data = b"openssh-key-v1\0".to_vec();
        string(&mut data, cipher);
        string(&mut data, kdf);
        string(&mut data, options);
        data.extend_from_slice(&1u32.to_be_bytes());
        string(&mut data, public);
        string(&mut data, private);
        data
    }
    fn ssh_fixture(encrypted: bool) -> String {
        let (public, private) = openssh_parts();
        let data = if encrypted {
            let mut options = Vec::new();
            string(&mut options, &[7; 16]);
            options.extend_from_slice(&16u32.to_be_bytes());
            container(b"aes256-ctr", b"bcrypt", &options, &public, &[9; 144])
        } else {
            container(b"none", b"none", b"", &public, &private)
        };
        pem("OPENSSH PRIVATE KEY", &data)
    }
    fn tlv(tag: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 256);
        let mut out = vec![tag];
        if data.len() >= 128 {
            out.push(0x81);
        }
        out.push(data.len() as u8);
        out.extend_from_slice(data);
        out
    }
    fn integers(count: usize) -> Vec<u8> {
        let mut inner = tlv(2, &[0]);
        for i in 1..count {
            inner.extend(tlv(2, &[i as u8]));
        }
        tlv(0x30, &inner)
    }
    fn ec_fixture() -> Vec<u8> {
        tlv(0x30, &[tlv(2, &[1]), tlv(4, &[25; 32])].concat())
    }

    #[test]
    fn base64_strict_and_roundtrips() {
        for size in 1..=255 {
            let bytes: Vec<_> = (0..size).map(|n| n as u8).collect();
            assert_eq!(decode64(&base64(&bytes)), Some(bytes));
        }
        for bad in [
            "", "a", "!!!!", "====", "YQ=A", "YQ==YQ==", "YR==", "YWJ=", "Y Q=",
        ] {
            assert_eq!(decode64(bad), None);
        }
    }

    #[test]
    fn openssh_checks_structure_and_encryption() {
        assert_eq!(private_key(&ssh_fixture(false)), Some(true));
        assert_eq!(private_key(&ssh_fixture(true)), Some(false));
        let (public, private) = openssh_parts();
        let data = container(b"none", b"none", b"", &public, &private);
        for end in 0..data.len() {
            assert_eq!(openssh(&data[..end]), None);
        }
        assert_eq!(
            openssh(&container(b"none", b"bcrypt", b"", &public, &private)),
            None
        );
        assert_eq!(
            openssh(&container(
                b"none",
                b"none",
                b"unexpected",
                &public,
                &private
            )),
            None
        );
        let mut bad = private.clone();
        bad[0] ^= 1; // Checkints disagree.
        assert_eq!(
            openssh(&container(b"none", b"none", b"", &public, &bad)),
            None
        );
        *bad.last_mut().unwrap() = 255;
        bad[0] ^= 1;
        assert_eq!(
            openssh(&container(b"none", b"none", b"", &public, &bad)),
            None
        );
        let mut bad_public = public.clone();
        *bad_public.last_mut().unwrap() ^= 1;
        assert_eq!(
            openssh(&container(b"none", b"none", b"", &bad_public, &private)),
            None
        );
        assert_eq!(private_key(&pem("PUBLIC KEY", &data)), None);
    }

    #[test]
    fn openssh_rsa_dsa_and_ecdsa_fields() {
        type KeyFields<'a> = (&'a [u8], Vec<Vec<u8>>, Vec<Vec<u8>>);
        let fixtures: Vec<KeyFields<'_>> = vec![
            (
                b"ssh-rsa",
                vec![vec![3], vec![17]],
                vec![vec![17], vec![3], vec![7], vec![5], vec![11], vec![13]],
            ),
            (
                b"ssh-dss",
                vec![vec![3], vec![5], vec![7], vec![11]],
                vec![vec![3], vec![5], vec![7], vec![11], vec![13]],
            ),
            (
                b"ecdsa-sha2-nistp256",
                vec![b"nistp256".to_vec(), [vec![4], vec![42; 64]].concat()],
                vec![
                    b"nistp256".to_vec(),
                    [vec![4], vec![42; 64]].concat(),
                    vec![17; 32],
                ],
            ),
        ];
        for (kind, public_fields, private_fields) in fixtures {
            let mut public = Vec::new();
            string(&mut public, kind);
            for field in public_fields {
                string(&mut public, &field);
            }
            let mut private = [17u32.to_be_bytes(), 17u32.to_be_bytes()].concat();
            string(&mut private, kind);
            for field in private_fields {
                string(&mut private, &field);
            }
            string(&mut private, b"");
            private.extend(1..=((8 - private.len() % 8) % 8) as u8);
            assert_eq!(
                openssh(&container(b"none", b"none", b"", &public, &private)),
                Some(true)
            );
        }
    }

    #[test]
    fn pem_and_der_formats_require_complete_structures() {
        for (label, data) in [
            ("RSA PRIVATE KEY", integers(9)),
            ("DSA PRIVATE KEY", integers(6)),
            ("EC PRIVATE KEY", ec_fixture()),
        ] {
            assert_eq!(private_key(&pem(label, &data)), Some(true));
            for end in 0..data.len() {
                assert_eq!(private_key(&pem(label, &data[..end])), None);
            }
            assert_eq!(private_key(&format!("{}junk", pem(label, &data))), None);
            let encoded = pem(label, &data);
            assert_eq!(
                private_key(&encoded.lines().take(2).collect::<Vec<_>>().join("\n")),
                None
            );
        }
        let algorithms = [
            (
                tlv(
                    0x30,
                    &[tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"), tlv(5, &[])].concat(),
                ),
                integers(9),
            ),
            (
                tlv(
                    0x30,
                    &[
                        tlv(6, b"\x2a\x86\x48\xce\x3d\x02\x01"),
                        tlv(6, b"\x2a\x86\x48\xce\x3d\x03\x01\x07"),
                    ]
                    .concat(),
                ),
                ec_fixture(),
            ),
            (tlv(0x30, &tlv(6, b"\x2b\x65\x70")), tlv(4, &[23; 32])),
        ];
        for (algorithm, key) in algorithms {
            let data = tlv(0x30, &[tlv(2, &[0]), algorithm, tlv(4, &key)].concat());
            assert_eq!(private_key(&pem("PRIVATE KEY", &data)), Some(true));
        }
        let encrypted = pem("RSA PRIVATE KEY", &[9; 32]).replacen(
            '\n',
            &format!(
                "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,{}\n\n",
                "A1".repeat(16)
            ),
            1,
        );
        assert_eq!(private_key(&encrypted), Some(false));
        assert_eq!(
            private_key(&encrypted.replace("Proc-Type: 4,ENCRYPTED\n", "")),
            None
        );
        assert_eq!(private_key(&pem("RSA PRIVATE KEY", &[9; 32])), None);
        assert_eq!(
            private_key(&encrypted.replace(&base64(&[9; 32]), &base64(&[9; 24]))),
            None
        );
        let pbes2 = tlv(
            0x30,
            &[
                tlv(
                    0x30,
                    &[
                        tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d"),
                        tlv(
                            0x30,
                            &[
                                tlv(
                                    0x30,
                                    &[
                                        tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c"),
                                        tlv(0x30, &[tlv(4, &[7; 16]), tlv(2, &[16])].concat()),
                                    ]
                                    .concat(),
                                ),
                                tlv(
                                    0x30,
                                    &[
                                        tlv(6, b"\x60\x86\x48\x01\x65\x03\x04\x01\x2a"),
                                        tlv(4, &[8; 16]),
                                    ]
                                    .concat(),
                                ),
                            ]
                            .concat(),
                        ),
                    ]
                    .concat(),
                ),
                tlv(4, &[9; 32]),
            ]
            .concat(),
        );
        assert_eq!(
            private_key(&pem("ENCRYPTED PRIVATE KEY", &pbes2)),
            Some(false)
        );
        assert_eq!(private_key(&pem("PRIVATE KEY", &pbes2)), None);
        for bytes in [
            vec![0x30, 0x80],
            vec![0x30, 0x84, 255, 255, 255, 255],
            vec![0x30, 0x81, 0],
        ] {
            assert_eq!(private_key(&pem("PRIVATE KEY", &bytes)), None);
        }
    }

    #[test]
    fn npm_credentials_quotes_comments_references_and_lines() {
        let token = ["canary", "-npm-secret-123"].concat();
        let basic = base64(format!("person:{token}").as_bytes());
        let pass = base64(token.as_bytes());
        let text = format!(
            "\u{feff}; comment\r\n//registry.example/:_authToken=\"{token}\" ; note\r\n_auth={basic}\n_password='{pass}'\n"
        );
        let mut issues = Vec::new();
        npmrc(&text, &mut issues);
        assert_eq!(
            issues.iter().map(|i| i.line).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        for issue in &issues {
            assert_eq!(issue.id, "npmrc-plaintext-token");
            assert_eq!(issue.path, "~/.npmrc");
            assert_eq!(issue.level, Level::High);
        }
        assert_private(&issues, &[&token, &basic, &pass, "person"]);
        let mut ignored = Vec::new();
        npmrc(
            "# _authToken=ignored\n; _authToken=ignored\n_authToken=${NPM_TOKEN}\n_authToken=\"${TOKEN}\"\n_authToken=\n_authToken='unterminated\n_authToken=\"quoted\"garbage\n_authToken=<token>\n_authToken=your_token_here\n_authToken=xxxxxxxx\n_auth=not-base64\n_password=eA==\nother:_authToken=abc\nfoo=bar\n_authToken[]=abc",
            &mut ignored,
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn docker_helpers_stale_auth_tokens_and_malformed_json() {
        let secret = ["canary", "-docker-secret-456"].concat();
        let auth = base64(format!("person:{secret}").as_bytes());
        for entry in [
            format!("\"auth\":\"{auth}\""),
            format!("\"identitytoken\":\"{secret}\""),
            format!("\"registrytoken\":\"{secret}\""),
            format!("\"password\":\"{secret}\""),
        ] {
            let mut issues = Vec::new();
            docker(
                &format!(
                    "{{\"credsStore\":\"desktop\",\"auths\":{{\"private-host\":{{{entry}}},\"other\":{{{entry}}}}}}}"
                ),
                &mut issues,
            );
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].id, "docker-plaintext-auth");
            assert_eq!(issues[0].line, 0);
            assert_private(&issues, &[&secret, &auth, "person", "private-host"]);
        }
        for text in [
            "{",
            "{}",
            "null",
            "{\"auths\":[]}",
            "{\"credsStore\":\"desktop\",\"auths\":{\"host\":{}}}",
            "{\"auths\":{\"host\":{\"auth\":\"invalid\",\"identitytoken\":\"\"}}}",
            "{\"auths\":{\"host\":{\"auth\":42}}}",
        ] {
            let mut issues = Vec::new();
            docker(text, &mut issues);
            assert!(issues.is_empty());
        }
        let deep = format!("{}0{}", "[".repeat(10000), "]".repeat(10000));
        assert!(!bounded_json(&deep));
        docker(&deep, &mut Vec::new());
        assert!(bounded_json(r#"{"quoted":"[\"{}"}"#));
    }

    #[test]
    fn ssh_fixes_name_the_key_and_quote_shell_characters() {
        for permissions in [false, true] {
            let fix = key_fix("~/.ssh/id_ed25519", permissions);
            assert!(fix.contains(if cfg!(windows) {
                "\"$HOME\\.ssh\\id_ed25519\""
            } else {
                "~/.ssh/id_ed25519"
            }));
            assert!(!fix.contains("<key-file>"));
            assert!(fix.contains(if permissions {
                "chmod 600 "
            } else {
                "ssh-keygen -p -f "
            }));
            let spaced = key_fix("~/.ssh/custom name", permissions);
            let expected = if cfg!(windows) {
                "\"$HOME\\.ssh\\custom name\""
            } else {
                "\"$HOME/.ssh/custom name\""
            };
            assert!(spaced.contains(expected));
            let hostile = key_fix("~/.ssh/$(echo test)`name\"", permissions);
            assert!(hostile.contains(if cfg!(windows) { "`$(" } else { "\\$(" }));
            assert!(hostile.contains(if cfg!(windows) { "`\"" } else { "\\\"" }));
            let controls = key_fix("~/.ssh/key\nnext", permissions);
            assert!(!controls.contains('\n'));
            assert!(!controls.contains(" -f "));
        }
    }

    #[test]
    fn pypirc_passwords_require_literal_ini_fields() {
        let secret = ["canary", "-pypirc-246"].concat();
        let text = format!(
            "\u{feff}[hidden-profile]\r\nusername = hidden-user\r\npassword: {secret}\r\n[other]\npassword = '{secret}' # note\n"
        );
        let mut issues = Vec::new();
        pypirc(&text, &mut issues);
        assert_findings(
            &issues,
            "pypirc-plaintext-password",
            "~/.pypirc",
            Level::High,
            &[3, 5],
            &secret,
        );
        assert_private(&issues, &["hidden-profile", "hidden-user"]);
        let mut ignored = Vec::new();
        pypirc(
            "password = outside-section\n[pypi]\n# password = commented\n; password: commented\npassword =\npassword: ''\npassword = ${PASS}\npassword = \"${PASS}\"\npassword = <password>\npassword: your_password\npassword = xxxxx\npassword = \"unterminated\nother = text\n    password = continuation\n[broken\npassword = ignored",
            &mut ignored,
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn git_credentials_report_lines_without_identity_or_host() {
        let secret = ["canary", "-git-357"].concat();
        let text = format!(
            "# header\nhttps://hidden-user:{secret}@hidden-host/path\nssh://hidden-user:{secret}@hidden-host:22\n"
        );
        let mut issues = Vec::new();
        git_credentials(&text, &mut issues);
        assert_findings(
            &issues,
            "git-credentials-plaintext",
            "~/.git-credentials",
            Level::High,
            &[2, 3],
            &secret,
        );
        assert_private(&issues, &["hidden-user", "hidden-host"]);
        assert!(issues[0].fix.contains(if cfg!(windows) {
            "helper manager"
        } else if cfg!(target_os = "macos") {
            "helper osxkeychain"
        } else {
            "helper libsecret"
        }));
        let mut ignored = Vec::new();
        git_credentials(
            "# https://user:comment@host\nhttps://user:@host\nhttps://user:${PASS}@host\nhttps://user:%24%7BPASS%7D@host\nhttps://user:your_password@host\nhttps://user:xxxxx@host\nhttps://user@host\nhttps://:secret@host\nhttps://user:secret@\nhttps://host/path/user:secret@other\nhttps://user:%ZZ@host\ninvalid scheme://user:secret@host\n1https://user:secret@host",
            &mut ignored,
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn netrc_handles_multiline_values_quotes_and_macros() {
        let secret = ["canary", "-netrc-468"].concat();
        let text = format!(
            "# header\nmachine hidden-host login hidden-user\npassword\n\"{secret}\"\nmacdef init\npassword macro-canary\nmachine macro-host password macro-canary\n\ndefault login hidden-user password {secret}\n"
        );
        for path in ["~/.netrc", "~/_netrc"] {
            let mut issues = Vec::new();
            netrc(&text, path, &mut issues);
            assert_findings(
                &issues,
                "netrc-plaintext-password",
                path,
                Level::High,
                &[3, 9],
                &secret,
            );
            assert_private(
                &issues,
                &["hidden-host", "hidden-user", "macro-canary", "macro-host"],
            );
            assert!(issues[0].fix.contains(path));
        }
        let mut ignored = Vec::new();
        netrc(
            "# password comment\nmachine host login user password \"\"\npassword ${PASS}\npassword '${PASS}'\npassword <password>\npassword your_password\npassword xxxxx\nlogin password\naccount password\npassword\nmachine other login user\nmacdef init\npassword macro-secret\n\npassword",
            "~/.netrc",
            &mut ignored,
        );
        assert!(ignored.is_empty());
        let mut ignored = Vec::new();
        netrc(
            "machine host login user\npassword \"unterminated\npassword orphan\n",
            "~/.netrc",
            &mut ignored,
        );
        assert!(ignored.is_empty());
        let mut quoted = Vec::new();
        netrc(
            &format!("default password \"{secret} with space\""),
            "~/.netrc",
            &mut quoted,
        );
        assert_findings(
            &quoted,
            "netrc-plaintext-password",
            "~/.netrc",
            Level::High,
            &[1],
            &secret,
        );
    }

    #[test]
    fn cargo_tokens_require_quoted_values_and_skip_multiline_contexts() {
        let secret = ["canary", "-cargo-579"].concat();
        let text = format!(
            "[registry]\ntoken = \"{secret}\" # note\n[registries.hidden-profile]\ntoken = '{secret}'\n"
        );
        for path in ["~/.cargo/credentials.toml", "~/.cargo/credentials"] {
            let mut issues = Vec::new();
            cargo_credentials(&text, path, &mut issues);
            assert_findings(
                &issues,
                "cargo-plaintext-token",
                path,
                Level::High,
                &[2, 4],
                &secret,
            );
            assert_private(&issues, &["hidden-profile"]);
            assert!(issues[0].fix.contains(if cfg!(windows) {
                "cargo:wincred"
            } else if cfg!(target_os = "macos") {
                "cargo:macos-keychain"
            } else {
                "cargo:libsecret"
            }));
        }
        let mut ignored = Vec::new();
        cargo_credentials(
            "[registry]\n# token = \"comment\"\ntoken = \"\"\ntoken = '${TOKEN}'\ntoken = \"your_token\"\ntoken = \"xxxxx\"\ntoken = \"<token>\"\ntoken = bare\ntoken = \"unterminated\nother = '''\ntoken = \"inside-literal\"\n'''\nother = \"\"\"\ntoken = \"inside-basic\"\n\"\"\"\n[[invalid]]\ntoken = \"ignored\"",
            "~/.cargo/credentials",
            &mut ignored,
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn kubeconfig_checks_only_direct_user_credentials_once() {
        let secret = ["canary", "-kube-680"].concat();
        for key in ["token", "client-key-data", "password"] {
            for indent in ["", "  "] {
                let text = format!(
                    "users:\n{indent}- name: hidden-profile\n{indent}  user:\n{indent}    {key}: '{secret}'\n{indent}    token: {secret}\n"
                );
                let mut issues = Vec::new();
                kubeconfig(&text, &mut issues);
                assert_findings(
                    &issues,
                    "kubeconfig-embedded-credentials",
                    "~/.kube/config",
                    Level::Medium,
                    &[4],
                    &secret,
                );
                assert_private(&issues, &["hidden-profile"]);
            }
        }
        let mut block = Vec::new();
        kubeconfig(
            &format!("users:\n- user:\n    client-key-data: |-\n      {secret}\n"),
            &mut block,
        );
        assert_findings(
            &block,
            "kubeconfig-embedded-credentials",
            "~/.kube/config",
            Level::Medium,
            &[3],
            &secret,
        );
        let mut ignored = Vec::new();
        kubeconfig(
            "clusters:\n- user:\n    token: outside-users\nusers:\n- name: profile\n  user:\n    # token: commented\n    token:\n    token: ''\n    token: ${TOKEN}\n    password: your_password\n    password: <password>\n    client-key-data: xxxxx\n    token: ~\n    token: null\n    token: *alias\n    exec:\n      token: not-a-credential\n      env:\n      - name: TOKEN\n        value: not-a-credential\n    auth-provider:\n      config:\n        password: not-a-credential\n    extensions:\n      token: not-a-credential\n- name: |\n    user:\n      token: part-of-name\ncontexts:\n- user:\n    password: outside-users",
            &mut ignored,
        );
        assert!(ignored.is_empty());
        // A plugin in the previous entry must not hide a subsequent static key.
        for value in ["~ # YAML null", "", "''", "${TOKEN}", "<token>"] {
            let mut ignored = Vec::new();
            kubeconfig(
                &format!("users:\n- user:\n    token: {value}\n"),
                &mut ignored,
            );
            assert!(ignored.is_empty());
        }
        let mut ignored = Vec::new();
        kubeconfig("users:\n- user:\n    token:not-a-mapping", &mut ignored);
        assert!(ignored.is_empty());
        let mut second = Vec::new();
        kubeconfig(
            &format!(
                "users:\n- user:\n    exec:\n      command: plugin\n- user:\n    password: {secret}"
            ),
            &mut second,
        );
        assert_findings(
            &second,
            "kubeconfig-embedded-credentials",
            "~/.kube/config",
            Level::Medium,
            &[6],
            &secret,
        );
    }

    #[test]
    fn aws_reports_first_literal_secret_per_profile_without_profile_name() {
        let secret = ["canary", "-aws-791"].concat();
        let text = format!(
            "[hidden-profile]\naws_access_key_id = hidden-access-id\naws_secret_access_key = {secret}\naws_secret_access_key = {secret}\n[hidden-second]\naws_secret_access_key = '{secret}'\n[hidden-profile]\naws_secret_access_key = {secret}\n"
        );
        let mut issues = Vec::new();
        aws_credentials(&text, &mut issues);
        assert_findings(
            &issues,
            "aws-plaintext-keys",
            "~/.aws/credentials",
            Level::High,
            &[3, 6],
            &secret,
        );
        assert_private(
            &issues,
            &["hidden-profile", "hidden-second", "hidden-access-id"],
        );
        let mut ignored = Vec::new();
        aws_credentials(
            "aws_secret_access_key = outside-section\n[default]\n# aws_secret_access_key = commented\n; aws_secret_access_key = commented\naws_secret_access_key =\naws_secret_access_key = ''\naws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}\naws_secret_access_key = your_key\naws_secret_access_key = <secret>\naws_secret_access_key = xxxxx\naws_access_key_id = unrelated\naws_session_token = unrelated\nother = text\n    aws_secret_access_key = continuation",
            &mut ignored,
        );
        assert!(ignored.is_empty());
    }

    fn assert_findings(
        issues: &[Issue],
        id: &str,
        path: &str,
        level: Level,
        lines: &[usize],
        secret: &str,
    ) {
        assert_eq!(issues.iter().map(|i| i.line).collect::<Vec<_>>(), lines);
        for i in issues {
            assert_eq!(i.id, id);
            assert_eq!(i.path, path);
            assert_eq!(i.level, level);
        }
        assert_private(issues, &[secret, &base64(secret.as_bytes())]);
    }

    fn assert_private(issues: &[Issue], secrets: &[&str]) {
        let output = format!("{issues:?}");
        for secret in secrets {
            assert!(!output.contains(secret), "credential leaked into Issue");
        }
    }

    struct Home(PathBuf);
    impl Home {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let home = std::env::temp_dir().join(format!(
                "jetscan-hygiene-test-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&home).unwrap();
            Self(home)
        }
        fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scan_is_read_only_sorted_relative_and_deterministic() {
        let home = Home::new();
        let secret = ["canary", "-filesystem-789"].concat();
        home.write(".npmrc", format!("_authToken={secret}\n"));
        home.write(
            ".docker/config.json",
            format!(
                "{{\"auths\":{{\"host\":{{\"auth\":\"{}\"}}}}}}",
                base64(format!("person:{secret}").as_bytes())
            ),
        );
        home.write(".ssh/custom name", ssh_fixture(false));
        home.write(".ssh/encrypted", ssh_fixture(true));
        home.write(
            ".ssh/id.pub",
            format!("{} {}", "ssh-ed25519", base64(&[42; 32])),
        );
        home.write(".ssh/nested/ignored", ssh_fixture(false));
        home.write(".ssh/binary", [255, 0, 254]);
        home.write(
            ".pypirc",
            format!("[hidden-profile]\npassword = {secret}\n"),
        );
        home.write(
            ".git-credentials",
            format!("https://hidden-user:{secret}@hidden-host\n"),
        );
        for path in [".netrc", "_netrc"] {
            home.write(
                path,
                format!("machine hidden-host login hidden-user\npassword {secret}\n"),
            );
        }
        for path in [".cargo/credentials", ".cargo/credentials.toml"] {
            home.write(path, format!("[registry]\ntoken = \"{secret}\"\n"));
        }
        home.write(
            ".kube/config",
            format!("users:\n- name: hidden-profile\n  user:\n    token: {secret}\n"),
        );
        home.write(
            ".aws/credentials",
            format!("[hidden-profile]\naws_secret_access_key = {secret}\n"),
        );
        let paths = [
            ".npmrc",
            ".docker/config.json",
            ".ssh/custom name",
            ".ssh/encrypted",
            ".pypirc",
            ".git-credentials",
            ".netrc",
            "_netrc",
            ".cargo/credentials",
            ".cargo/credentials.toml",
            ".kube/config",
            ".aws/credentials",
        ];
        let before: Vec<_> = paths
            .iter()
            .map(|p| fs::read(home.0.join(p)).unwrap())
            .collect();
        let issues = super::super::check(&home.0);
        assert_eq!(issues, run(&home.0));
        assert_eq!(issues, super::super::check(&home.0));
        assert_eq!(
            issues
                .iter()
                .map(|i| (i.path.as_str(), i.id))
                .collect::<Vec<_>>(),
            vec![
                ("~/.aws/credentials", "aws-plaintext-keys"),
                ("~/.cargo/credentials", "cargo-plaintext-token"),
                ("~/.cargo/credentials.toml", "cargo-plaintext-token"),
                ("~/.docker/config.json", "docker-plaintext-auth"),
                ("~/.git-credentials", "git-credentials-plaintext"),
                ("~/.kube/config", "kubeconfig-embedded-credentials"),
                ("~/.netrc", "netrc-plaintext-password"),
                ("~/.npmrc", "npmrc-plaintext-token"),
                ("~/.pypirc", "pypirc-plaintext-password"),
                ("~/.ssh/custom name", "ssh-key-no-passphrase"),
                ("~/_netrc", "netrc-plaintext-password"),
            ]
        );
        assert_private(
            &issues,
            &[
                &secret,
                &base64(secret.as_bytes()),
                "synthetic-comment-canary",
                "hidden-profile",
                "hidden-user",
                "hidden-host",
                &home.0.display().to_string(),
            ],
        );
        assert_eq!(
            issues.iter().map(|i| i.line).collect::<Vec<_>>(),
            vec![2, 2, 2, 0, 1, 4, 2, 1, 2, 0, 2]
        );
        assert!(
            issues
                .iter()
                .find(|i| i.id == "ssh-key-no-passphrase")
                .unwrap()
                .fix
                .contains("custom name\"")
        );
        for (path, bytes) in paths.iter().zip(before) {
            assert_eq!(fs::read(home.0.join(path)).unwrap(), bytes);
        }
    }

    #[test]
    fn missing_empty_oversized_and_invalid_files_are_skipped() {
        let home = Home::new();
        assert!(run(&home.0.join("missing")).is_empty());
        assert!(run(&home.0).is_empty());
        home.write(".npmrc", [255, 254]);
        home.write(".docker/config.json", "not json");
        home.write(".ssh/large", vec![b'a'; MAX_BYTES as usize + 1]);
        home.write(".ssh/empty", "");
        assert!(run(&home.0).is_empty());
        assert!(read_file(&home.0.join(".ssh/large")).is_none());
        assert!(run(&home.0.join(".npmrc")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn unix_permissions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let home = Home::new();
        home.write(".ssh/clear", ssh_fixture(false));
        home.write(".ssh/encrypted", ssh_fixture(true));
        for key in ["clear", "encrypted"] {
            fs::set_permissions(
                home.0.join(".ssh").join(key),
                fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }
        let issues = run(&home.0);
        assert_eq!(issues.len(), 3);
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.id == "ssh-key-permissions" && i.level == Level::Medium)
                .count(),
            2
        );
        symlink(home.0.join(".ssh/clear"), home.0.join(".npmrc")).unwrap();
        symlink(home.0.join(".ssh/clear"), home.0.join(".ssh/link")).unwrap();
        assert_eq!(run(&home.0), issues);
        let other = Home::new();
        symlink(home.0.join(".ssh"), other.0.join(".ssh")).unwrap();
        symlink(&home.0, other.0.join("home")).unwrap();
        assert!(run(&other.0).is_empty());
        assert!(run(&other.0.join("home")).is_empty());
    }
}
