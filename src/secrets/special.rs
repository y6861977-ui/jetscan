//! Спецфайлы с кредами: `.env*`, `.npmrc`, `.pypirc`, `.git-credentials`,
//! `.docker/config.json`, `.dockercfg`, хранилища паролей (T9.1), профили шелла
//! (`.bashrc`, `.zshrc`, `.envrc`, …), `~/.aws/credentials`, `.s3cfg`, Rails `secrets.yml`,
//! конфиги `hub`/`gh` (T9.4).
//!
//! Два режима фильтрации. Файл-хранилище (единственное назначение — хранить учётные данные:
//! `.netrc`, `.aws/credentials`, `hub`, …) — любое непустое буквальное значение = находка.
//! Файл настроек, где секреты лишь бывают (`.env`, профиль шелла, `secrets.yml`), — фильтры
//! имён ключей и заглушек, как у `.env`.
//!
//! Движок прогоняет общие правила (`rules::all`) по ВСЕМ файлам, включая эти,
//! и потом дедупит по (место, строка, отпечаток). Поэтому здесь не нужно
//! повторять провайдерские правила — только то, что видно лишь из структуры файла.

use super::{Confidence, Hit, RuleInfo};
use crate::json::{self, Json};
use std::collections::HashMap;
use std::path::Path;

const ENV_RULE: RuleInfo = RuleInfo {
    id: "env-secret",
    name: "Secret in environment file",
    confidence: Confidence::Medium,
};
const NPM_RULE: RuleInfo = RuleInfo {
    id: "npm-auth-token",
    name: "npm authentication token",
    confidence: Confidence::High,
};
const PYPI_RULE: RuleInfo = RuleInfo {
    id: "pypi-password",
    name: "PyPI password",
    confidence: Confidence::High,
};
const GIT_CREDENTIALS_RULE: RuleInfo = RuleInfo {
    id: "git-credentials",
    name: "Git credential password",
    confidence: Confidence::High,
};
const DOCKER_AUTH_RULE: RuleInfo = RuleInfo {
    id: "docker-auth",
    name: "Docker registry authentication",
    confidence: Confidence::High,
};
const STORE_PASSWORD_RULE: RuleInfo = RuleInfo {
    id: "credential-store-password",
    name: "Password in credential store",
    confidence: Confidence::High,
};
const SHELL_RULE: RuleInfo = RuleInfo {
    id: "shell-secret",
    name: "Secret in shell profile",
    confidence: Confidence::Medium,
};
// Same id and name as the line rule in `rules.rs`: one secret, one kind of finding.
const AWS_SECRET_RULE: RuleInfo = RuleInfo {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    confidence: Confidence::High,
};
const AWS_SESSION_RULE: RuleInfo = RuleInfo {
    id: "aws-session-token",
    name: "AWS Session Token",
    confidence: Confidence::High,
};
const RAILS_RULE: RuleInfo = RuleInfo {
    id: "rails-secret",
    name: "Secret in Rails secrets.yml",
    confidence: Confidence::High,
};
const HUB_RULE: RuleInfo = RuleInfo {
    id: "github-cli-oauth-token",
    name: "GitHub OAuth token in hub/gh config",
    confidence: Confidence::High,
};

/// Shell startup files (and direnv's `.envrc`): `export KEY=value` lives here. Dotfile
/// repositories keep them without the dot (`bashrc`), and `~/.zshrc.local` is the usual
/// place for "private" settings.
fn is_shell_profile(lower: &str) -> bool {
    let name = lower.strip_suffix(".local").unwrap_or(lower);
    let name = name.strip_prefix('.').unwrap_or(name);
    matches!(
        name,
        "bashrc"
            | "bash_profile"
            | "bash_login"
            | "bash_aliases"
            | "zshrc"
            | "zshenv"
            | "zprofile"
            | "zlogin"
            | "kshrc"
            | "mkshrc"
    ) || matches!(lower, ".profile" | ".envrc")
}

fn parent_is(path: &Path, name: &str) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|parent| parent.to_string_lossy().eq_ignore_ascii_case(name))
}

/// Это спецфайл? Решается по имени/пути. `.env.example`, `.env.sample`,
/// `.env.template` — НЕ спецфайлы.
pub fn is_special(path: &Path) -> bool {
    let Some(name) = path.file_name().map(|name| name.to_string_lossy()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower == ".env" {
        return true;
    }
    if lower.starts_with(".env.") {
        return !matches!(
            lower.as_str(),
            ".env.example" | ".env.sample" | ".env.template"
        );
    }
    if matches!(
        lower.as_str(),
        ".npmrc"
            | ".pypirc"
            | ".git-credentials"
            | ".netrc"
            | ".pgpass"
            | ".esmtprc"
            | "sftp-config.json"
            | ".ftpconfig"
            | ".remote-sync.json"
            | "deployment-config.json"
            | ".dockercfg"
            | ".s3cfg"
            | "secrets.yml"
            | "hub"
    ) {
        return true;
    }
    is_shell_profile(&lower)
        || (lower == "config.json" && parent_is(path, ".docker"))
        || (lower == "sftp.json" && parent_is(path, ".vscode"))
        || (lower == "webservers.xml" && parent_is(path, ".idea"))
        || (lower.ends_with(".xml") && parent_is(path, "filezilla"))
        || (matches!(lower.as_str(), "credentials" | "config") && parent_is(path, ".aws"))
        || (lower == "hosts.yml" && parent_is(path, "gh"))
}

/// Находки в спецфайле. `text` — содержимое целиком. `line`/`col` — как в `Hit`.
pub fn scan(path: &Path, text: &str) -> Vec<Hit> {
    if !is_special(path) {
        return Vec::new();
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name == ".env" || name.starts_with(".env.") {
        // Шаблон окружения (`.env.production.example`): сканируем — туда копируют и настоящие
        // ключи, — но заглушки на любом языке (`ЗАМЕНИТЬ_ПАРОЛЬ`) не считаем секретом.
        let template = [".example", ".sample", ".template", ".dist"]
            .iter()
            .any(|s| name.ends_with(s));
        scan_env(text, template)
    } else if name == ".npmrc" {
        scan_assignments(text, NPM_RULE, |key| {
            key.rsplit(':').next().is_some_and(|key| {
                let key = key.trim();
                ["_authToken", "_auth", "_password"]
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
            })
        })
    } else if name == ".pypirc" {
        scan_assignments(text, PYPI_RULE, |key| {
            key.trim().eq_ignore_ascii_case("password")
        })
    } else if name == ".git-credentials" {
        scan_git_credentials(text)
    } else if name == ".netrc" {
        scan_netrc(text)
    } else if name == ".pgpass" {
        scan_pgpass(text)
    } else if name == ".esmtprc" {
        scan_esmtprc(text)
    } else if is_shell_profile(&name) {
        scan_shell(text)
    } else if name == ".dockercfg" {
        scan_dockercfg(text)
    } else if name == ".s3cfg" {
        scan_ini_store(
            text,
            &[
                ("secret_key", AWS_SECRET_RULE),
                ("access_token", AWS_SESSION_RULE),
                ("gpg_passphrase", STORE_PASSWORD_RULE),
            ],
        )
    } else if parent_is(path, ".aws") {
        scan_ini_store(
            text,
            &[
                ("aws_secret_access_key", AWS_SECRET_RULE),
                ("aws_session_token", AWS_SESSION_RULE),
                ("aws_security_token", AWS_SESSION_RULE),
            ],
        )
    } else if name == "secrets.yml" {
        scan_rails_secrets(text)
    } else if name == "hub" || name == "hosts.yml" {
        scan_hub_config(text)
    } else if name.ends_with(".xml") {
        scan_password_xml(text)
    } else if name != "config.json" {
        scan_password_json(text)
    } else {
        scan_docker_config(text)
    }
}

fn scan_env(text: &str, template: bool) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, start, end)) = assignment(line) else {
            continue;
        };
        let key = key.trim();
        let key = key
            .strip_prefix("export ")
            .or_else(|| key.strip_prefix("EXPORT "))
            .unwrap_or(key)
            .trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            continue;
        }
        if !env_key_is_sensitive(key) || env_value_is_not_secret(&line[start..end], template) {
            continue;
        }
        push_hit(&mut hits, ENV_RULE, line_index + 1, line, start, end);
    }
    hits
}

/// Ключ `.env` похож на секрет, если одно из его СЛОВ (через `_`) — секретное.
/// Подстрока не годится: `MONKEY`, `BYPASS_CACHE`, `PASSENGER_COUNT` — не секреты.
/// `PUBLIC`/`PUBLISHABLE` в ключе — значение специально публичное (`NEXT_PUBLIC_*_KEY`).
fn env_key_is_sensitive(key: &str) -> bool {
    const SECRET_WORDS: &[&str] = &[
        "KEY",
        "APIKEY",
        "SECRETKEY",
        "ACCESSKEY",
        "PRIVATEKEY",
        "AUTHKEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PWD",
        "CREDENTIALS",
        "PRIVATE",
    ];
    const SECRET_SUFFIXES: &[&str] = &["APIKEY", "SECRET", "TOKEN", "PASSWORD"];
    let upper = key.to_ascii_uppercase();
    let words: Vec<&str> = upper.split('_').filter(|w| !w.is_empty()).collect();
    if words
        .iter()
        .any(|w| matches!(*w, "PUBLIC" | "PUBLISHABLE" | "PUB"))
    {
        return false;
    }
    words
        .iter()
        .any(|w| SECRET_WORDS.contains(w) || SECRET_SUFFIXES.iter().any(|s| w.ends_with(s)))
}

/// Значения, которые точно не секрет: флаги, числа, длительности (`TOKEN_TTL=3600`).
fn env_value_is_not_secret(value: &str, template: bool) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    if is_env_placeholder(value.trim(), &lower, template) {
        return true;
    }
    // Только байтами: срез `&str` по `len() - 1` паникует на не-ASCII (`ПАРОЛЬ=секретД`).
    let b = lower.as_bytes();
    matches!(
        lower.as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "none" | "nil" | "undefined"
    ) || b.iter().all(|c| c.is_ascii_digit() || *c == b'.')
        || (b.len() > 1
            && b[..b.len() - 1].iter().all(u8::is_ascii_digit)
            && matches!(b[b.len() - 1], b's' | b'm' | b'h' | b'd'))
}

/// Заглушка вместо значения: `your_api_key`, `replace-me`, `<token>`, `ВСТАВЬТЕ_КЛЮЧ`.
/// В шаблонах (`*.example`) ещё и любое значение с не-ASCII буквами — настоящие ключи
/// и пароли из генераторов ASCII, а текст на русском — инструкция для человека.
fn is_env_placeholder(value: &str, lower: &str, template: bool) -> bool {
    const STARTS: &[&str] = &[
        "your", "replace", "change", "insert", "put_", "put-", "enter", "example", "todo", "fixme",
        "<", "...", "xxx",
    ];
    const STARTS_RU: &[&str] = &["вставь", "замени", "укажи", "введи", "заполни", "ваш"];
    let lower_ru = value.to_lowercase();
    STARTS.iter().any(|s| lower.starts_with(s))
        || STARTS_RU.iter().any(|s| lower_ru.starts_with(s))
        || (template && value.chars().any(|c| c.is_alphabetic() && !c.is_ascii()))
}

fn scan_assignments(text: &str, rule: RuleInfo, key_matches: impl Fn(&str) -> bool) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let Some((key, start, end)) = assignment(line) else {
            continue;
        };
        if key_matches(key) {
            push_hit(&mut hits, rule, line_index + 1, line, start, end);
        }
    }
    hits
}

fn scan_git_credentials(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        if let Some((start, end)) = url_password(line)
            && stored_password(&line[start..end])
        {
            hits.push(Hit {
                rule: GIT_CREDENTIALS_RULE,
                line: line_index + 1,
                col: line[..start].chars().count() + 1,
                secret: line[start..end].to_string(),
            });
        }
    }
    hits
}

// Credential stores deliberately bypass the general placeholder/entropy filters.
fn stored_password(value: &str) -> bool {
    !value.is_empty()
        && !(value.starts_with("${") && value.ends_with('}'))
        && !(value.starts_with('$')
            && value.len() > 1
            && value[1..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

fn store_hit(hits: &mut Vec<Hit>, text: &str, start: usize, secret: String) {
    store_hit_as(hits, STORE_PASSWORD_RULE, text, start, secret);
}

fn store_hit_as(hits: &mut Vec<Hit>, rule: RuleInfo, text: &str, start: usize, secret: String) {
    if stored_password(&secret) {
        let (line, col) = line_and_column(text, start);
        hits.push(Hit {
            rule,
            line,
            col,
            secret,
        });
    }
}

/// `export KEY=value` / `KEY=value` in a shell profile. Not a credential store — the
/// file is mostly settings — so the `.env` key and placeholder filters apply. Only literal
/// values count: anything the shell would expand (`$VAR`, `$(cmd)`, backticks) is not the
/// secret itself.
fn scan_shell(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let Some((key, start, end)) = shell_assignment(line) else {
            continue;
        };
        let value = &line[start..end];
        if !env_key_is_sensitive(key)
            || env_value_is_not_secret(value, false)
            || shell_value_is_not_secret(key, value)
        {
            continue;
        }
        push_hit(&mut hits, SHELL_RULE, line_index + 1, line, start, end);
    }
    hits
}

/// `[export ]NAME=value` at the start of a line → (NAME, byte range of the literal value).
/// `None` for anything the shell would expand or that we cannot read on one line.
fn shell_assignment(line: &str) -> Option<(&str, usize, usize)> {
    let bytes = line.as_bytes();
    let mut at = line.len() - line.trim_start().len();
    if bytes.get(at) == Some(&b'#') {
        return None;
    }
    if line[at..].starts_with("export")
        && bytes
            .get(at + "export".len())
            .is_some_and(|b| *b == b' ' || *b == b'\t')
    {
        at += "export".len();
        while bytes.get(at).is_some_and(|b| *b == b' ' || *b == b'\t') {
            at += 1;
        }
    }
    let key_start = at;
    if !bytes
        .get(at)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    while bytes
        .get(at)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        at += 1;
    }
    let key = &line[key_start..at];
    // No spaces around `=` in shell; `[ "$x" = y ]` and `X == y` are not assignments.
    if bytes.get(at) != Some(&b'=') || bytes.get(at + 1) == Some(&b'=') {
        return None;
    }
    let start = at + 1;
    let (start, end) = match bytes.get(start) {
        Some(b'\'') => {
            let close = line[start + 1..].find('\'')? + start + 1;
            (start + 1, close)
        }
        Some(b'"') => {
            let close = line[start + 1..].find('"')? + start + 1;
            if line[start + 1..close].contains(['$', '`', '\\']) {
                return None;
            }
            (start + 1, close)
        }
        _ => {
            let end = line[start..]
                .find(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | ')' | '<' | '>'))
                .map_or(line.len(), |n| start + n);
            if line[start..end].contains(['$', '`', '\\', '\'', '"', '(']) {
                return None;
            }
            (start, end)
        }
    };
    (start < end).then_some((key, start, end))
}

/// What `.env` filters do not cover but shell profiles are full of: paths (`KEY_FILE=~/.ssh/k`,
/// `PASSWORD_STORE_DIR=…`) and GPG key ids (`GPG_KEY=0x…` — public identifiers, not secrets).
fn shell_value_is_not_secret(key: &str, value: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    let words: Vec<&str> = upper.split('_').filter(|w| !w.is_empty()).collect();
    let last = words.last().copied().unwrap_or("");
    let hex = value.strip_prefix("0x").unwrap_or(value);
    value.starts_with(['/', '~'])
        || value.starts_with("./")
        || value.starts_with("../")
        || matches!(
            last,
            "DIR" | "PATH" | "FILE" | "HOME" | "SOCK" | "SOCKET" | "CMD" | "COMMAND" | "PROGRAM"
        )
        || (words
            .iter()
            .any(|w| matches!(*w, "GPG" | "PGP" | "GNUPG" | "GPGKEY"))
            && !hex.is_empty()
            && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// INI-style credential files (`~/.aws/credentials`, `~/.s3cfg`): `key = value` under
/// `[sections]`. Credential stores — any non-empty literal value of a listed key is a
/// finding, however weak (same rule as T9.1). Trailing ` # comment` is dropped.
fn scan_ini_store(text: &str, keys: &[(&str, RuleInfo)]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut offset = 0;
    for raw in text.split_inclusive('\n') {
        let line_start = offset;
        offset += raw.len();
        let line = raw.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';', '[']) {
            continue;
        }
        let Some(equals) = line.find('=') else {
            continue;
        };
        let key = line[..equals].trim();
        let Some(rule) = keys
            .iter()
            .find(|(name, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, rule)| *rule)
        else {
            continue;
        };
        let mut end = [" #", "\t#", " ;", "\t;"]
            .iter()
            .filter_map(|marker| line[equals + 1..].find(marker))
            .min()
            .map_or(line.len(), |n| equals + 1 + n);
        let (mut start, trimmed_end) = trim_ascii_bounds(line, equals + 1, end);
        end = trimmed_end;
        let bytes = line.as_bytes();
        if end - start >= 2
            && matches!(bytes[start], b'\'' | b'"')
            && bytes[end - 1] == bytes[start]
        {
            start += 1;
            end -= 1;
        }
        store_hit_as(
            &mut hits,
            rule,
            text,
            line_start + start,
            line[start..end].to_string(),
        );
    }
    hits
}

/// One line of YAML `key: value` → (key, byte range of the scalar value). Plain and
/// quoted scalars only; block scalars, anchors, aliases, flow collections and tags are
/// skipped (`None`), as is a key with no value (the start of a nested mapping).
fn yaml_scalar(line: &str) -> Option<(&str, usize, usize)> {
    let mut at = line.len() - line.trim_start().len();
    if line[at..].starts_with("- ") {
        at += 2;
        at += line[at..].len() - line[at..].trim_start().len();
    }
    let rest = &line[at..];
    if rest.starts_with('#') {
        return None;
    }
    let colon = rest.find(':')?;
    let key = rest[..colon].trim_matches(['\'', '"']);
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return None;
    }
    let after = at + colon + 1;
    if line
        .as_bytes()
        .get(after)
        .is_some_and(|b| !b.is_ascii_whitespace())
    {
        return None;
    }
    let (start, end) = trim_ascii_bounds(line, after, line.len());
    let bytes = line.as_bytes();
    match bytes.get(start)? {
        q @ (b'\'' | b'"') => {
            let close = line[start + 1..].find(char::from(*q))? + start + 1;
            Some((key, start + 1, close))
        }
        b'|' | b'>' | b'&' | b'*' | b'!' | b'{' | b'[' | b'#' => None,
        _ => {
            let end = line[start..end]
                .find(" #")
                .map_or(end, |n| trim_ascii_bounds(line, start, start + n).1);
            Some((key, start, end))
        }
    }
}

/// Rails `config/secrets.yml`: `secret_key_base` and any other secret-named key with a
/// literal value. ERB (`<%= ENV["SECRET_KEY_BASE"] %>`) is a reference, not a secret.
/// Rails' generator writes literal development/test keys here — they are reported too:
/// they sign cookies of whatever runs with that environment.
fn scan_rails_secrets(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let Some((key, start, end)) = yaml_scalar(line) else {
            continue;
        };
        let value = &line[start..end];
        if start == end
            || value.contains("<%")
            || matches!(value, "~" | "null" | "Null" | "NULL")
            || !env_key_is_sensitive(key)
            || env_value_is_not_secret(value, false)
        {
            continue;
        }
        push_hit(&mut hits, RAILS_RULE, line_index + 1, line, start, end);
    }
    hits
}

/// `~/.config/hub` and `~/.config/gh/hosts.yml`: `oauth_token: …` is a GitHub token,
/// whatever its format (hub stored 40-hex tokens that no prefix rule can see).
/// A credential store: any literal value is a finding.
fn scan_hub_config(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut offset = 0;
    for raw in text.split_inclusive('\n') {
        let line_start = offset;
        offset += raw.len();
        let line = raw.trim_end_matches(['\r', '\n']);
        if let Some((key, start, end)) = yaml_scalar(line)
            && key == "oauth_token"
        {
            store_hit_as(
                &mut hits,
                HUB_RULE,
                text,
                line_start + start,
                line[start..end].to_string(),
            );
        }
    }
    hits
}

struct StoreWord {
    value: String,
    start: usize,
    quoted: bool,
}

// Line-local tokens for netrc and esmtprc. Keep source offsets even when escapes
// change the decoded length; a '#' inside a value is part of the password.
fn store_words(line: &str) -> Option<Vec<StoreWord>> {
    let mut chars = line.char_indices().peekable();
    let mut words = Vec::new();
    while let Some((offset, first)) = chars.next() {
        if first.is_whitespace() || first == '\u{feff}' {
            continue;
        }
        if first == '#' {
            break;
        }
        let quoted = matches!(first, '\'' | '"');
        let start = offset + usize::from(quoted);
        let mut value = String::new();
        let mut closed = !quoted;
        if !quoted {
            value.push(first);
        }
        while let Some(&(_, c)) = chars.peek() {
            if !quoted && c.is_whitespace() {
                break;
            }
            chars.next();
            if quoted && c == first {
                closed = true;
                break;
            }
            if c == '\\' {
                value.push(match chars.next()?.1 {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    c => c,
                });
            } else {
                value.push(c);
            }
        }
        if !closed
            || (quoted
                && chars
                    .peek()
                    .is_some_and(|(_, c)| !c.is_whitespace() && *c != '#'))
        {
            return None;
        }
        words.push(StoreWord {
            value,
            start,
            quoted,
        });
    }
    Some(words)
}

fn scan_netrc(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let (mut active, mut in_macro, mut pending) = (false, false, None);
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        if in_macro {
            if line.trim().is_empty() {
                in_macro = false;
            }
            continue;
        }
        let Some(words) = store_words(line) else {
            pending = None;
            active = false;
            continue;
        };
        for word in words {
            if let Some(key) = pending.take() {
                // A missing value must not consume the next record. The word
                // "password" itself IS a valid weak password in this store.
                if key != "password"
                    || word.quoted
                    || !matches!(
                        word.value.as_str(),
                        "machine" | "default" | "login" | "account" | "macdef"
                    )
                {
                    if key == "machine" {
                        active = !word.value.is_empty();
                    }
                    if key == "password" && active {
                        store_hit(&mut hits, text, line_start + word.start, word.value);
                    }
                    continue;
                }
            }
            if word.quoted {
                continue;
            }
            match word.value.as_str() {
                "machine" => {
                    active = false;
                    pending = Some("machine");
                }
                "default" => active = true,
                "login" => pending = Some("login"),
                "account" => pending = Some("account"),
                "password" => pending = Some("password"),
                "macdef" => {
                    in_macro = true;
                    break;
                }
                _ => {}
            }
        }
    }
    hits
}

fn scan_esmtprc(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let leading = line.len() - line.trim_start().len();
        let rest = &line[leading..];
        let key_end = rest
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(rest.len());
        if rest[..key_end].eq_ignore_ascii_case("password") {
            let tail = rest[key_end..].trim_start();
            let tail = tail.strip_prefix('=').unwrap_or(tail).trim_start();
            let start = line.len() - tail.len();
            if let Some(words) = store_words(tail)
                && let [word] = words.as_slice()
            {
                store_hit(
                    &mut hits,
                    text,
                    offset + start + word.start,
                    word.value.clone(),
                );
            }
        }
        offset += line.len();
    }
    hits
}

fn scan_pgpass(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim_start().starts_with('#') {
            continue;
        }
        let (mut fields, mut escaped, mut password_start) = (0, false, 0);
        let mut password = String::new();
        for (i, c) in line.char_indices() {
            if escaped {
                if fields == 4 {
                    password.push(c);
                }
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == ':' && fields < 4 {
                fields += 1;
                password_start = i + 1;
            } else if fields == 4 {
                password.push(c);
            }
        }
        if escaped && fields == 4 {
            password.push('\\');
        }
        if fields == 4 {
            store_hit(&mut hits, text, start + password_start, password);
        }
    }
    hits
}

fn password_key(key: &str) -> bool {
    [
        "password",
        "pass",
        "passwd",
        "passphrase",
        "privateKeyPassphrase",
    ]
    .iter()
    .any(|name| key.eq_ignore_ascii_case(name))
}

// Blank JSONC comments without moving any byte offsets. Scan strings rather
// than recursively parsing the document: nesting cannot exhaust the stack and
// added lines from git history can be inspected independently as well.
fn scan_password_json(text: &str) -> Vec<Hit> {
    let mut bytes = text.as_bytes().to_vec();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            cursor = json_quoted_end(&bytes, cursor).unwrap_or(bytes.len());
        } else if bytes[cursor..].starts_with(b"//") || bytes[cursor..].starts_with(b"/*") {
            let block = bytes[cursor + 1] == b'*';
            let end = if block {
                bytes[cursor + 2..]
                    .windows(2)
                    .position(|w| w == b"*/")
                    .map_or(bytes.len(), |n| cursor + 2 + n + 2)
            } else {
                bytes[cursor..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |n| cursor + n)
            };
            for b in &mut bytes[cursor..end] {
                if !matches!(*b, b'\r' | b'\n') {
                    *b = b' ';
                }
            }
            cursor = end;
        } else {
            cursor += 1;
        }
    }
    // Replacing whole comments with ASCII preserves UTF-8 outside comments.
    let clean = String::from_utf8(bytes).expect("comment stripping preserves UTF-8");
    let tokens = json_string_tokens(&clean);
    let mut hits = Vec::new();
    for pair in tokens.windows(2) {
        let (key, value) = (&pair[0], &pair[1]);
        if password_key(&key.decoded) && clean[key.end..value.quote_start].trim() == ":" {
            store_hit(&mut hits, text, value.content_start, value.decoded.clone());
        }
    }
    hits
}

// Decode only built-in/numeric XML entities. Never resolve DTDs or external
// entities (these files are untrusted and scanning must remain offline).
fn xml_value(value: &str) -> String {
    let mut output = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        output.push_str(&rest[..start]);
        rest = &rest[start..];
        let Some(end) = rest.find(';') else {
            break;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|n| u32::from_str_radix(n, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|n| n.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = decoded {
            output.push(c);
        } else {
            output.push_str(&rest[..=end]);
        }
        rest = &rest[end + 1..];
    }
    output.push_str(rest);
    output
}

fn scan_password_xml(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let bytes = text.as_bytes();
    let mut cursor = 0;
    while let Some(next) = text[cursor..].find('<') {
        cursor += next;
        if text[cursor..].starts_with("<!--") || text[cursor..].starts_with("<![CDATA[") {
            let terminator = if text[cursor..].starts_with("<!--") {
                "-->"
            } else {
                "]]>"
            };
            cursor = text[cursor..]
                .find(terminator)
                .map_or(text.len(), |n| cursor + n + terminator.len());
            continue;
        }
        let start = cursor + 1;
        let mut end = start;
        let mut quote = None;
        while end < bytes.len() {
            match (quote, bytes[end]) {
                (Some(q), b) if q == b => quote = None,
                (None, b'\'' | b'"') => quote = Some(bytes[end]),
                (None, b'>') => break,
                _ => {}
            }
            end += 1;
        }
        if end == bytes.len() {
            break;
        }
        cursor = end + 1;
        let tag = &text[start..end];
        if tag.starts_with(['!', '?', '/']) {
            continue;
        }
        let name_end = tag
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(tag.len());
        let name = &tag[..name_end];
        // Attribute scanner consumes all values, so password-looking text
        // inside another attribute cannot become a new attribute.
        let mut at = start + name_end;
        while at < end {
            while at < end && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            let key_start = at;
            while at < end && !bytes[at].is_ascii_whitespace() && !matches!(bytes[at], b'=' | b'/')
            {
                at += 1;
            }
            let key = &text[key_start..at];
            while at < end && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            if bytes.get(at) != Some(&b'=') {
                break;
            }
            at += 1;
            while at < end && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            if !matches!(bytes.get(at), Some(b'\'' | b'"')) {
                break;
            }
            let q = bytes[at];
            at += 1;
            let value_start = at;
            while at < end && bytes[at] != q {
                at += 1;
            }
            if at == end {
                break;
            }
            if password_key(key) {
                store_hit(
                    &mut hits,
                    text,
                    value_start,
                    xml_value(&text[value_start..at]),
                );
            }
            at += 1;
        }
        if password_key(name) && !tag.trim_end().ends_with('/') {
            let close = format!("</{name}>");
            if let Some(length) = text[cursor..].find(&close) {
                let raw = &text[cursor..cursor + length];
                let leading = raw.len() - raw.trim_start().len();
                let value = raw.trim();
                if let Some(cdata) = value
                    .strip_prefix("<![CDATA[")
                    .and_then(|v| v.strip_suffix("]]>"))
                {
                    store_hit(&mut hits, text, cursor + leading + 9, cdata.to_string());
                } else if !value.contains('<') {
                    store_hit(&mut hits, text, cursor + leading, xml_value(value));
                }
                cursor += length + close.len();
            }
        }
    }
    hits
}

fn scan_docker_config(text: &str) -> Vec<Hit> {
    let Ok(root) = json::parse(text) else {
        return Vec::new();
    };
    let Some(auths) = root.get("auths").and_then(Json::as_object) else {
        return Vec::new();
    };
    let mut expected = HashMap::<String, usize>::new();
    for entry in auths.values() {
        let Some(auth) = entry.get("auth").and_then(Json::as_str) else {
            continue;
        };
        if !ignored_value(auth) {
            *expected.entry(auth.to_string()).or_default() += 1;
        }
    }
    if expected.is_empty() {
        return Vec::new();
    }

    let tokens = json_string_tokens(text);
    let Some(span) = root_auths_object(text, &tokens) else {
        return Vec::new();
    };
    docker_auth_hits(text, &tokens, span, expected)
}

/// Legacy `~/.dockercfg` (before `config.json`): the root object IS the `auths` map —
/// `{"https://index.docker.io/v1/": {"auth": "…", "email": "…"}}`.
fn scan_dockercfg(text: &str) -> Vec<Hit> {
    let Ok(root) = json::parse(text) else {
        return Vec::new();
    };
    let Some(registries) = root.as_object() else {
        return Vec::new();
    };
    let mut expected = HashMap::<String, usize>::new();
    for entry in registries.values() {
        if let Some(auth) = entry.get("auth").and_then(Json::as_str)
            && !ignored_value(auth)
        {
            *expected.entry(auth.to_string()).or_default() += 1;
        }
    }
    if expected.is_empty() {
        return Vec::new();
    }
    let Some(open) = text.find('{') else {
        return Vec::new();
    };
    let Some(close) = matching_object_end(text, open) else {
        return Vec::new();
    };
    let tokens = json_string_tokens(text);
    docker_auth_hits(text, &tokens, (open, close), expected)
}

/// `"auth": "…"` pairs inside `span` whose value the parser saw as a registry's auth.
fn docker_auth_hits(
    text: &str,
    tokens: &[JsonStringToken],
    (auths_start, auths_end): (usize, usize),
    mut expected: HashMap<String, usize>,
) -> Vec<Hit> {
    let mut hits = Vec::new();
    for pair in tokens.windows(2) {
        let key = &pair[0];
        let value = &pair[1];
        if key.quote_start <= auths_start
            || value.end > auths_end
            || key.decoded != "auth"
            || text[key.end..value.quote_start].trim() != ":"
        {
            continue;
        }
        let Some(remaining) = expected.get_mut(&value.decoded) else {
            continue;
        };
        if *remaining == 0 {
            continue;
        }
        *remaining -= 1;
        let (line, col) = line_and_column(text, value.content_start);
        hits.push(Hit {
            rule: DOCKER_AUTH_RULE,
            line,
            col,
            secret: value.decoded.clone(),
        });
    }
    hits
}

fn assignment(line: &str) -> Option<(&str, usize, usize)> {
    let equals = line.find('=')?;
    let key = &line[..equals];
    let (mut start, mut end) = trim_ascii_bounds(line, equals + 1, line.len());
    if start == end {
        return None;
    }
    let bytes = line.as_bytes();
    if matches!(bytes.get(start), Some(b'\'' | b'"')) && bytes.get(end - 1) == bytes.get(start) {
        start += 1;
        end -= 1;
    }
    if start == end || ignored_value(&line[start..end]) {
        return None;
    }
    Some((key, start, end))
}

fn trim_ascii_bounds(text: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

fn url_password(line: &str) -> Option<(usize, usize)> {
    let separator = line.find("://")?;
    let scheme = &line[..separator];
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let authority_start = separator + 3;
    let authority_end = line[authority_start..]
        .char_indices()
        .find(|(_, c)| c.is_whitespace() || *c == '/')
        .map(|(offset, _)| authority_start + offset)
        .unwrap_or(line.len());
    let authority = &line[authority_start..authority_end];
    let at = authority.rfind('@')?;
    if at + 1 == authority.len() {
        return None;
    }
    let userinfo = &authority[..at];
    let colon = userinfo.find(':')?;
    if colon == 0 || colon + 1 == userinfo.len() {
        return None;
    }
    let start = authority_start + colon + 1;
    let end = authority_start + at;
    Some((start, end))
}

fn ignored_value(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "changeme" | "placeholder" | "<your-key>" | "<your_key>"
    ) || (value.starts_with("${") && value.ends_with('}'))
        || (value.starts_with('$')
            && value[1..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return true;
    }
    value.len() >= 4 && value.bytes().all(|byte| matches!(byte, b'x' | b'X'))
}

fn push_hit(
    hits: &mut Vec<Hit>,
    rule: RuleInfo,
    line_number: usize,
    line: &str,
    start: usize,
    end: usize,
) {
    let secret = &line[start..end];
    if ignored_value(secret) {
        return;
    }
    hits.push(Hit {
        rule,
        line: line_number,
        col: line[..start].chars().count() + 1,
        secret: secret.to_string(),
    });
}

#[derive(Debug)]
struct JsonStringToken {
    decoded: String,
    quote_start: usize,
    content_start: usize,
    end: usize,
}

fn json_string_tokens(text: &str) -> Vec<JsonStringToken> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let quote_start = cursor;
        cursor += 1;
        let content_start = cursor;
        let mut escaped = false;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                let end = cursor + 1;
                if let Ok(Json::Str(decoded)) = json::parse(&text[quote_start..end]) {
                    tokens.push(JsonStringToken {
                        decoded,
                        quote_start,
                        content_start,
                        end,
                    });
                }
                cursor = end;
                break;
            }
            cursor += 1;
        }
    }
    tokens
}

fn root_auths_object(text: &str, tokens: &[JsonStringToken]) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    for token in tokens {
        if token.decoded != "auths" || json_object_depth(text, token.quote_start) != 1 {
            continue;
        }
        let mut cursor = token.end;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b':') {
            continue;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'{') {
            continue;
        }
        return Some((cursor, matching_object_end(text, cursor)?));
    }
    None
}

fn json_object_depth(text: &str, byte_index: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut cursor = 0;
    while cursor < byte_index {
        match bytes[cursor] {
            b'"' => cursor = json_quoted_end(bytes, cursor).unwrap_or(byte_index),
            b'{' => {
                depth += 1;
                cursor += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                cursor += 1;
            }
            _ => cursor += 1,
        }
    }
    depth
}

fn matching_object_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut cursor = start;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => cursor = json_quoted_end(bytes, cursor)?,
            b'{' => {
                depth += 1;
                cursor += 1;
            }
            b'}' => {
                depth = depth.checked_sub(1)?;
                cursor += 1;
                if depth == 0 {
                    return Some(cursor);
                }
            }
            _ => cursor += 1,
        }
    }
    None
}

fn json_quoted_end(bytes: &[u8], quote_start: usize) -> Option<usize> {
    let mut cursor = quote_start + 1;
    let mut escaped = false;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Some(cursor + 1);
        }
        cursor += 1;
    }
    None
}

fn line_and_column(text: &str, byte_index: usize) -> (usize, usize) {
    let before = &text[..byte_index];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    let col = text[line_start..byte_index].chars().count() + 1;
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn credential_store_paths_are_narrowly_scoped() {
        for path in [
            ".netrc",
            "db/.pgpass",
            ".esmtprc",
            "sftp-config.json",
            ".ftpconfig",
            ".remote-sync.json",
            "deployment-config.json",
            ".vscode/sftp.json",
            ".idea/WebServers.xml",
            "FileZilla/sitemanager.XML",
        ] {
            assert!(is_special(Path::new(path)), "{path}");
        }
        for path in [
            "netrc",
            ".netrc.example",
            "sftp.json",
            "WebServers.xml",
            "other/filezilla.xml",
            "filezilla/data.json",
            "sftp-config.json.example",
        ] {
            assert!(!is_special(Path::new(path)), "{path}");
            assert!(scan(Path::new(path), "password=ignored").is_empty());
        }
    }

    #[test]
    fn weak_passwords_are_secrets_in_every_credential_store() {
        for value in [
            ["pass", "word"].concat(),
            ["pass", "123"].concat(),
            ["change", "me"].concat(),
            "x".repeat(6),
            ["place", "holder"].concat(),
        ] {
            let cases = [
                (
                    ".netrc",
                    format!("machine example.test login user password {value}"),
                ),
                (".pgpass", format!("host:5432:db:user:{value}")),
                (
                    ".git-credentials",
                    format!("https://user:{value}@example.test"),
                ),
                (".esmtprc", format!("password \"{value}\"")),
                (
                    "filezilla/filezilla.xml",
                    format!("<Server><Pass>{value}</Pass></Server>"),
                ),
                (
                    ".idea/WebServers.xml",
                    format!("<fileTransfer password=\"{value}\"/>"),
                ),
                ("sftp-config.json", format!("{{\"password\":\"{value}\"}}")),
                (".ftpconfig", format!("{{\"pass\":\"{value}\"}}")),
                (".remote-sync.json", format!("{{\"password\":\"{value}\"}}")),
                (".vscode/sftp.json", format!("{{\"password\":\"{value}\"}}")),
                (
                    "deployment-config.json",
                    format!("{{\"password\":\"{value}\"}}"),
                ),
            ];
            for (path, text) in cases {
                let hits = scan(Path::new(path), &text);
                assert_eq!(hits.len(), 1, "{path}");
                assert_eq!(hits[0].secret, value, "{path}");
                assert_eq!(hits[0].rule.confidence, Confidence::High);
            }
        }
    }

    #[test]
    fn credential_stores_skip_empty_values_references_and_comments() {
        for value in ["", "${PASSWORD}", "$PASSWORD"] {
            for (path, text) in [
                (
                    ".netrc",
                    format!("machine host password \"{value}\"\n# password comment"),
                ),
                (
                    ".pgpass",
                    format!("host:5432:db:user:{value}\n#h:p:d:u:comment"),
                ),
                (
                    ".git-credentials",
                    format!(
                        "https://user:{value}@example.test\n# https://user:comment@example.test"
                    ),
                ),
                (
                    ".esmtprc",
                    format!("password = \"{value}\" # comment\n# password comment"),
                ),
                (
                    "sftp-config.json",
                    format!(
                        "{{// \"password\": \"comment\"\n\"password\":\"{value}\" /* \"pass\": \"comment\" */}}"
                    ),
                ),
                (
                    "filezilla/filezilla.xml",
                    format!("<!-- <Pass>comment</Pass> --><Pass>{value}</Pass>"),
                ),
                (
                    ".idea/WebServers.xml",
                    format!("<!-- <x password='comment'/> --><x password='{value}'/>"),
                ),
            ] {
                assert!(scan(Path::new(path), &text).is_empty(), "{path}: {value}");
            }
        }
    }

    #[test]
    fn netrc_tracks_records_multiline_values_macros_and_positions() {
        let value = ["weak", " пар\\\"оль"].concat();
        let text = format!(
            "machine host login password\npassword\n\"{value}\"\nmacdef init\npassword macro\n\ndefault password pass123\nmachine other password\nmachine third login password\n"
        );
        let hits = scan(Path::new(".netrc"), &text);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].secret, value.replace("\\\"", "\""));
        assert_eq!((hits[0].line, hits[0].col), (3, 2));
        assert_eq!((hits[1].line, hits[1].col), (7, 18));
        assert!(scan(Path::new(".netrc"), "machine host password \"unterminated").is_empty());
    }

    #[test]
    fn pgpass_decodes_escaped_separators_and_keeps_source_position() {
        let value = ["pa", "ss"].concat();
        let text = format!("# header\r\nho\\:st:5432:db:юзер:{value}\\:a\\\\b\r\ninvalid:record\n");
        let hits = scan(Path::new(".pgpass"), &text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].secret, format!("{value}:a\\b"));
        assert_eq!(
            (hits[0].line, hits[0].col),
            (2, "ho\\:st:5432:db:юзер:".chars().count() + 1)
        );
    }

    #[test]
    fn json_passwords_decode_escapes_skip_comments_and_handle_nested_profiles() {
        let weak = ["pass", "word"].concat();
        let text = format!(
            r#"[{{"name":"юзер", "password":"{weak}\u0021"}},
/* пароль: "password":"comment" */ {{"profiles":{{"dev":{{"passphrase":"{weak}"}}}}}},
{{"password":null,"pass":false,"promptForPass":true,"url":"https://example.test"}},
{{"note":"\"password\":\"comment\"","privateKeyPassphrase":"${{PASS}}"}}]"#
        );
        let hits = scan(Path::new(".vscode/sftp.json"), &text);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].secret, format!("{weak}!"));
        assert_eq!(
            hits[0].col,
            text[..text.find(&format!("{weak}\\u")).unwrap()]
                .chars()
                .count()
                + 1
        );
        assert_eq!(hits[1].secret, weak);
        assert_eq!(hits[1].line, 2);
        let deep = format!(
            "{}\"password\":\"{weak}\"{}",
            "{".repeat(20_000),
            "}".repeat(20_000)
        );
        assert_eq!(scan(Path::new(".ftpconfig"), &deep).len(), 1);
    }

    #[test]
    fn xml_passwords_handle_entities_cdata_and_attribute_boundaries() {
        let weak = ["pass", "word"].concat();
        let text = format!(
            "<!-- <x password='comment'/> -->\n<x note=\"password='comment'\" password='{weak}&amp;&#33;'/>\n<Pass><![CDATA[{weak}<x>]]></Pass>\n<Pass encoding=\"base64\">{}</Pass>\n<Pass>&#36;{{PASS}}</Pass>",
            ["cGFz", "c3dvcmQ="].concat()
        );
        let hits = scan(Path::new("filezilla/filezilla.xml"), &text);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].secret, format!("{weak}&!"));
        assert_eq!(hits[0].line, 2);
        assert_eq!(hits[1].secret, format!("{weak}<x>"));
        assert_eq!(hits[1].line, 3);
        assert_eq!(hits[2].secret, ["cGFz", "c3dvcmQ="].concat());
        assert!(
            scan(
                Path::new("filezilla/filezilla.xml"),
                "<!-- <Pass>comment</Pass>"
            )
            .is_empty()
        );
    }

    #[test]
    fn git_credentials_accept_password_punctuation_and_weak_values() {
        let value = ["pass", "word!#@498"].concat();
        let text = format!("https://user@example.test:{value}@github.test\n");
        let hits = scan(Path::new(".git-credentials"), &text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].secret, value);
    }

    #[test]
    fn recognizes_special_paths_and_ignores_env_templates() {
        for path in [
            ".env",
            ".env.local",
            ".npmrc",
            ".pypirc",
            ".git-credentials",
            ".docker/config.json",
        ] {
            assert!(is_special(Path::new(path)), "{path}");
        }
        for path in [
            ".env.example",
            ".env.sample",
            ".env.template",
            "env",
            "config.json",
        ] {
            assert!(!is_special(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn scans_nonempty_sensitive_env_values() {
        let api = format!("{}{}", "runtime-", "api-value");
        let password = format!("{}{}", "runtime-", "password-value");
        let text = format!(
            "# comment\nAPI_KEY={api}\nEMPTY_TOKEN=\nNORMAL=value\nDB_PASSWORD=\"{password}\"\nREF_SECRET=${{SECRET_FROM_CI}}\n"
        );

        let hits = scan(Path::new(".env.local"), &text);

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].rule.id, "env-secret");
        assert_eq!((hits[0].line, hits[0].col), (2, 9));
        assert_eq!(hits[0].secret, api);
        assert_eq!((hits[1].line, hits[1].col), (5, 14));
        assert_eq!(hits[1].secret, password);
    }

    #[test]
    fn env_example_is_not_scanned() {
        let value = format!("{}{}", "runtime-", "value");
        assert!(scan(Path::new(".env.example"), &format!("API_KEY={value}")).is_empty());
    }

    #[test]
    fn scans_npmrc_auth_fields() {
        let token = format!("{}{}", "runtime-", "npm-value");
        let auth = format!("{}{}", "base64-", "npm-auth-value");
        let password = format!("{}{}", "base64-", "npm-password-value");
        let text = format!(
            "registry=https://registry.example.test\n\
             //registry.example.test/:_authToken = \"{token}\"\n\
             _auth = {auth}\n\
             //registry.example.test/:_password = '{password}'\n\
             _auth=${{NPM_AUTH}}\n\
             _password=changeme\n\
             email=developer@example.test\n"
        );

        let hits = scan(Path::new(".npmrc"), &text);

        assert_eq!(hits.len(), 3);
        assert!(hits.iter().all(|hit| hit.rule.id == "npm-auth-token"));
        assert_eq!(
            hits.iter()
                .map(|hit| (hit.line, hit.secret.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (2, token.as_str()),
                (3, auth.as_str()),
                (4, password.as_str())
            ]
        );
    }

    #[test]
    fn scans_pypirc_password() {
        let password = format!("{}{}", "runtime-", "pypi-value");
        let text = format!("[server]\nusername = uploader\npassword = {password}\n");

        let hits = scan(Path::new(".pypirc"), &text);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.id, "pypi-password");
        assert_eq!((hits[0].line, hits[0].col), (3, 12));
        assert_eq!(hits[0].secret, password);
    }

    #[test]
    fn scans_git_credentials_password() {
        let password = format!("{}{}", "runtime-", "git-password");
        let line = format!("{}{}{}", "https://developer:", password, "@example.test");

        let hits = scan(Path::new(".git-credentials"), &line);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.id, "git-credentials");
        assert_eq!(hits[0].col, "https://developer:".chars().count() + 1);
        assert_eq!(hits[0].secret, password);
    }

    #[test]
    fn scans_only_auths_entries_in_docker_config() {
        let first = format!("{}{}", "base64-", "docker-one");
        let second = format!("{}{}", "base64-", "docker-two");
        let text = format!(
            "{{\n  \"auth\": \"{first}\",\n  \"auths\": {{\n    \"one.example\": {{\"auth\": \"{first}\"}},\n    \"two.example\": {{\n      \"auth\": \"{second}\"\n    }}\n  }}\n}}"
        );
        let path = PathBuf::from("project").join(".docker").join("config.json");

        let hits = scan(&path, &text);

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].rule.id, "docker-auth");
        assert_eq!((hits[0].line, hits[0].secret.as_str()), (4, first.as_str()));
        assert_eq!(
            (hits[1].line, hits[1].secret.as_str()),
            (6, second.as_str())
        );
    }

    #[test]
    fn malformed_docker_config_is_ignored() {
        assert!(scan(Path::new(".docker/config.json"), "{not json").is_empty());
    }
}

#[cfg(test)]
mod review_tests {
    //! Регрессии с ревью T1.3 (Claude): ложные срабатывания в `.env`.
    use super::*;

    fn env_hits(text: &str) -> Vec<String> {
        scan(Path::new(".env"), text)
            .into_iter()
            .map(|h| h.secret)
            .collect()
    }

    #[test]
    fn env_does_not_flag_lookalike_keys_or_trivial_values() {
        let text = "MONKEY=banana\nBYPASS_CACHE=true\nPASSENGER_COUNT=4\nKEYBOARD=us\n\
                    TOKEN_TTL=3600\nSESSION_TIMEOUT_SECRET_ROTATION=30d\n\
                    NEXT_PUBLIC_STRIPE_KEY=pk_live_abc123\nDEBUG=false\n";
        assert_eq!(env_hits(text), Vec::<String>::new());
    }

    #[test]
    fn env_template_placeholders_are_skipped_but_real_keys_are_not() {
        // Реальный прогон: в .env.production.example были русские заглушки И настоящий ключ.
        let real = format!("{}{}", "re_iK2", "q9Zt7LmXw4F9BL");
        let text = format!(
            "PGPASSWORD=ЗАМЕНИТЬ_ПАРОЛЬ_БД
JWT_SECRET=ВСТАВЬТЕ_СЛУЧАЙНЫЙ_HEX
API_KEY=your_api_key
\n             TOKEN=<token>
RESEND_API_KEY={real}
"
        );
        let hits: Vec<String> = scan(Path::new(".env.production.example"), &text)
            .into_iter()
            .map(|h| h.secret)
            .collect();
        assert_eq!(hits, vec![real]);
    }

    #[test]
    fn env_non_ascii_values_do_not_panic() {
        // Падало на реальном прогоне `jetscan machine`: срез посреди `Д`.
        let text = "DB_PASSWORD=парольД
API_KEY=Д
TOKEN=1Д
";
        assert_eq!(env_hits(text), vec!["парольД", "Д", "1Д"]);
    }

    #[test]
    fn env_still_flags_real_secret_keys() {
        let text = "DB_PASSWORD=Tq9vL2mXw\nSTRIPE_SECRET=s3cr3tValue\nGITHUB_TOKEN=abc12345\n\
                    OPENAI_APIKEY=k-123456\nexport AWS_SECRET_ACCESS_KEY=wJalr0XUtn\nMYSQL_PWD=root\n";
        assert_eq!(
            env_hits(text),
            vec![
                "Tq9vL2mXw",
                "s3cr3tValue",
                "abc12345",
                "k-123456",
                "wJalr0XUtn",
                "root"
            ]
        );
    }
}

#[cfg(test)]
mod t94_tests {
    //! T9.4: shell profiles, AWS/S3 credential files, Rails secrets.yml, hub/gh, .dockercfg.
    //! Secret-looking values are assembled at runtime so this file holds none.
    use super::*;

    /// Random-looking value of the given shape, never a real key.
    fn fake(parts: &[&str]) -> String {
        parts.concat()
    }

    fn secrets(path: &str, text: &str) -> Vec<String> {
        scan(Path::new(path), text)
            .into_iter()
            .map(|h| h.secret)
            .collect()
    }

    fn found(hits: &[Hit]) -> Vec<(&str, usize, usize, &str)> {
        hits.iter()
            .map(|h| (h.rule.id, h.line, h.col, h.secret.as_str()))
            .collect()
    }

    #[test]
    fn new_special_paths_are_narrowly_scoped() {
        for path in [
            ".bashrc",
            "home/.bash_profile",
            "dotfiles/bashrc",
            ".zshrc",
            ".zshrc.local",
            ".zshenv",
            ".profile",
            ".envrc",
            ".dockercfg",
            ".s3cfg",
            ".aws/credentials",
            ".aws/config",
            "config/secrets.yml",
            "web/ruby/secrets.yml",
            "hub",
            ".config/hub",
            ".config/gh/hosts.yml",
        ] {
            assert!(is_special(Path::new(path)), "{path}");
        }
        let token = fake(&["Qz7Kp2Lm", "9Xw4Rt6Y"]);
        for path in [
            "profile",
            "bashrc.sh",
            "install.bash",
            "config",
            "credentials",
            "cloud/config",
            "hosts.yml",
            "secrets.yaml",
            "secrets.yml.example",
            "hub.yml",
            "dockercfg",
        ] {
            assert!(!is_special(Path::new(path)), "{path}");
            for text in [
                format!("export API_TOKEN={token}"),
                format!("aws_secret_access_key = {token}"),
                format!("oauth_token: {token}"),
                format!("secret_key_base: {token}"),
            ] {
                assert!(scan(Path::new(path), &text).is_empty(), "{path}");
            }
        }
    }

    #[test]
    fn shell_profiles_report_literal_exported_secrets() {
        let aws = fake(&["nQ2Vz", "KrMrRjyS", "Llt8HCdFU3tM"]);
        let gh = fake(&["51e61afe", "e2c2667123fc", "9ed160a0"]);
        let weak = fake(&["Pass!", "12345"]);
        let plain = fake(&["k9", "Lm2Qz"]);
        let text = format!(
            "# ~/.bashrc\r\nHISTSIZE=1000\r\nexport AWS_SECRET_ACCESS_KEY={aws}\r\n\
             export HOMEBREW_GITHUB_API_TOKEN='{gh}' # comment\r\n\
             if [ -n \"$PS1\" ]; then\r\n  export GMAIL_PASSWORD=\"{weak}\"\r\nfi\r\n\
             DB_PASS={plain}; export DB_PASS\r\n"
        );
        let hits = scan(Path::new(".bashrc"), &text);
        assert_eq!(
            found(&hits),
            vec![
                ("shell-secret", 3, 30, aws.as_str()),
                ("shell-secret", 4, 35, gh.as_str()),
                ("shell-secret", 6, 26, weak.as_str()),
                ("shell-secret", 8, 9, plain.as_str()),
            ]
        );
        assert!(hits.iter().all(|h| h.rule.confidence == Confidence::Medium));
        // One line at a time (as history lines arrive): same result.
        assert_eq!(
            secrets(".zshrc", &format!("export API_KEY={plain}")),
            vec![plain]
        );
    }

    #[test]
    fn shell_profiles_skip_references_paths_placeholders_and_non_assignments() {
        let value = fake(&["Qz7Kp2Lm", "9Xw4Rt6Y"]);
        let text = format!(
            "# export API_TOKEN={value}\n\
             export API_TOKEN=\n\
             export S3_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY\n\
             export GITHUB_TOKEN=${{GH_TOKEN}}\n\
             export NPM_TOKEN=\"$(cat ~/.npm-token)\"\n\
             export OPENAI_API_KEY=`pass show openai`\n\
             export SLACK_TOKEN=\"abc$SUFFIX\"\n\
             export SECRET_KEY=$(openssl rand -hex 32)\n\
             export PASSWORD_STORE_DIR=~/.password-store\n\
             export SSH_KEY=/home/me/.ssh/id_ed25519\n\
             export DEPLOY_KEY_FILE=keys/deploy\n\
             export GPG_KEY=0x1A2B3C4D5E6F7A8B\n\
             export GPGKEY=1A2B3C4D\n\
             export TOKEN_TTL=3600\n\
             export API_KEY=your_api_key_here\n\
             export NEXT_PUBLIC_API_KEY={value}\n\
             export DEBUG=true\n\
             [ \"$TOKEN\" = {value} ] && echo same\n\
             TOKEN=={value}\n\
             export -n API_TOKEN\n\
             export API_TOKEN='{value}\n\
             alias token='echo {value}'\n"
        );
        assert_eq!(secrets(".bash_profile", &text), Vec::<String>::new());
        // A setting that merely contains a secret word is not a secret name.
        assert!(secrets(".profile", &format!("export KEYTIMEOUT={value}")).is_empty());
    }

    #[test]
    fn aws_credentials_file_reports_any_stored_secret() {
        let secret = fake(&["nQ2Vz", "KrMrRjyS", "Llt8HCdFU3tM"]);
        let session = fake(&["IQoJb3", "JpZ2luX2VjE", "Pz9Kq"]);
        let weak = ["change", "me"].concat();
        let text = format!(
            "# AWS\r\n[default]\r\naws_access_key_id = {}\r\naws_secret_access_key = {secret} # note\r\n\
             aws_session_token={session}\r\n[profile two]\r\nAWS_SECRET_ACCESS_KEY = {weak}\r\n",
            fake(&["yLryKGwc", "Gc3ez9G8"])
        );
        let hits = scan(Path::new(".aws/credentials"), &text);
        assert_eq!(
            found(&hits),
            vec![
                ("aws-secret-key", 4, 25, secret.as_str()),
                ("aws-session-token", 5, 19, session.as_str()),
                ("aws-secret-key", 7, 25, weak.as_str()),
            ]
        );
        assert!(hits.iter().all(|h| h.rule.confidence == Confidence::High));
    }

    #[test]
    fn aws_credentials_file_skips_empty_references_and_comments() {
        let value = fake(&["nQ2Vz", "KrMrRjyS", "Llt8HCdFU3tM"]);
        let text = format!(
            "[default]\naws_secret_access_key =\naws_secret_access_key = ${{AWS_SECRET}}\n\
             aws_session_token = $SESSION\n# aws_secret_access_key = {value}\n\
             ; aws_secret_access_key = {value}\n[aws_secret_access_key = {value}]\n\
             aws_access_key_id = {value}\nregion = us-east-1\n"
        );
        assert!(secrets(".aws/config", &text).is_empty());
    }

    #[test]
    fn s3cfg_reports_secret_key_not_access_key() {
        let secret = fake(&["yLryKGwc", "Gc3ez9G8YAnj"]);
        let text = format!(
            "[default]\naccess_key = {}\nsecret_key = {secret} # Sensitive\ngpg_passphrase =\n\
             access_token = \nhost_base = s3.amazonaws.com\n",
            fake(&["nQ2Vz", "KrMrRjyS"])
        );
        let hits = scan(Path::new(".s3cfg"), &text);
        assert_eq!(
            found(&hits),
            vec![("aws-secret-key", 3, 14, secret.as_str())]
        );
    }

    #[test]
    fn rails_secrets_yml_reports_literal_secrets() {
        let dev = fake(&["e0ec946f", "cefea5ce0d4d", "924f3c8db11d"]);
        let quoted = fake(&["96dc2e34", "9b1236b9e591"]);
        let other = fake(&["Qz7Kp2Lm", "9Xw4Rt6Y"]);
        let text = format!(
            "# comment\r\ndevelopment:\r\n  secret_key_base: {dev}\r\n\r\ntest:\r\n  secret_key_base: \"{quoted}\"\r\n\
             production:\r\n  secret_key_base: <%= ENV[\"SECRET_KEY_BASE\"] %>\r\n  stripe_secret_key: {other} # live\r\n"
        );
        let hits = scan(Path::new("config/secrets.yml"), &text);
        assert_eq!(
            found(&hits),
            vec![
                ("rails-secret", 3, 20, dev.as_str()),
                ("rails-secret", 6, 21, quoted.as_str()),
                ("rails-secret", 9, 22, other.as_str()),
            ]
        );
    }

    #[test]
    fn rails_secrets_yml_skips_erb_references_and_placeholders() {
        let value = fake(&["Qz7Kp2Lm", "9Xw4Rt6Y"]);
        let text = format!(
            "production:\n  secret_key_base: \"<%= ENV.fetch('SECRET_KEY_BASE') %>\"\n\
             secret_key_base:\n  secret_key_base: ~\n  secret_key_base: null\n\
             # secret_key_base: {value}\n  secret_key_base: your_secret_here\n\
             secret_key_base: |\n  {value}\n  api_token: ${{API_TOKEN}}\n\
             stripe_publishable_key: {value}\n  domain_name: example.test\n\
             secret_key_base: *default_secret\n  timeout_secret: 30\n"
        );
        assert_eq!(secrets("config/secrets.yml", &text), Vec::<String>::new());
    }

    #[test]
    fn hub_and_gh_configs_report_any_oauth_token() {
        let token = fake(&["7f9cc25d", "e23d1a255720", "b0ae4551f404"]);
        let weak = ["sec", "ret"].concat();
        let hub = format!(
            "---\r\ngithub.com:\r\n- user: octocat\r\n  oauth_token: \"{token}\"\r\n  protocol: https\r\n\
             enterprise.test:\r\n- oauth_token: {weak}\r\n"
        );
        let hits = scan(Path::new("hub"), &hub);
        assert_eq!(
            found(&hits),
            vec![
                ("github-cli-oauth-token", 4, 17, token.as_str()),
                ("github-cli-oauth-token", 7, 16, weak.as_str()),
            ]
        );
        let gh = format!("github.com:\n    user: octocat\n    oauth_token: {token}\n");
        assert_eq!(secrets(".config/gh/hosts.yml", &gh), vec![token.clone()]);
        let empty = format!(
            "github.com:\n  oauth_token:\n  oauth_token: \"\"\n  oauth_token: ${{GH_TOKEN}}\n\
             # oauth_token: {token}\n  user: octocat\n  git_protocol: https\n"
        );
        assert!(secrets(".config/hub", &empty).is_empty());
    }

    #[test]
    fn legacy_dockercfg_reports_registry_auths() {
        let auth = fake(&["X3Rva2Vu", "OjEyMzQuMThq", "Zjg0MWZr"]);
        let other = fake(&["dXNlcjpw", "YXNzd29yZA"]);
        let text = format!(
            "{{\r\n  \"https://index.docker.io/v1/\": {{\r\n    \"email\": \"d@example.test\",\r\n    \"auth\": \"{auth}\"\r\n  }},\r\n\
             \"registry.test\": {{\"auth\": \"{other}\"}},\r\n  \"empty.test\": {{\"auth\": \"\"}},\r\n\
             \"nested.test\": {{\"meta\": {{\"auth\": \"{other}x\"}}}}\r\n}}"
        );
        let hits = scan(Path::new("home/.dockercfg"), &text);
        assert_eq!(
            found(&hits),
            vec![
                ("docker-auth", 4, 14, auth.as_str()),
                ("docker-auth", 6, 28, other.as_str()),
            ]
        );
        assert!(scan(Path::new(".dockercfg"), "{not json").is_empty());
        assert!(scan(Path::new(".dockercfg"), "[\"auth\", \"x\"]").is_empty());
        assert!(scan(Path::new(".dockercfg"), "{\"r\": {\"auth\": \"${AUTH}\"}}").is_empty());
    }
}
