//! Спецфайлы с кредами: `.env*`, `.npmrc`, `.pypirc`, `.git-credentials`,
//! `.docker/config.json`.
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
    if matches!(lower.as_str(), ".npmrc" | ".pypirc" | ".git-credentials") {
        return true;
    }
    lower == "config.json"
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|parent| parent.to_string_lossy().eq_ignore_ascii_case(".docker"))
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
        if let Some((start, end)) = url_password(line) {
            push_hit(
                &mut hits,
                GIT_CREDENTIALS_RULE,
                line_index + 1,
                line,
                start,
                end,
            );
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
    let Some((auths_start, auths_end)) = root_auths_object(text, &tokens) else {
        return Vec::new();
    };
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
        .find(|(_, c)| c.is_whitespace() || matches!(c, '/' | '?' | '#'))
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
    (!ignored_value(&line[start..end])).then_some((start, end))
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
