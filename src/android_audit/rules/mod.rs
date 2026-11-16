//! Правила Android Source Audit. `confirmed` не выдаётся никогда: совпадение шаблона и литерал в
//! исходнике — не доказательство эксплуатации. Каждое правило возвращает находки и причины
//! неполноты (→ `partial`).

pub mod code;
pub mod gradle;
pub mod manifest;
pub mod secret;

use super::types::{
    AndroidFinding, AndroidLocation, Confidence, Evidence, Severity, finding_id, normalized_key,
};
use crate::ui;

pub const EXPORT_ID: &str = "ANDROID-EXPORT-001";
pub const DEBUG_ID: &str = "ANDROID-DEBUG-002";
pub const NET_ID: &str = "ANDROID-NET-003";
pub const BACKUP_ID: &str = "ANDROID-BACKUP-004";
pub const PERMS_ID: &str = "ANDROID-PERMS-005";
pub const SECRET_ID: &str = "ANDROID-SECRET-006";
pub const MINIFY_ID: &str = "ANDROID-MINIFY-007";
pub const SIGNING_ID: &str = "ANDROID-SIGNING-008";
pub const KEYSTORE_ID: &str = "ANDROID-KEYSTORE-009";
pub const WEBVIEW_ID: &str = "ANDROID-WEBVIEW-010";
pub const TLS_ID: &str = "ANDROID-TLS-011";
pub const CRYPTO_ID: &str = "ANDROID-CRYPTO-012";
pub const STORAGE_ID: &str = "ANDROID-STORAGE-013";
pub const LOG_ID: &str = "ANDROID-LOG-014";

/// Все правила в порядке отчёта.
pub const ALL: &[&str] = &[
    EXPORT_ID,
    DEBUG_ID,
    NET_ID,
    BACKUP_ID,
    PERMS_ID,
    SECRET_ID,
    MINIFY_ID,
    SIGNING_ID,
    KEYSTORE_ID,
    WEBVIEW_ID,
    TLS_ID,
    CRYPTO_ID,
    STORAGE_ID,
    LOG_ID,
];

pub const REF_MASVS: &str = "https://mas.owasp.org/MASVS/";

/// Сколько срабатываний одного правила в одном файле разбираем (защита от файлов-бомб).
pub const MAX_HITS_PER_FILE: usize = 200;

/// Итог правила по одному месту (модуль/файл).
#[derive(Default, Debug)]
pub struct RuleOutput {
    pub findings: Vec<AndroidFinding>,
    /// (правило, причина неполноты).
    pub partial: Vec<(&'static str, String)>,
}

impl RuleOutput {
    pub fn extend(&mut self, other: RuleOutput) {
        self.findings.extend(other.findings);
        self.partial.extend(other.partial);
    }
}

/// Описание новой находки (чтобы не передавать 15 аргументов).
pub struct New<'a> {
    pub rule: &'static str,
    pub category: &'static str,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub path: &'a str,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub component: Option<String>,
    pub excerpt: Option<String>,
    pub fingerprint: Option<String>,
    /// Ключ id (без строки): отпечаток, компонент или нормализованный фрагмент.
    pub key: String,
    pub explanation: String,
    pub remediation: &'static str,
    pub references: Vec<&'static str>,
    pub cwe_ids: Vec<&'static str>,
    pub tags: Vec<String>,
}

impl New<'_> {
    pub fn build(self) -> AndroidFinding {
        let key = match &self.fingerprint {
            Some(fp) => fp.clone(),
            None => normalized_key(&self.key),
        };
        let mut tags = vec!["android-source".to_string()];
        tags.extend(self.tags);
        AndroidFinding {
            id: finding_id(self.rule, self.path, &key),
            rule_id: self.rule,
            title: self.title,
            category: self.category,
            severity: self.severity,
            confidence: self.confidence,
            location: AndroidLocation {
                relative_path: self.path.to_string(),
                line: self.line,
                column: self.line.and(self.column),
                component: self.component,
            },
            evidence: Evidence {
                redacted_excerpt: self.excerpt.map(|e| truncate(&ui::sanitize_line(&e))),
                fingerprint: self.fingerprint,
            },
            explanation: self.explanation,
            remediation_id: Some(format!("{}:{}", self.rule, self.remediation)),
            references: self.references,
            cwe_ids: self.cwe_ids,
            tags,
        }
    }
}

pub const EXCERPT_MAX_CHARS: usize = 160;

pub fn truncate(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= EXCERPT_MAX_CHARS {
        return text.to_string();
    }
    let mut out: String = text.chars().take(EXCERPT_MAX_CHARS - 1).collect();
    out.push('…');
    out
}

/// Слова идентификатора: `accessToken` → [access, token], `API_KEY` → [api, key], `pass-word` → [pass, word].
pub fn words(ident: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = ident.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let boundary = c.is_uppercase()
            && !cur.is_empty()
            && (chars[i - 1].is_lowercase()
                || chars[i - 1].is_ascii_digit()
                || chars.get(i + 1).is_some_and(|n| n.is_lowercase()));
        if boundary {
            out.push(std::mem::take(&mut cur));
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Последнее слово (или пара слов) идентификатора — секретное: `password`, `accessToken`,
/// `apiKey`, `clientSecret`. `tokenType`, `passwordHint`, `tokens` — нет.
pub fn is_sensitive_name(ident: &str) -> bool {
    let w = words(ident);
    let Some(last) = w.last() else {
        return false;
    };
    let prev = w.len().checked_sub(2).map(|i| w[i].as_str());
    // Имя описывает не сам секрет, а что-то о нём: `negativeResponseFromOldToken`,
    // `tokenErrorFromServer`, `passwordRequestCode` (полевой тест, Thunderbird).
    if w.iter().any(|x| {
        matches!(
            x.as_str(),
            "response"
                | "error"
                | "exception"
                | "failure"
                | "result"
                | "request"
                | "callback"
                | "listener"
                | "state"
                | "status"
                | "type"
        )
    }) {
        return false;
    }
    match last.as_str() {
        "password" | "passwd" | "pwd" | "passphrase" | "secret" | "token" | "credential"
        | "credentials" | "apikey" | "privatekey" => true,
        "key" => matches!(
            prev,
            Some("api" | "private" | "secret" | "access" | "signing")
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_words() {
        assert_eq!(words("accessToken"), vec!["access", "token"]);
        assert_eq!(words("API_KEY"), vec!["api", "key"]);
        assert_eq!(words("HTTPServerURL"), vec!["http", "server", "url"]);
        assert_eq!(words("token2fa"), vec!["token2fa"]);
        assert_eq!(words("mUserPassword"), vec!["m", "user", "password"]);
    }

    #[test]
    fn sensitive_names() {
        for yes in [
            "password",
            "userPassword",
            "accessToken",
            "API_KEY",
            "apiKey",
            "clientSecret",
            "refresh_token",
            "privateKey",
            "credentials",
        ] {
            assert!(is_sensitive_name(yes), "{yes}");
        }
        for no in [
            "tokenType",
            "passwordHint",
            "tokens",
            "key",
            "monkey",
            "tokenizer",
            "isPasswordSet",
            "TAG",
            "keyAlias",
            "negativeResponseFromOldToken",
            "tokenErrorFromServer",
        ] {
            assert!(!is_sensitive_name(no), "{no}");
        }
    }

    #[test]
    fn excerpts_are_truncated() {
        let long = "a".repeat(400);
        assert_eq!(truncate(&long).chars().count(), EXCERPT_MAX_CHARS);
    }
}
