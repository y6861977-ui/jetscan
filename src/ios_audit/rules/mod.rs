//! Правила iOS Source Audit. `confirmed` не выдаётся никогда: совпадение шаблона и литерал в
//! исходнике — не доказательство эксплуатации. Каждое правило возвращает находки и причины
//! неполноты (→ `partial`).

pub mod code;
pub mod plist;
pub mod secret;

use super::types::{
    Confidence, Evidence, IosFinding, IosLocation, Severity, finding_id, normalized_key,
};
pub use crate::android_audit::rules::{is_sensitive_name, truncate, words};
use crate::ui;

pub const ATS_ID: &str = "IOS-ATS-001";
pub const URLSCHEME_ID: &str = "IOS-URLSCHEME-002";
pub const ENTITLEMENTS_ID: &str = "IOS-ENTITLEMENTS-003";
pub const SECRET_ID: &str = "IOS-SECRET-004";
pub const SIGNING_ID: &str = "IOS-SIGNING-005";
pub const STORAGE_ID: &str = "IOS-STORAGE-006";
pub const KEYCHAIN_ID: &str = "IOS-KEYCHAIN-007";
pub const TLS_ID: &str = "IOS-TLS-008";
pub const WEBVIEW_ID: &str = "IOS-WEBVIEW-009";
pub const CRYPTO_ID: &str = "IOS-CRYPTO-010";
pub const LOG_ID: &str = "IOS-LOG-011";
pub const PASTEBOARD_ID: &str = "IOS-PASTEBOARD-012";

/// Все правила в порядке отчёта.
pub const ALL: &[&str] = &[
    ATS_ID,
    URLSCHEME_ID,
    ENTITLEMENTS_ID,
    SECRET_ID,
    SIGNING_ID,
    STORAGE_ID,
    KEYCHAIN_ID,
    TLS_ID,
    WEBVIEW_ID,
    CRYPTO_ID,
    LOG_ID,
    PASTEBOARD_ID,
];

/// Правила по коду Swift/Objective-C.
pub const CODE_RULES: &[&str] = &[
    STORAGE_ID,
    KEYCHAIN_ID,
    TLS_ID,
    WEBVIEW_ID,
    CRYPTO_ID,
    LOG_ID,
    PASTEBOARD_ID,
];

/// Правила по Info.plist.
pub const INFO_RULES: &[&str] = &[ATS_ID, URLSCHEME_ID];

pub const REF_MASVS: &str = "https://mas.owasp.org/MASVS/";

/// Сколько срабатываний одного файла разбираем (защита от файлов-бомб).
pub const MAX_HITS_PER_FILE: usize = 200;

#[derive(Default, Debug)]
pub struct RuleOutput {
    pub findings: Vec<IosFinding>,
    /// (правило, причина неполноты).
    pub partial: Vec<(&'static str, String)>,
}

impl RuleOutput {
    pub fn extend(&mut self, other: RuleOutput) {
        self.findings.extend(other.findings);
        self.partial.extend(other.partial);
    }
}

/// Описание новой находки.
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
    pub fn build(self) -> IosFinding {
        let key = match &self.fingerprint {
            Some(fp) => fp.clone(),
            None => normalized_key(&self.key),
        };
        let mut tags = vec!["ios-source".to_string()];
        tags.extend(self.tags);
        // Совпадение шаблона — никогда не доказательство.
        let confidence = match self.confidence {
            Confidence::Confirmed => Confidence::Potential,
            c => c,
        };
        IosFinding {
            id: finding_id(self.rule, self.path, &key),
            rule_id: self.rule,
            title: self.title,
            category: self.category,
            severity: self.severity,
            confidence,
            location: IosLocation {
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
