//! Внутренние типы Web Source Audit. Поля повторяют FindingV2 из
//! `docs/architecture/CONTRACTS_V2.md`; адаптер на `finding_v2` пишет интегратор
//! (соответствие — в `HANDOFF_WEB.md`). Сырых секретов здесь нет по построению:
//! в `Evidence` только маска и отпечаток.

/// Насколько доказано. `Confirmed` этот модуль сейчас не выдаёт вообще:
/// совпадение шаблона — не доказательство, а бандл мы не собираем.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Confirmed,
    Potential,
    NeedsReview,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Potential => "potential",
            Confidence::NeedsReview => "needs_review",
        }
    }
}

/// Тяжесть последствий, если находка верна. Отдельно от уверенности.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Completed,
    Partial,
    Skipped,
    Error,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::Completed => "completed",
            CheckStatus::Partial => "partial",
            CheckStatus::Skipped => "skipped",
            CheckStatus::Error => "error",
        }
    }
}

/// Место в исходнике. Путь — от корня проекта, через `/`. Строка и колонка с 1,
/// колонка — в символах Unicode (как у ядра). `None` — позиции нет; не выдумываем.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceLocation {
    pub relative_path: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

/// Доказательство без секрета: фрагмент, где значение заменено маской, и отпечаток
/// (тот же, что у `jetscan secrets` — работает с `.jetscanignore`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub redacted_excerpt: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebFinding {
    /// Стабильный id: `web/<rule>/<16 hex>` от правила, пути и отпечатка/фрагмента (без номера строки).
    pub id: String,
    pub rule_id: &'static str,
    pub title: String,
    pub category: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: SourceLocation,
    pub evidence: Evidence,
    pub explanation: String,
    pub remediation_id: Option<String>,
    pub references: Vec<&'static str>,
    pub cwe_ids: Vec<&'static str>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleCheck {
    pub id: String,
    pub status: CheckStatus,
    pub reason: Option<String>,
}

impl RuleCheck {
    pub fn new(id: &str, status: CheckStatus, reason: Option<String>) -> RuleCheck {
        RuleCheck {
            id: id.to_string(),
            status,
            reason,
        }
    }
}

/// Строит стабильный id находки. `key` — отпечаток секрета или нормализованный фрагмент.
pub fn finding_id(rule_id: &str, relative_path: &str, key: &str) -> String {
    let digest =
        crate::hash::sha256(format!("jetscan:web:v1:{rule_id}\0{relative_path}\0{key}").as_bytes());
    format!(
        "web/{}/{}",
        rule_id.to_ascii_lowercase(),
        crate::hash::hex(&digest[..8])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_id_is_stable_and_rule_scoped() {
        let a = finding_id("WEB-SECRET-001", "app/a.tsx", "0123456789abcdef");
        assert_eq!(
            a,
            finding_id("WEB-SECRET-001", "app/a.tsx", "0123456789abcdef")
        );
        assert!(a.starts_with("web/web-secret-001/"));
        assert_eq!(a.len(), "web/web-secret-001/".len() + 16);
        assert_ne!(
            a,
            finding_id("WEB-ENV-002", "app/a.tsx", "0123456789abcdef")
        );
        assert_ne!(
            a,
            finding_id("WEB-SECRET-001", "app/b.tsx", "0123456789abcdef")
        );
    }

    #[test]
    fn labels_match_contract_spelling() {
        assert_eq!(Confidence::NeedsReview.label(), "needs_review");
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(CheckStatus::Partial.label(), "partial");
    }
}
