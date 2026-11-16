//! Типы результата iOS Source Audit. Уровни/уверенность/статусы — общие с Web, APK и Android
//! (`web_audit::types`), чтобы все сканеры одинаково отображались на FindingV2.
//! Место находки — реальный `файл:строка:колонка` в исходниках проекта (путь от корня, через `/`).
//! Сырых секретов здесь нет по построению: в `Evidence` только маска ядра и отпечаток.

pub use crate::web_audit::types::{CheckStatus, Confidence, Evidence, RuleCheck, Severity};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IosLocation {
    /// От корня проекта, через `/`.
    pub relative_path: String,
    /// С 1; `None` — позиции нет (файл подписи), не выдумываем.
    pub line: Option<u32>,
    /// С 1, в символах Unicode (как у ядра).
    pub column: Option<u32>,
    /// Цель Xcode / ключ plist (`target App`, `NSExceptionDomains.example.com`).
    pub component: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IosFinding {
    /// `ios/<rule>/<16 hex>` от правила, пути и ключа (отпечаток/компонент) — без номера строки.
    pub id: String,
    pub rule_id: &'static str,
    pub title: String,
    pub category: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: IosLocation,
    pub evidence: Evidence,
    pub explanation: String,
    pub remediation_id: Option<String>,
    pub references: Vec<&'static str>,
    pub cwe_ids: Vec<&'static str>,
    pub tags: Vec<String>,
}

/// Стабильный id находки: первые 8 байт SHA-256 от (правило, путь, ключ). Ключ — отпечаток
/// секрета ядра или нормализованный компонент/фрагмент; строки и колонки в нём нет.
pub fn finding_id(rule_id: &str, relative_path: &str, key: &str) -> String {
    let digest =
        crate::hash::sha256(format!("jetscan:ios:v1:{rule_id}\0{relative_path}\0{key}").as_bytes());
    format!(
        "ios/{}/{}",
        rule_id.to_ascii_lowercase(),
        crate::hash::hex(&digest[..8])
    )
}

/// Ключ для id из фрагмента кода: пробелы убраны, чтобы переформатирование не меняло id.
pub fn normalized_key(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_id_is_stable_and_scoped() {
        let a = finding_id("IOS-TLS-008", "App/Net.swift", "k");
        assert_eq!(a, finding_id("IOS-TLS-008", "App/Net.swift", "k"));
        assert!(a.starts_with("ios/ios-tls-008/"));
        assert_eq!(a.len(), "ios/ios-tls-008/".len() + 16);
        assert_ne!(a, finding_id("IOS-TLS-008", "App/Other.swift", "k"));
        assert_ne!(a, finding_id("IOS-LOG-011", "App/Net.swift", "k"));
        assert!(crate::finding_v2::output::is_canonical_id(
            &a,
            "IOS-TLS-008"
        ));
    }
}
