//! Типы результата APK Static Audit. Уровни/уверенность/статусы — общие с Web Source Audit
//! (`web_audit::types`), чтобы оба сканера отображались на FindingV2 одинаково.
//! Место находки в APK — запись архива и компонент манифеста; строк исходника Java/Kotlin
//! не бывает (из DEX их не выдумываем).

pub use crate::web_audit::types::{CheckStatus, Confidence, Evidence, RuleCheck, Severity};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApkLocation {
    /// Запись архива (`AndroidManifest.xml`, `assets/config.json`, `res/xml/…`).
    pub archive_entry: Option<String>,
    /// Компонент/элемент (`service .SyncService`, `application`, `meta-data@android:value`).
    pub component: Option<String>,
    /// Строка — только для текстовых записей, где она реально есть.
    pub line: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApkFinding {
    pub id: String,
    pub rule_id: &'static str,
    pub title: String,
    pub category: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: ApkLocation,
    pub evidence: Evidence,
    pub explanation: String,
    pub remediation_id: Option<String>,
    pub references: Vec<&'static str>,
    pub cwe_ids: Vec<&'static str>,
    pub tags: Vec<String>,
}

/// `apk/<rule>/<16 hex>` от правила, записи и ключа (отпечаток/компонент) — без номера строки.
pub fn finding_id(rule_id: &str, entry: &str, key: &str) -> String {
    let digest =
        crate::hash::sha256(format!("jetscan:apk:v1:{rule_id}\0{entry}\0{key}").as_bytes());
    format!(
        "apk/{}/{}",
        rule_id.to_ascii_lowercase(),
        crate::hash::hex(&digest[..8])
    )
}

/// Находка о манифесте — самый частый случай.
#[allow(clippy::too_many_arguments)]
pub fn manifest_finding(
    rule_id: &'static str,
    category: &'static str,
    component: Option<String>,
    title: String,
    severity: Severity,
    confidence: Confidence,
    explanation: String,
    remediation: &str,
    references: &[&'static str],
    cwe_ids: &[&'static str],
    tags: Vec<String>,
) -> ApkFinding {
    let entry = "AndroidManifest.xml";
    let key = format!("{}\0{title}", component.as_deref().unwrap_or(""));
    let excerpt = component.as_ref().map(|c| crate::ui::sanitize_line(c));
    ApkFinding {
        id: finding_id(rule_id, entry, &key),
        rule_id,
        title,
        category,
        severity,
        confidence,
        location: ApkLocation {
            archive_entry: Some(entry.to_string()),
            component,
            line: None,
        },
        evidence: Evidence {
            redacted_excerpt: excerpt,
            fingerprint: None,
        },
        explanation,
        remediation_id: Some(format!("{rule_id}:{remediation}")),
        references: references.to_vec(),
        cwe_ids: cwe_ids.to_vec(),
        tags,
    }
}
