//! APK-NET-003: открытый HTTP и доверие пользовательским сертификатам.
//!
//! Источники (документация Android «Network security configuration» и `<application>`):
//! - `android:usesCleartextTraffic`: по умолчанию `true` при targetSdk ≤ 27, `false` при ≥ 28;
//!   на API 24+ флаг игнорируется, если у приложения есть network security config;
//! - в config: `cleartextTrafficPermitted` у `base-config`/`domain-config` (по умолчанию — как
//!   выше по targetSdk); `<trust-anchors><certificates src="user"/>` — доверие сертификатам,
//!   установленным пользователем (MITM); `debug-overrides` действуют только в debuggable-сборке;
//! - без config при targetSdk ≤ 23 пользовательские CA доверенные по умолчанию.
//!
//! Файл config находим без `resources.arsc`: среди `res/**/*.xml` берём AXML-документы с корнем
//! `<network-security-config>` (имя файла может быть обфусцировано). Если манифест ссылается на
//! config, а такого файла нет — проверка `partial`.

use super::RuleOutput;
use crate::apk_audit::axml::{Document, Element};
use crate::apk_audit::manifest::{Flag, Manifest, flag};
use crate::apk_audit::types::{
    ApkFinding, ApkLocation, Confidence, Evidence, Severity, finding_id, manifest_finding,
};

pub const NET_ID: &str = "APK-NET-003";

const REF_NSC: &str = "https://developer.android.com/privacy-and-security/security-config";
const REF_APPLICATION: &str =
    "https://developer.android.com/guide/topics/manifest/application-element";
const REF_MASVS: &str = "https://mas.owasp.org/MASVS/";

/// Разобранный network security config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub entry: String,
    pub base_cleartext: Flag,
    pub base_user_certs: bool,
    /// Для каждого `domain-config`: (cleartextTrafficPermitted, доверяет ли user CA).
    pub domains: Vec<(Flag, bool)>,
    pub debug_user_certs: bool,
}

fn trusts_user(e: &Element) -> bool {
    e.children
        .iter()
        .filter(|t| t.name == "trust-anchors")
        .flat_map(|t| t.children.iter().filter(|c| c.name == "certificates"))
        .any(|c| crate::apk_audit::manifest::string(c.plain("src")).as_deref() == Some("user"))
}

/// `None` — это не network security config.
pub fn parse_config(entry: &str, doc: &Document) -> Option<NetworkConfig> {
    let root = doc
        .root
        .as_ref()
        .filter(|r| r.name == "network-security-config")?;
    let base = root.children.iter().find(|c| c.name == "base-config");
    let mut domains = Vec::new();
    // domain-config может быть вложенным — обходим без рекурсии.
    let mut work: Vec<&Element> = root
        .children
        .iter()
        .filter(|c| c.name == "domain-config")
        .collect();
    while let Some(d) = work.pop() {
        domains.push((flag(d.plain("cleartextTrafficPermitted")), trusts_user(d)));
        work.extend(d.children.iter().filter(|c| c.name == "domain-config"));
    }
    Some(NetworkConfig {
        entry: entry.to_string(),
        base_cleartext: base.map_or(Flag::Absent, |b| flag(b.plain("cleartextTrafficPermitted"))),
        base_user_certs: base.is_some_and(trusts_user),
        domains,
        debug_user_certs: root
            .children
            .iter()
            .filter(|c| c.name == "debug-overrides")
            .any(trusts_user),
    })
}

fn config_finding(
    cfg: &NetworkConfig,
    component: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    explanation: String,
    cwe: &'static str,
) -> ApkFinding {
    ApkFinding {
        id: finding_id(NET_ID, &cfg.entry, title),
        rule_id: NET_ID,
        title: title.to_string(),
        category: "network",
        severity,
        confidence,
        location: ApkLocation {
            archive_entry: Some(cfg.entry.clone()),
            component: Some(component.to_string()),
            line: None,
        },
        evidence: Evidence {
            redacted_excerpt: Some(component.to_string()),
            fingerprint: None,
        },
        explanation,
        remediation_id: Some(format!("{NET_ID}:tighten-network-config")),
        references: vec![
            REF_NSC,
            if cwe == "CWE-295" {
                "https://cwe.mitre.org/data/definitions/295.html"
            } else {
                "https://cwe.mitre.org/data/definitions/319.html"
            },
            REF_MASVS,
        ],
        cwe_ids: vec![cwe],
        tags: vec!["apk".into(), "masvs:MASVS-NETWORK".into()],
    }
}

pub fn check(m: &Manifest, configs: &[NetworkConfig]) -> RuleOutput {
    let mut out = RuleOutput::default();
    let Some(app) = &m.application else {
        return out;
    };
    let target = m.sdk.target;
    let has_config = !configs.is_empty();
    if app.network_security_config && !has_config {
        out.partial.push(
            "the manifest references a network security config, but no res/**/*.xml with a \
             <network-security-config> root was found (resources.arsc is not parsed)"
                .to_string(),
        );
    }
    if configs.len() > 1 {
        out.partial.push(format!(
            "{} network security config files found; without resources.arsc it is not known which \
             one the manifest uses, so all were checked",
            configs.len()
        ));
    }
    // Флаг манифеста действует, если config нет, или на устройствах ниже API 24 (minSdk < 24).
    let flag_applies = !has_config || m.sdk.min < 24;
    let where_flag = if has_config {
        " (on Android 7.0+ the network security config takes precedence; minSdk is below 24)"
    } else {
        ""
    };
    match app.uses_cleartext {
        Flag::True if flag_applies => out.findings.push(manifest_finding(
            NET_ID,
            "network",
            Some("application".to_string()),
            "Cleartext HTTP is allowed app-wide".to_string(),
            Severity::Medium,
            Confidence::Potential,
            format!(
                "android:usesCleartextTraffic=\"true\"{where_flag}: the app may talk plain HTTP, which \
                 anyone on the network can read and modify. Potential: whether any request actually \
                 uses http:// is not visible without analysing the code."
            ),
            "tighten-network-config",
            &[REF_APPLICATION, REF_NSC, "https://cwe.mitre.org/data/definitions/319.html", REF_MASVS],
            &["CWE-319"],
            vec!["apk".into(), "masvs:MASVS-NETWORK".into()],
        )),
        Flag::Absent if flag_applies && target <= 27 => out.findings.push(manifest_finding(
            NET_ID,
            "network",
            Some("application".to_string()),
            "Cleartext HTTP is allowed by default (targetSdk <= 27)".to_string(),
            Severity::Low,
            Confidence::NeedsReview,
            format!(
                "android:usesCleartextTraffic is not set and targetSdk is {target}; for targetSdk 27 \
                 and lower the default is to allow plain HTTP. Raise targetSdk or set it to false."
            ),
            "tighten-network-config",
            &[REF_APPLICATION, REF_NSC, REF_MASVS],
            &["CWE-319"],
            vec!["apk".into(), "masvs:MASVS-NETWORK".into()],
        )),
        Flag::Unresolved => out
            .partial
            .push("android:usesCleartextTraffic is a resource reference".to_string()),
        _ => {}
    }
    if !has_config && target <= 23 {
        out.findings.push(manifest_finding(
            NET_ID,
            "network",
            Some("application".to_string()),
            "User-installed CA certificates are trusted by default (targetSdk <= 23)".to_string(),
            Severity::Low,
            Confidence::NeedsReview,
            format!(
                "There is no network security config and targetSdk is {target}; apps targeting API 23 \
                 and lower trust CA certificates the user (or an MDM / malware) installed, which \
                 enables interception of HTTPS."
            ),
            "tighten-network-config",
            &[REF_NSC, "https://cwe.mitre.org/data/definitions/295.html", REF_MASVS],
            &["CWE-295"],
            vec!["apk".into(), "masvs:MASVS-NETWORK".into()],
        ));
    }
    for cfg in configs {
        match cfg.base_cleartext {
            Flag::True => out.findings.push(config_finding(
                cfg,
                "base-config cleartextTrafficPermitted=true",
                "Network security config allows cleartext HTTP for all domains",
                Severity::Medium,
                Confidence::Potential,
                "The base-config permits plain HTTP for every domain not overridden by a domain-config."
                    .to_string(),
                "CWE-319",
            )),
            Flag::Absent if target <= 27 => out.findings.push(config_finding(
                cfg,
                "base-config (default)",
                "Network security config allows cleartext HTTP by default (targetSdk <= 27)",
                Severity::Low,
                Confidence::NeedsReview,
                format!("cleartextTrafficPermitted is not set and targetSdk is {target}, so the default permits plain HTTP."),
                "CWE-319",
            )),
            _ => {}
        }
        let cleartext_domains = cfg.domains.iter().filter(|(f, _)| *f == Flag::True).count();
        if cleartext_domains > 0 {
            out.findings.push(config_finding(
                cfg,
                "domain-config cleartextTrafficPermitted=true",
                "Network security config allows cleartext HTTP for some domains",
                Severity::Low,
                Confidence::NeedsReview,
                format!(
                    "{cleartext_domains} domain-config block(s) permit plain HTTP. Check that none of \
                     those domains carries credentials or personal data."
                ),
                "CWE-319",
            ));
        }
        if cfg.base_user_certs || cfg.domains.iter().any(|(_, u)| *u) {
            out.findings.push(config_finding(
                cfg,
                "trust-anchors certificates src=user",
                "Network security config trusts user-installed CA certificates",
                Severity::Medium,
                Confidence::Potential,
                "A <certificates src=\"user\"/> trust anchor outside debug-overrides lets any CA the \
                 user (or an MDM / malware) installed intercept this app's HTTPS traffic."
                    .to_string(),
                "CWE-295",
            ));
        }
        if cfg.debug_user_certs && app.debuggable == Flag::True {
            out.findings.push(config_finding(
                cfg,
                "debug-overrides certificates src=user",
                "Debug overrides trusting user CAs are active (app is debuggable)",
                Severity::Low,
                Confidence::Potential,
                "debug-overrides normally apply only to debug builds — but this APK is debuggable, so \
                 they are in effect."
                    .to_string(),
                "CWE-295",
            ));
        }
    }
    merge_cleartext_duplicates(&mut out, m.sdk.min);
    out
}

/// Флаг манифеста (действует ниже Android 7.0, когда minSdk < 24) и base-config сети (действует
/// с 7.0) про открытый HTTP — один факт: оставляем находку config и называем в ней оба источника
/// (полевой тест 2026-11-12, FP-паттерн 13). Severity — большая из двух.
fn merge_cleartext_duplicates(out: &mut RuleOutput, min_sdk: i32) {
    let is_manifest = |f: &ApkFinding| {
        f.location.archive_entry.as_deref() == Some("AndroidManifest.xml")
            && f.title.starts_with("Cleartext HTTP is allowed")
    };
    let is_config_base = |f: &ApkFinding| {
        f.location
            .component
            .as_deref()
            .is_some_and(|c| c.starts_with("base-config"))
            && f.title.contains("cleartext HTTP")
    };
    let (Some(manifest), Some(config)) = (
        out.findings.iter().position(is_manifest),
        out.findings.iter().position(is_config_base),
    ) else {
        return;
    };
    let from_manifest = out.findings.remove(manifest);
    let config = if config > manifest {
        config - 1
    } else {
        config
    };
    let target = &mut out.findings[config];
    target.severity = target.severity.min(from_manifest.severity);
    target.explanation.push_str(&format!(
        " The manifest says the same for devices below Android 7.0 (minSdk is {min_sdk}): {}",
        from_manifest.title.to_ascii_lowercase()
    ));
    target.explanation.push('.');
    target
        .tags
        .push("also_in:AndroidManifest.xml application".to_string());
}
