//! Движок APK Static Audit: архив → манифест → правила → результат (схема 2).
//! Битый архив/манифест — это не `Err`, а результат с проверками `error`/`skipped` и причиной:
//! так отчёт не выглядит «чистым» (Demo 4). `Err` — только если файл не прочитать вовсе.

use super::axml::{self, Document};
use super::manifest::{self, Manifest};
use super::rules::{self, RuleOutput, manifest_rules as mr};
use super::types::{ApkFinding, CheckStatus, RuleCheck};
use super::zip::{self, Archive, Budget, Issue};
use crate::ui;
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Default)]
pub struct ApkScanOptions {
    pub zip: zip::Limits,
    pub axml: axml::Limits,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApkInfo {
    pub package: Option<String>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub entries: usize,
    pub network_configs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ApkScanResult {
    pub schema_version: u32,
    pub apk: ApkInfo,
    /// Отсортированы по (запись, компонент, правило).
    pub findings: Vec<ApkFinding>,
    pub checks: Vec<RuleCheck>,
    pub limitations: Vec<String>,
    /// Сетевых действий нет и не бывает.
    pub network_activities: Vec<String>,
}

impl ApkScanResult {
    /// Полный скан: проверки есть, и ни одна не `partial`/`error` (контракт V2, уточнение 2026-11-12).
    /// Пустой список проверок — не «полный», а «ничего не проверено».
    pub fn completed(&self) -> bool {
        !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|c| matches!(c.status, CheckStatus::Completed | CheckStatus::Skipped))
    }
}

pub const MANIFEST_RULES: &[&str] = &[
    mr::EXPORT_ID,
    mr::DEBUG_ID,
    rules::net::NET_ID,
    mr::BACKUP_ID,
    mr::PERMS_ID,
];

const BASE_LIMITATIONS: &[&str] = &[
    "static analysis only: the APK was not installed or run",
    "APK signatures (v1/v2/v3) are not verified",
    "classes*.dex: only the string pool is scanned for keys; code (bytecode) is not analysed, so a DEX finding is located by string index, never by class or source line",
    "resources.arsc is not parsed: resource references (@...) in the manifest are not resolved",
    "manifest defaults follow the Android documentation for the declared minSdk/targetSdk",
];

pub fn scan_apk(path: &Path, options: &ApkScanOptions) -> Result<ApkScanResult, String> {
    let data = zip::load(path, &options.zip)
        .map_err(|e| format!("{}: {e}", ui::sanitize_line(&path.display().to_string())))?;
    Ok(scan_bytes(&data, options))
}

fn issue_text(issue: &Issue) -> String {
    match issue {
        Issue::TrailingData { bytes } => format!("{bytes} byte(s) after the end of the archive"),
        Issue::PrependedData { bytes } => format!("{bytes} byte(s) before the first entry"),
        Issue::DuplicateName { name, count } => format!(
            "{count} entries share the name {}; the first one was analysed",
            ui::sanitize_line(name)
        ),
        Issue::SuspiciousName { name } => format!(
            "entry name {} has a path traversal/absolute form (nothing is extracted)",
            ui::sanitize_line(name)
        ),
        Issue::Overlap { first, second } => format!(
            "entries {} and {} share bytes; both were ignored",
            ui::sanitize_line(first),
            ui::sanitize_line(second)
        ),
        Issue::UntrustedEntry { name, reason } => {
            format!("entry {} ignored: {reason}", ui::sanitize_line(name))
        }
        Issue::CentralDirectorySizeMismatch => {
            "central directory size differs from the end record".to_string()
        }
    }
}

fn status(out_partial: &[String], base: &[String]) -> (CheckStatus, Option<String>) {
    let reasons: Vec<String> = base.iter().chain(out_partial).cloned().collect();
    if reasons.is_empty() {
        (CheckStatus::Completed, None)
    } else {
        (CheckStatus::Partial, Some(reasons.join("; ")))
    }
}

fn skipped_all(checks: &mut Vec<RuleCheck>, status: CheckStatus, reason: &str) {
    for id in MANIFEST_RULES.iter().chain([&rules::secret::SECRET_ID]) {
        checks.push(RuleCheck::new(id, status, Some(reason.to_string())));
    }
}

pub fn scan_bytes(data: &[u8], options: &ApkScanOptions) -> ApkScanResult {
    let mut result = ApkScanResult {
        schema_version: SCHEMA_VERSION,
        apk: ApkInfo::default(),
        findings: Vec::new(),
        checks: Vec::new(),
        limitations: BASE_LIMITATIONS.iter().map(|s| s.to_string()).collect(),
        network_activities: Vec::new(),
    };
    let archive = match Archive::parse(data, &options.zip) {
        Ok(a) => a,
        Err(e) => {
            let why = e.describe();
            result.checks.push(RuleCheck::new(
                "apk.archive",
                CheckStatus::Error,
                Some(why.clone()),
            ));
            skipped_all(
                &mut result.checks,
                CheckStatus::Skipped,
                &format!("not_checked: {why}"),
            );
            return result;
        }
    };
    result.apk.entries = archive.entries.len();
    let archive_issues: Vec<String> = archive.issues.iter().map(issue_text).collect();
    let archive_untrusted = archive
        .issues
        .iter()
        .any(|i| matches!(i, Issue::Overlap { .. } | Issue::UntrustedEntry { .. }));
    result.limitations.extend(archive_issues.iter().cloned());
    result.checks.push(if archive_untrusted {
        RuleCheck::new(
            "apk.archive",
            CheckStatus::Partial,
            Some("some entries were ignored (see limitations)".to_string()),
        )
    } else {
        RuleCheck::new("apk.archive", CheckStatus::Completed, None)
    });

    let mut budget = Budget::new(&options.zip);
    let manifest = load_manifest(&archive, &mut budget, options);
    let (manifest, manifest_issues) = match manifest {
        Ok(pair) => pair,
        Err(why) => {
            result.checks.push(RuleCheck::new(
                "apk.manifest",
                CheckStatus::Error,
                Some(why.clone()),
            ));
            for id in MANIFEST_RULES {
                result.checks.push(RuleCheck::new(
                    id,
                    CheckStatus::Skipped,
                    Some(format!("not_checked: {why}")),
                ));
            }
            run_secrets(&archive, &mut budget, &mut result);
            sort(&mut result);
            return result;
        }
    };
    result.apk.package = manifest.package.clone();
    result.apk.min_sdk = manifest.sdk.min_declared.then_some(manifest.sdk.min);
    result.apk.target_sdk = manifest.sdk.target_declared.then_some(manifest.sdk.target);
    let mut base = Vec::new();
    if !manifest_issues.is_empty() {
        base.push(format!(
            "manifest decoded with problems: {}",
            manifest_issues.join("; ")
        ));
    }
    if manifest.sdk.unresolved {
        base.push("minSdk/targetSdk could not be read; defaults were used".to_string());
    }
    if !manifest.sdk.target_declared {
        result.limitations.push(format!(
            "targetSdkVersion is not declared in the manifest; Android treats it as {} (minSdk)",
            manifest.sdk.target
        ));
    }
    result.checks.push(RuleCheck::new(
        "apk.manifest",
        if base.is_empty() {
            CheckStatus::Completed
        } else {
            CheckStatus::Partial
        },
        (!base.is_empty()).then(|| base.join("; ")),
    ));

    let configs = network_configs(&archive, &mut budget, options);
    result.apk.network_configs = configs.iter().map(|c| c.entry.clone()).collect();
    let outputs: [(&str, RuleOutput); 5] = [
        (mr::EXPORT_ID, mr::exported(&manifest)),
        (mr::DEBUG_ID, mr::debuggable(&manifest)),
        (rules::net::NET_ID, rules::net::check(&manifest, &configs)),
        (mr::BACKUP_ID, mr::backup(&manifest)),
        (mr::PERMS_ID, mr::permissions(&manifest)),
    ];
    for (id, out) in outputs {
        let (st, reason) = status(&out.partial, &base);
        result.checks.push(RuleCheck::new(id, st, reason));
        result.findings.extend(out.findings);
    }
    run_secrets(&archive, &mut budget, &mut result);
    sort(&mut result);
    result
}

fn run_secrets(archive: &Archive, budget: &mut Budget, result: &mut ApkScanResult) {
    let (out, stats) = rules::secret::check(archive, budget);
    let (st, reason) = status(&out.partial, &[]);
    result
        .checks
        .push(RuleCheck::new(rules::secret::SECRET_ID, st, reason));
    result.findings.extend(out.findings);
    if stats.out_of_scope > 0 {
        result.limitations.push(format!(
            "{} binary entr(ies) (resources.arsc, native libraries, images, signatures) were not scanned for secrets",
            stats.out_of_scope
        ));
    }
    if stats.nested_code > 0 {
        result.limitations.push(format!(
            "{} DEX/JAR/ZIP/APK file(s) inside the APK (outside classes*.dex) were not checked",
            stats.nested_code
        ));
    }
    result.limitations.extend(stats.dex_notes);
}

fn sort(result: &mut ApkScanResult) {
    result
        .findings
        .sort_by(|a, b| (&a.location, a.rule_id, &a.id).cmp(&(&b.location, b.rule_id, &b.id)));
}

fn load_manifest(
    archive: &Archive,
    budget: &mut Budget,
    options: &ApkScanOptions,
) -> Result<(Manifest, Vec<String>), String> {
    let index = archive
        .find("AndroidManifest.xml")
        .ok_or("the archive has no AndroidManifest.xml")?;
    let bytes = archive
        .read(index, budget)
        .map_err(|e| format!("AndroidManifest.xml: {}", e.describe()))?;
    let doc: Document = axml::decode(&bytes, &options.axml)
        .map_err(|e| format!("AndroidManifest.xml: {}", e.describe()))?;
    let manifest = manifest::from_document(&doc)
        .ok_or("AndroidManifest.xml: the root element is not <manifest>")?;
    Ok((
        manifest,
        doc.issues.iter().map(|i| ui::sanitize_line(i)).collect(),
    ))
}

/// `res/**/*.xml` с корнем `<network-security-config>` (без resources.arsc — по содержимому).
fn network_configs(
    archive: &Archive,
    budget: &mut Budget,
    options: &ApkScanOptions,
) -> Vec<rules::net::NetworkConfig> {
    let mut configs = Vec::new();
    for (index, entry) in archive.entries.iter().enumerate() {
        let lower = entry.name.to_ascii_lowercase();
        if !(lower.starts_with("res/") && lower.ends_with(".xml")) {
            continue;
        }
        let Ok(bytes) = archive.read(index, budget) else {
            continue;
        };
        let Ok(doc) = axml::decode(&bytes, &options.axml) else {
            continue;
        };
        if let Some(cfg) = rules::net::parse_config(&entry.name, &doc) {
            configs.push(cfg);
        }
    }
    configs
}
