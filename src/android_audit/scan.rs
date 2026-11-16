//! Движок Android Source Audit: обход → структура Gradle-проекта → правила → результат (схема 2).
//! Битые файлы, нелитеральный Gradle, бюджеты — это не `Err`, а проверки `partial` с причиной:
//! отчёт не выглядит «чистым», когда что-то не проверено. `Err` — только если корень не открыть.

use super::project::{Module, ModuleKind, Project, SdkValue, needs_structure_text};
use super::rules::{self, RuleOutput, code, gradle as gradle_rules, manifest, secret};
use super::types::{AndroidFinding, CheckStatus, RuleCheck};
use super::walk::{self, Budgets, FileKind, Reader, WalkStats};
use crate::secrets::scan::INLINE_IGNORE;
use crate::ui;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 2;

/// Сколько путей перечислять в одной причине/ограничении.
pub const MAX_LISTED: usize = 5;

#[derive(Clone, Debug, Default)]
pub struct AndroidScanOptions {
    pub budgets: Budgets,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleInfo {
    pub dir: String,
    pub kind: ModuleKind,
    pub package: Option<String>,
    pub application_id: Option<String>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub compile_sdk: Option<i32>,
    pub manifests: Vec<String>,
    pub manifests_not_merged: Vec<String>,
    pub network_security_config: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    pub walk: WalkStats,
    pub gradle_files: usize,
    pub code_files_checked: usize,
    pub test_files_skipped: usize,
    pub files_scanned_for_secrets: usize,
    pub ignored_inline: usize,
    pub firebase_config_keys: usize,
    pub files_with_recoveries: usize,
}

#[derive(Clone, Debug)]
pub struct AndroidScanResult {
    pub schema_version: u32,
    pub modules: Vec<ModuleInfo>,
    /// Отсортированы по (путь, строка, колонка, правило, id).
    pub findings: Vec<AndroidFinding>,
    pub checks: Vec<RuleCheck>,
    pub limitations: Vec<String>,
    pub stats: ScanStats,
    /// Сетевых действий нет и не бывает.
    pub network_activities: Vec<String>,
}

impl AndroidScanResult {
    /// Полный скан: проверки есть, и ни одна не `partial`/`error` (контракт V2, уточнение 2026-11-12).
    pub fn completed(&self) -> bool {
        !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|c| matches!(c.status, CheckStatus::Completed | CheckStatus::Skipped))
    }
}

const BASE_LIMITATIONS: &[&str] = &[
    "static source analysis: nothing was built, installed or run, and nothing was sent anywhere",
    "build variants: src/main and every non-debug, non-test source-set manifest (release and all flavors together) are merged into one view; debug and test manifests are not analysed; manifests of external libraries (AARs) are not visible",
    "Gradle is evaluated only for literals (best effort for libs.versions.toml, gradle.properties, ext/extra/val variables and buildSrc/build-logic constants); values computed at build time are reported as unknown",
    "code patterns (WebView, TLS, crypto, logging, SharedPreferences) are token patterns, not data-flow analysis: where a value comes from and whether the code runs is not known",
    "test source sets (src/test, src/androidTest, ...) are not checked for code patterns; keys found in tests are reported at lower severity",
    "keystore files (*.jks, *.keystore, *.bks, *.p12, *.pfx) are detected by name only and never opened",
    "secret fingerprints are truncated salted SHA-256 hashes (as in `jetscan secrets`); a weak password could be brute-forced from its fingerprint",
];

/// Модуль, которому принадлежит путь (самый длинный каталог-префикс).
fn module_of<'a>(modules: &'a [Module], path: &str) -> Option<&'a Module> {
    modules
        .iter()
        .filter(|m| m.dir.is_empty() || path.starts_with(&format!("{}/", m.dir)))
        .max_by_key(|m| m.dir.len())
}

fn listed(paths: &[String]) -> String {
    let mut shown: Vec<String> = paths
        .iter()
        .take(MAX_LISTED)
        .map(|p| ui::sanitize_line(p))
        .collect();
    if paths.len() > MAX_LISTED {
        shown.push(format!("and {} more", paths.len() - MAX_LISTED));
    }
    shown.join(", ")
}

/// Убирает находки на строках с `jetscan:ignore`.
fn drop_ignored(findings: &mut Vec<AndroidFinding>, from: usize, text: &str, ignored: &mut usize) {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut k = from;
    while k < findings.len() {
        let hit = findings[k]
            .location
            .line
            .and_then(|l| lines.get(l as usize - 1))
            .is_some_and(|l| l.contains(INLINE_IGNORE));
        if hit {
            findings.remove(k);
            *ignored += 1;
        } else {
            k += 1;
        }
    }
}

pub fn scan_source(root: &Path, options: &AndroidScanOptions) -> Result<AndroidScanResult, String> {
    let (canonical, entries, walk_stats) = walk::list(root, &options.budgets)?;
    let mut reader = Reader::new(canonical, &options.budgets, walk_stats);
    let mut texts = BTreeMap::new();
    for e in entries.iter().filter(|e| needs_structure_text(e)) {
        if let Some(text) = reader.read(e) {
            texts.insert(e.relative_path.clone(), text);
        }
    }
    let project = Project::build(entries, texts);
    let mut stats = ScanStats {
        gradle_files: project
            .gradle
            .keys()
            .filter(|p| {
                let l = p.to_ascii_lowercase();
                l.ends_with(".gradle") || l.ends_with(".gradle.kts")
            })
            .count(),
        ..ScanStats::default()
    };
    let mut result = AndroidScanResult {
        schema_version: SCHEMA_VERSION,
        modules: Vec::new(),
        findings: Vec::new(),
        checks: Vec::new(),
        limitations: BASE_LIMITATIONS.iter().map(|s| s.to_string()).collect(),
        stats: ScanStats::default(),
        network_activities: Vec::new(),
    };
    let android_modules: Vec<&Module> = project
        .modules
        .iter()
        .filter(|m| m.kind.is_android())
        .collect();
    if stats.gradle_files == 0 {
        let why =
            "not applicable: no Gradle build files (build.gradle / build.gradle.kts) were found";
        result.checks.push(RuleCheck::new(
            "android.project",
            CheckStatus::Skipped,
            Some(why.to_string()),
        ));
        for id in rules::ALL {
            result.checks.push(RuleCheck::new(
                id,
                CheckStatus::Skipped,
                Some(why.to_string()),
            ));
        }
        stats.walk = reader.stats;
        result.stats = stats;
        return Ok(result);
    }

    let mut out = RuleOutput::default();
    // 1. Манифест и Gradle по модулям.
    let mut manifest_seen = false;
    for module in &project.modules {
        let (m_out, info, limits) = manifest::check(&project, module);
        manifest_seen |= !info.merged.is_empty();
        out.extend(m_out);
        result.limitations.extend(limits);
        out.extend(gradle_rules::debug(&project, module));
        out.extend(gradle_rules::minify(&project, module));
        if !module.kind.is_android() {
            continue;
        }
        let sdk = |v: &SdkValue| v.value();
        let mut sdk_notes = Vec::new();
        for (name, v) in [
            ("minSdk", &module.min_sdk),
            ("targetSdk", &module.target_sdk),
            ("compileSdk", &module.compile_sdk),
        ] {
            if let SdkValue::Known {
                value,
                best_effort: Some(how),
                ..
            } = v
            {
                sdk_notes.push(format!(
                    "module {}: {name} {value} resolved best effort ({})",
                    ui::sanitize_line(module.display_name()),
                    ui::sanitize_line(how)
                ));
            }
        }
        result.limitations.extend(sdk_notes);
        if !info.not_merged.is_empty() {
            result.limitations.push(format!(
                "module {}: not analysed (debug/test source sets): {}",
                ui::sanitize_line(module.display_name()),
                listed(&info.not_merged)
            ));
        }
        result.modules.push(ModuleInfo {
            dir: module.display_name().to_string(),
            kind: module.kind,
            package: info.package.clone(),
            application_id: module.application_id.clone(),
            min_sdk: info.min_sdk.or(sdk(&module.min_sdk)),
            target_sdk: info.target_sdk.or(sdk(&module.target_sdk)),
            compile_sdk: sdk(&module.compile_sdk),
            manifests: info.merged.clone(),
            manifests_not_merged: info.not_merged.clone(),
            network_security_config: info.network_config.clone(),
        });
    }
    // 2. Подпись и хранилища ключей.
    let (signing, keystores_with_passwords) = gradle_rules::signing(&project);
    out.extend(signing);
    let ignore = secret::GitIgnore::from_project(&project);
    out.extend(secret::keystores(
        &project,
        &ignore,
        &keystores_with_passwords,
    ));
    // Находки по файлам из шага структуры — с учётом `jetscan:ignore`.
    let mut ignored_inline = 0usize;
    {
        let mut by_path: HashMap<String, Vec<AndroidFinding>> = HashMap::new();
        for f in std::mem::take(&mut out.findings) {
            by_path
                .entry(f.location.relative_path.clone())
                .or_default()
                .push(f);
        }
        let mut paths: Vec<String> = by_path.keys().cloned().collect();
        paths.sort();
        for path in paths {
            let mut list = by_path.remove(&path).unwrap_or_default();
            if let Some(text) = project.texts.get(&path) {
                drop_ignored(&mut list, 0, text, &mut ignored_inline);
            }
            out.findings.extend(list);
        }
    }

    // 3. Содержимое: ключи во всех текстовых файлах, шаблоны в Kotlin/Java.
    let mut code_stats = code::CodeStats::default();
    let mut secret_stats = secret::SecretStats::default();
    let mut has_code = false;
    for entry in &project.entries {
        let lang = match entry.kind {
            FileKind::Kotlin => Some(crate::android_audit::lex::Lang::Kotlin),
            FileKind::Java => Some(crate::android_audit::lex::Lang::Java),
            FileKind::Keystore | FileKind::GitIgnore => continue,
            _ => None,
        };
        let owned;
        let text = match project.texts.get(&entry.relative_path) {
            Some(t) => t.as_str(),
            None => {
                let Some(t) = reader.read(entry) else {
                    continue;
                };
                owned = t;
                owned.as_str()
            }
        };
        let before = out.findings.len();
        let mut comments = Vec::new();
        if let Some(lang) = lang
            && !crate::android_audit::project::is_build_logic(&entry.relative_path)
        {
            has_code = true;
            let min_sdk =
                module_of(&project.modules, &entry.relative_path).and_then(|m| m.min_sdk.value());
            comments = code::check(
                &entry.relative_path,
                text,
                lang,
                min_sdk,
                &mut out,
                &mut code_stats,
            );
        } else if let Some(lang) = lang {
            comments = crate::android_audit::lex::lex(text, lang).comments;
        }
        secret::check_file(
            &project,
            &ignore,
            entry,
            text,
            &comments,
            &mut out,
            &mut secret_stats,
        );
        drop_ignored(&mut out.findings, before, text, &mut ignored_inline);
    }
    stats.walk = reader.stats.clone();
    stats.code_files_checked = code_stats.files_checked;
    stats.test_files_skipped = code_stats.test_files_skipped;
    stats.files_scanned_for_secrets = secret_stats.files_scanned;
    stats.ignored_inline = ignored_inline + secret_stats.ignored_inline;
    stats.firebase_config_keys = secret_stats.firebase_config_keys;
    stats.files_with_recoveries = code_stats.files_with_recoveries;

    // 4. Проверки.
    // Неполнота обхода: глобальная (бюджет, глубина, каталоги) — для всех правил; пропущенные
    // файлы — только для правил, которым нужен файл такого вида.
    let walk_reason = stats.walk.incomplete_everywhere().then(|| {
        format!(
            "the file walk was incomplete ({} outside the root, {} too deep, {} unreadable folder(s){})",
            stats.walk.outside_root_skipped,
            stats.walk.depth_limited,
            stats.walk.dirs_unreadable,
            if stats.walk.budget_exhausted {
                ", total budget exhausted"
            } else {
                ""
            }
        )
    });
    let skipped_for = |rule: &str| -> Option<String> {
        let code_rule = [
            rules::WEBVIEW_ID,
            rules::TLS_ID,
            rules::CRYPTO_ID,
            rules::STORAGE_ID,
            rules::LOG_ID,
        ]
        .contains(&rule);
        let paths: Vec<String> = stats
            .walk
            .skipped_files
            .iter()
            .filter(|(path, kind)| match kind {
                FileKind::Kotlin | FileKind::Java => code_rule || rule == rules::SECRET_ID,
                FileKind::Manifest | FileKind::Gradle | FileKind::VersionCatalog => !code_rule,
                FileKind::Properties => {
                    [rules::SECRET_ID, rules::SIGNING_ID].contains(&rule)
                        || (!code_rule && path.ends_with("gradle.properties"))
                }
                FileKind::Xml if path.contains("/res/") => {
                    manifest::MANIFEST_RULES.contains(&rule) || rule == rules::SECRET_ID
                }
                _ => rule == rules::SECRET_ID,
            })
            .map(|(p, _)| p.clone())
            .collect();
        (!paths.is_empty()).then(|| {
            format!(
                "{} file(s) were not read (too large for --max-size or unreadable): {}",
                paths.len(),
                listed(&paths)
            )
        })
    };
    let recoveries: Vec<String> = project
        .gradle
        .iter()
        .filter(|(_, g)| g.recoveries > 0)
        .map(|(p, _)| p.clone())
        .collect();
    let mut project_reasons = Vec::new();
    if let Some(w) = &walk_reason {
        project_reasons.push(w.clone());
    }
    let skipped_gradle: Vec<String> = stats
        .walk
        .skipped_files
        .iter()
        .filter(|(_, k)| matches!(k, FileKind::Gradle | FileKind::VersionCatalog))
        .map(|(p, _)| p.clone())
        .collect();
    if !skipped_gradle.is_empty() {
        project_reasons.push(format!(
            "Gradle file(s) not read: {}",
            listed(&skipped_gradle)
        ));
    }
    if !recoveries.is_empty() {
        project_reasons.push(format!(
            "Gradle files with unbalanced braces or unterminated strings were read approximately: {}",
            listed(&recoveries)
        ));
    }
    result.checks.push(if project_reasons.is_empty() {
        RuleCheck::new("android.project", CheckStatus::Completed, None)
    } else {
        RuleCheck::new(
            "android.project",
            CheckStatus::Partial,
            Some(project_reasons.join("; ")),
        )
    });
    let has_app = android_modules
        .iter()
        .any(|m| m.kind == ModuleKind::Application);
    let mut reasons: HashMap<&'static str, Vec<String>> = HashMap::new();
    for (rule, why) in out.partial.drain(..) {
        let list = reasons.entry(rule).or_default();
        if !list.contains(&why) {
            list.push(why);
        }
    }
    if !secret_stats.capped.is_empty() {
        reasons.entry(rules::SECRET_ID).or_default().push(format!(
            "more than {} matches in {}; the rest was not analysed",
            rules::MAX_HITS_PER_FILE,
            listed(&secret_stats.capped)
        ));
    }
    if !code_stats.capped.is_empty() {
        for id in [
            rules::WEBVIEW_ID,
            rules::TLS_ID,
            rules::CRYPTO_ID,
            rules::STORAGE_ID,
            rules::LOG_ID,
        ] {
            reasons.entry(id).or_default().push(format!(
                "more than {} code findings in {}; the rest was dropped",
                rules::MAX_HITS_PER_FILE,
                listed(&code_stats.capped)
            ));
        }
    }
    for id in rules::ALL {
        let manifest_rule = manifest::MANIFEST_RULES.contains(id);
        let code_rule = [
            rules::WEBVIEW_ID,
            rules::TLS_ID,
            rules::CRYPTO_ID,
            rules::STORAGE_ID,
            rules::LOG_ID,
        ]
        .contains(id);
        let app_only = [
            rules::DEBUG_ID,
            rules::NET_ID,
            rules::BACKUP_ID,
            rules::MINIFY_ID,
        ]
        .contains(id);
        let skip = if manifest_rule && android_modules.is_empty() {
            Some("not applicable: no Android application or library module was found")
        } else if app_only && !has_app {
            Some("not applicable: no Android application module was found")
        } else if manifest_rule && !manifest_seen && reasons.get(id).is_none_or(Vec::is_empty) {
            Some("not applicable: no AndroidManifest.xml was found in the Android modules")
        } else if code_rule && !has_code {
            Some("not applicable: no Kotlin/Java sources were found")
        } else {
            None
        };
        if let Some(why) = skip {
            result.checks.push(RuleCheck::new(
                id,
                CheckStatus::Skipped,
                Some(why.to_string()),
            ));
            continue;
        }
        let mut why = reasons.remove(id).unwrap_or_default();
        if let Some(w) = skipped_for(id) {
            why.insert(0, w);
        }
        if let Some(w) = &walk_reason {
            why.insert(0, w.clone());
        }
        let mut shown: Vec<String> = why.iter().take(10).cloned().collect();
        if why.len() > 10 {
            shown.push(format!("and {} more", why.len() - 10));
        }
        result.checks.push(if shown.is_empty() {
            RuleCheck::new(id, CheckStatus::Completed, None)
        } else {
            RuleCheck::new(id, CheckStatus::Partial, Some(shown.join("; ")))
        });
    }

    // 5. Ограничения по факту.
    if stats.test_files_skipped > 0 {
        result.limitations.push(format!(
            "{} Kotlin/Java file(s) in test source sets were not checked for code patterns",
            stats.test_files_skipped
        ));
    }
    if stats.firebase_config_keys > 0 {
        result.limitations.push(format!(
            "{} Google API key(s) in google-services.json were not reported: Firebase client keys are \
             public identifiers by design (restrict them in the Google Cloud console)",
            stats.firebase_config_keys
        ));
    }
    if stats.files_with_recoveries > 0 {
        result.limitations.push(format!(
            "{} Kotlin/Java file(s) have unterminated strings or comments; their code patterns were matched approximately",
            stats.files_with_recoveries
        ));
    }
    if stats.walk.skipped_binary > 0 {
        result.limitations.push(format!(
            "{} binary file(s) with a source extension were skipped",
            stats.walk.skipped_binary
        ));
    }
    if android_modules.iter().any(|m| m.convention) {
        let names: Vec<String> = android_modules
            .iter()
            .filter(|m| m.convention)
            .map(|m| m.display_name().to_string())
            .collect();
        result.limitations.push(format!(
            "module(s) {} use convention plugins (build-logic/buildSrc); their build types and SDK levels were read from there only where they are literals",
            listed(&names)
        ));
    }
    let mut seen = std::collections::HashSet::new();
    result.limitations.retain(|l| seen.insert(l.clone()));

    // 6. Порядок.
    let mut findings = out.findings;
    findings.sort_by(|a, b| {
        (
            &a.location.relative_path,
            a.location.line,
            a.location.column,
            a.rule_id,
            &a.id,
        )
            .cmp(&(
                &b.location.relative_path,
                b.location.line,
                b.location.column,
                b.rule_id,
                &b.id,
            ))
    });
    findings.dedup_by(|a, b| a.id == b.id && a.location == b.location);
    result.findings = findings;
    result.stats = stats;
    Ok(result)
}
