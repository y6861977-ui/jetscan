//! Движок iOS Source Audit: обход → структура (pbxproj, xcconfig) → правила → результат (схема 2).
//! Битые plist/pbxproj, нелитеральные настройки сборки, двоичные plist, бюджеты — это не `Err`, а
//! проверки `partial` с причиной: отчёт не выглядит «чистым», когда что-то не проверено. `Err` — только
//! если корень не открыть.

use super::lex::{self, Lang};
use super::plist;
use super::project::{Project, is_test_path, is_tooling_path, needs_structure_text};
use super::rules::{self, RuleOutput, code, plist as plist_rules, secret};
use super::types::{CheckStatus, IosFinding, RuleCheck};
use super::walk::{self, Budgets, Content, FileKind, Reader, WalkStats};
use crate::android_audit::rules::secret::GitIgnore;
use crate::secrets::scan::INLINE_IGNORE;
use crate::ui;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 2;

/// Сколько путей перечислять в одной причине/ограничении.
pub const MAX_LISTED: usize = 5;

#[derive(Clone, Debug, Default)]
pub struct IosScanOptions {
    pub budgets: Budgets,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetInfo {
    pub name: String,
    pub kind: String,
    pub deployment_target: Option<String>,
    pub info_plists: Vec<String>,
    pub entitlements: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectInfo {
    /// Путь к `project.pbxproj`.
    pub path: String,
    pub targets: Vec<TargetInfo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    pub walk: WalkStats,
    pub xcode_projects: usize,
    pub swift_files_checked: usize,
    pub objc_files_checked: usize,
    pub test_files_skipped: usize,
    pub info_plists_checked: usize,
    pub entitlements_checked: usize,
    pub files_scanned_for_secrets: usize,
    pub ignored_inline: usize,
    pub firebase_config_keys: usize,
    pub files_with_recoveries: usize,
}

#[derive(Clone, Debug)]
pub struct IosScanResult {
    pub schema_version: u32,
    pub projects: Vec<ProjectInfo>,
    /// Отсортированы по (путь, строка, колонка, правило, id).
    pub findings: Vec<IosFinding>,
    pub checks: Vec<RuleCheck>,
    pub limitations: Vec<String>,
    pub stats: ScanStats,
    /// Сетевых действий нет и не бывает.
    pub network_activities: Vec<String>,
}

impl IosScanResult {
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
    "static source analysis: nothing was built, installed or run, and nothing was sent anywhere; the built .ipa is not analysed (frameworks, Swift packages and pods compiled into it are not visible)",
    "build settings are read from project.pbxproj literals only; xcconfig inheritance (#include, $(inherited)) is best effort and conditional settings ([sdk=…], [config=…]) are ignored",
    "Info.plist keys generated from build settings (GENERATE_INFOPLIST_FILE / INFOPLIST_KEY_*) are not reconstructed; App Transport Security and URL types can only be set in an Info.plist file, which is what is checked",
    "code patterns (UserDefaults, Keychain, URLSession trust, WebView, CommonCrypto, logging, pasteboard) are token patterns, not data-flow analysis: where a value comes from and whether the code runs is not known",
    "test folders and files (*Tests, *UITests, Specs, Mocks, Fixtures, …) and tooling (fastlane, scripts, Package.swift) are not checked for code patterns; keys found in tests are reported at lower severity",
    "third-party and generated folders are skipped: Pods, Carthage/Build, Carthage/Checkouts, DerivedData, build, .build, SourcePackages, *.xcassets, *.framework, *.xcframework",
    "signing files (*.p12, *.p8, *.mobileprovision, *.cer, *.keychain) are judged by name and their first 64 bytes only; their contents are never read or shown",
    "binary property lists (bplist00) are not parsed",
    "secret fingerprints are truncated salted SHA-256 hashes (as in `jetscan secrets`); a weak password could be brute-forced from its fingerprint",
];

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
fn drop_ignored(findings: &mut Vec<IosFinding>, from: usize, text: &str, ignored: &mut usize) {
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

fn push_reason(reasons: &mut HashMap<&'static str, Vec<String>>, rule: &'static str, why: String) {
    let list = reasons.entry(rule).or_default();
    if !list.contains(&why) {
        list.push(why);
    }
}

pub fn scan_source(root: &Path, options: &IosScanOptions) -> Result<IosScanResult, String> {
    let (canonical, entries, walk_stats) = walk::list(root, &options.budgets)?;
    let mut reader = Reader::new(canonical, &options.budgets, walk_stats);
    let mut texts = BTreeMap::new();
    for e in entries.iter().filter(|e| needs_structure_text(e)) {
        if let Content::Text(text) = reader.read(e) {
            texts.insert(e.relative_path.clone(), text);
        }
    }
    let project = Project::build(entries, texts);
    let ignore = GitIgnore::from_files(project.entries_of(FileKind::GitIgnore).filter_map(|e| {
        project
            .texts
            .get(&e.relative_path)
            .map(|t| (e.relative_path.as_str(), t.as_str()))
    }));
    let mut stats = ScanStats {
        xcode_projects: project.projects.len() + project.broken.len(),
        ..ScanStats::default()
    };
    let mut result = IosScanResult {
        schema_version: SCHEMA_VERSION,
        projects: Vec::new(),
        findings: Vec::new(),
        checks: Vec::new(),
        limitations: BASE_LIMITATIONS.iter().map(|s| s.to_string()).collect(),
        stats: ScanStats::default(),
        network_activities: Vec::new(),
    };
    let info_plists: Vec<&walk::Entry> = project
        .entries_of(FileKind::Plist)
        .filter(|e| project.is_info_plist(&e.relative_path))
        .collect();
    let code_files = project.entries.iter().filter(|e| e.kind.is_code()).count();
    let ios_like = stats.xcode_projects > 0
        || project.has_package_swift
        || !info_plists.is_empty()
        || project.entries_of(FileKind::Entitlements).next().is_some()
        || code_files > 0;
    if !ios_like {
        let why = "not applicable: no Xcode project, Swift package, Info.plist or Swift/Objective-C sources were found";
        result.checks.push(RuleCheck::new(
            "ios.project",
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

    // Настройки конфигурации по (проект, цель, конфигурация).
    let mut settings_of: HashMap<(String, String, String), &BTreeMap<String, String>> =
        HashMap::new();
    for p in &project.projects {
        for t in &p.targets {
            for c in &t.configs {
                settings_of.insert(
                    (p.name.clone(), t.name.clone(), c.name.clone()),
                    &c.settings,
                );
            }
        }
        result.projects.push(ProjectInfo {
            path: p.path.clone(),
            targets: p
                .targets
                .iter()
                .map(|t| {
                    let mut info: Vec<String> = t
                        .configs
                        .iter()
                        .filter_map(|c| c.info_plist.clone())
                        .collect();
                    info.sort();
                    info.dedup();
                    let mut ent: Vec<String> = t
                        .configs
                        .iter()
                        .filter_map(|c| c.entitlements.clone())
                        .collect();
                    ent.sort();
                    ent.dedup();
                    TargetInfo {
                        name: t.name.clone(),
                        kind: t.kind().to_string(),
                        deployment_target: t
                            .configs
                            .iter()
                            .find(|c| !c.debug)
                            .or(t.configs.first())
                            .and_then(|c| c.deployment_target.clone()),
                        info_plists: info,
                        entitlements: ent,
                    }
                })
                .collect(),
        });
    }

    let mut out = RuleOutput::default();
    let mut reasons: HashMap<&'static str, Vec<String>> = HashMap::new();
    let mut code_stats = code::CodeStats::default();
    let mut secret_stats = secret::SecretStats::default();
    let mut ignored_inline = 0usize;
    let mut binary_plists: Vec<(String, FileKind)> = Vec::new();
    let mut has_code = false;
    let mut entitlements_seen = 0usize;
    for entry in &project.entries {
        let path = entry.relative_path.as_str();
        if entry.kind.is_signing() {
            let header = reader.header(entry);
            secret::signing(entry, header.as_deref(), &ignore, &mut out);
            continue;
        }
        if entry.kind == FileKind::GitIgnore {
            continue;
        }
        let owned;
        let text = match project.texts.get(path) {
            Some(t) => t.as_str(),
            None => match reader.read(entry) {
                Content::Text(t) => {
                    owned = t;
                    owned.as_str()
                }
                Content::BinaryPlist => {
                    binary_plists.push((path.to_string(), entry.kind));
                    continue;
                }
                Content::Skipped => continue,
            },
        };
        let before = out.findings.len();
        let mut lexed = None;
        match entry.kind {
            FileKind::Plist | FileKind::Entitlements => {
                let info = entry.kind == FileKind::Plist && project.is_info_plist(path);
                let ent = entry.kind == FileKind::Entitlements;
                let parsed = plist::parse(text);
                let usages: &[super::project::Usage] = if info {
                    project.info_usage.get(path).map_or(&[], Vec::as_slice)
                } else if ent {
                    project
                        .entitlements_usage
                        .get(path)
                        .map_or(&[], Vec::as_slice)
                } else {
                    &[]
                };
                let test_only = if usages.is_empty() {
                    is_test_path(path)
                } else {
                    usages.iter().all(|u| u.test)
                };
                match &parsed {
                    Err(e) if (info || ent) && !test_only => {
                        let rules_for: &[&'static str] = if info {
                            rules::INFO_RULES
                        } else {
                            &[rules::ENTITLEMENTS_ID]
                        };
                        for id in rules_for {
                            push_reason(
                                &mut reasons,
                                id,
                                format!("{}: {}", ui::sanitize_line(path), e.describe()),
                            );
                        }
                    }
                    Ok(p) if (info || ent) && !test_only => {
                        let usages: Vec<super::project::Usage> =
                            usages.iter().filter(|u| !u.test).cloned().collect();
                        let settings: Vec<&BTreeMap<String, String>> = usages
                            .iter()
                            .filter_map(|u| {
                                settings_of
                                    .get(&(u.project.clone(), u.target.clone(), u.config.clone()))
                                    .copied()
                            })
                            .collect();
                        let ctx = plist_rules::Context {
                            path,
                            usages: &usages,
                            settings,
                        };
                        if info {
                            stats.info_plists_checked += 1;
                            plist_rules::info_plist(&p.root, &ctx, &mut out);
                        } else {
                            entitlements_seen += 1;
                            stats.entitlements_checked += 1;
                            plist_rules::entitlements(&p.root, &ctx, &mut out);
                        }
                    }
                    _ => {}
                }
                let hit_lines =
                    secret::check_file(&ignore, entry, text, None, &mut out, &mut secret_stats);
                if let Ok(p) = &parsed
                    && entry.kind == FileKind::Plist
                {
                    let lines: Vec<&str> = text.split('\n').collect();
                    secret::plist_named(
                        entry,
                        &p.root,
                        &ignore,
                        &hit_lines,
                        &lines,
                        &mut out,
                        &mut secret_stats,
                    );
                }
            }
            FileKind::XcConfig => {
                let hit_lines =
                    secret::check_file(&ignore, entry, text, None, &mut out, &mut secret_stats);
                secret::xcconfig_named(
                    entry,
                    text,
                    &ignore,
                    &hit_lines,
                    &mut out,
                    &mut secret_stats,
                );
            }
            FileKind::Swift | FileKind::ObjC => {
                let lang = if entry.kind == FileKind::Swift {
                    Lang::Swift
                } else {
                    Lang::ObjC
                };
                let l = lex::lex(text, lang);
                if is_test_path(path) {
                    stats.test_files_skipped += 1;
                } else if !is_tooling_path(path) {
                    has_code = true;
                    match lang {
                        Lang::Swift => stats.swift_files_checked += 1,
                        Lang::ObjC => stats.objc_files_checked += 1,
                    }
                    code::check(path, text, lang, &l, &mut out, &mut code_stats);
                }
                lexed = Some(l);
                secret::check_file(
                    &ignore,
                    entry,
                    text,
                    lexed.as_ref(),
                    &mut out,
                    &mut secret_stats,
                );
            }
            _ => {
                secret::check_file(&ignore, entry, text, None, &mut out, &mut secret_stats);
            }
        }
        drop(lexed);
        drop_ignored(&mut out.findings, before, text, &mut ignored_inline);
    }
    stats.walk = reader.stats.clone();
    stats.files_scanned_for_secrets = secret_stats.files_scanned;
    stats.ignored_inline = ignored_inline + secret_stats.ignored_inline;
    stats.firebase_config_keys = secret_stats.firebase_config_keys;
    stats.files_with_recoveries = code_stats.files_with_recoveries;
    let skipped_files = reader.skipped.clone();

    // Проверки.
    for (rule, why) in out.partial.drain(..) {
        push_reason(&mut reasons, rule, why);
    }
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
    let mut project_reasons = Vec::new();
    if let Some(w) = &walk_reason {
        project_reasons.push(w.clone());
    }
    for (path, why) in &project.broken {
        project_reasons.push(format!(
            "{} could not be parsed: {}",
            ui::sanitize_line(path),
            ui::sanitize_line(why)
        ));
    }
    let skipped_pbx: Vec<String> = skipped_files
        .iter()
        .filter(|(_, k)| matches!(k, FileKind::Pbxproj | FileKind::XcConfig))
        .map(|(p, _)| p.clone())
        .collect();
    if !skipped_pbx.is_empty() {
        project_reasons.push(format!(
            "project file(s) not read (too large or unreadable): {}",
            listed(&skipped_pbx)
        ));
    }
    let issues: Vec<String> = project
        .projects
        .iter()
        .flat_map(|p| p.issues.iter().cloned())
        .collect();
    if !issues.is_empty() {
        let mut shown: Vec<String> = issues.iter().take(MAX_LISTED).cloned().collect();
        if issues.len() > MAX_LISTED {
            shown.push(format!("and {} more", issues.len() - MAX_LISTED));
        }
        project_reasons.push(shown.join("; "));
    }
    if project.projects.is_empty() && project.broken.is_empty() && !project.generators.is_empty() {
        let names: Vec<String> = project
            .generators
            .iter()
            .map(|(p, what)| format!("{p} ({what})"))
            .collect();
        project_reasons.push(format!(
            "the Xcode project is generated and not committed ({}); generator specs are not parsed, so Info.plist and entitlements were found by file name and their build configurations are unknown",
            listed(&names)
        ));
    }
    result.checks.push(if project_reasons.is_empty() {
        RuleCheck::new("ios.project", CheckStatus::Completed, None)
    } else {
        RuleCheck::new(
            "ios.project",
            CheckStatus::Partial,
            Some(project_reasons.join("; ")),
        )
    });
    for (path, kind) in &binary_plists {
        let rules_for: Vec<&'static str> = match kind {
            FileKind::Entitlements => vec![rules::ENTITLEMENTS_ID, rules::SECRET_ID],
            _ if project.is_info_plist(path) => {
                vec![rules::ATS_ID, rules::URLSCHEME_ID, rules::SECRET_ID]
            }
            _ => vec![rules::SECRET_ID],
        };
        for id in rules_for {
            push_reason(
                &mut reasons,
                id,
                format!(
                    "{}: binary property list (bplist00) is not parsed",
                    ui::sanitize_line(path)
                ),
            );
        }
    }
    if !secret_stats.capped.is_empty() {
        push_reason(
            &mut reasons,
            rules::SECRET_ID,
            format!(
                "more than {} matches in {}; the rest was not analysed",
                rules::MAX_HITS_PER_FILE,
                listed(&secret_stats.capped)
            ),
        );
    }
    if !code_stats.capped.is_empty() {
        for id in rules::CODE_RULES {
            push_reason(
                &mut reasons,
                id,
                format!(
                    "more than {} code findings in {}; the rest was dropped",
                    rules::MAX_HITS_PER_FILE,
                    listed(&code_stats.capped)
                ),
            );
        }
    }
    let skipped_for = |rule: &str| -> Option<String> {
        let code_rule = rules::CODE_RULES.contains(&rule);
        let paths: Vec<String> = skipped_files
            .iter()
            .filter(|(path, kind)| match kind {
                FileKind::Swift | FileKind::ObjC => code_rule || rule == rules::SECRET_ID,
                FileKind::Plist if project.is_info_plist(path) => {
                    rules::INFO_RULES.contains(&rule) || rule == rules::SECRET_ID
                }
                FileKind::Entitlements => {
                    rule == rules::ENTITLEMENTS_ID || rule == rules::SECRET_ID
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
    let any_info = !info_plists.is_empty();
    for id in rules::ALL {
        let skip = if rules::INFO_RULES.contains(id) && !any_info {
            Some("not applicable: no Info.plist file was found")
        } else if rules::INFO_RULES.contains(id)
            && stats.info_plists_checked == 0
            && reasons.get(id).is_none_or(Vec::is_empty)
            && binary_plists.is_empty()
        {
            Some("not applicable: only Info.plist files of test targets were found")
        } else if *id == rules::ENTITLEMENTS_ID
            && project.entries_of(FileKind::Entitlements).next().is_none()
        {
            Some("not applicable: no .entitlements file was found")
        } else if *id == rules::ENTITLEMENTS_ID
            && entitlements_seen == 0
            && reasons.get(id).is_none_or(Vec::is_empty)
            && binary_plists.is_empty()
        {
            Some("not applicable: only entitlements of test targets were found")
        } else if rules::CODE_RULES.contains(id) && !has_code {
            Some(
                "not applicable: no Swift/Objective-C app sources were found (test and tooling files are not checked)",
            )
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

    // Ограничения по факту.
    if stats.test_files_skipped > 0 {
        result.limitations.push(format!(
            "{} Swift/Objective-C file(s) in test folders were not checked for code patterns",
            stats.test_files_skipped
        ));
    }
    if stats.firebase_config_keys > 0 {
        result.limitations.push(format!(
            "{} Google API key(s) in GoogleService-Info.plist were not reported: Firebase client keys are public identifiers by design (restrict them in the Google Cloud console)",
            stats.firebase_config_keys
        ));
    }
    if stats.files_with_recoveries > 0 {
        result.limitations.push(format!(
            "{} Swift/Objective-C file(s) have unterminated strings or comments; their code patterns were matched approximately",
            stats.files_with_recoveries
        ));
    }
    if stats.walk.skipped_binary > 0 {
        result.limitations.push(format!(
            "{} binary file(s) with a source extension were skipped",
            stats.walk.skipped_binary
        ));
    }
    if project.has_package_swift {
        result.limitations.push(
            "Package.swift manifests are recognised but not evaluated (dependencies and their versions are not checked here)"
                .to_string(),
        );
    }
    if !project.generators.is_empty() && !project.projects.is_empty() {
        let names: Vec<String> = project.generators.iter().map(|(p, _)| p.clone()).collect();
        result.limitations.push(format!(
            "project generator spec(s) {} are not parsed; the committed project.pbxproj was used",
            listed(&names)
        ));
    }
    if project.projects.is_empty() && project.broken.is_empty() && any_info {
        result.limitations.push(
            "no project.pbxproj was found: Info.plist and entitlements were found by file name, so which build configuration (debug/release) uses them is unknown"
                .to_string(),
        );
    }
    let mut seen = std::collections::HashSet::new();
    result.limitations.retain(|l| seen.insert(l.clone()));

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
