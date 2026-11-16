//! Web Source Audit (Next.js / React): локальная статическая проверка исходников.
//! Владелец — агент «Сканеры», см. `docs/architecture/CONTRACTS_V2.md`.
//!
//! Никогда не исполняет код проекта, не запускает npm/node/сборку, не ходит в сеть.
//! Точка входа — [`scan_source`]; соответствие контракту FindingV2 — в `HANDOFF_WEB.md`.

pub mod cli;
pub mod enumerate;
pub mod framework;
pub mod lexer;
pub mod location;
pub mod project;
pub mod provenance;
pub mod report;
pub mod rules;
pub mod sql;
pub mod types;

#[cfg(test)]
pub(crate) mod testutil;

pub use enumerate::{Budgets, EnumStats};
pub use framework::{FrameworkInfo, FrameworkKind, Manifest};
pub use types::{
    CheckStatus, Confidence, Evidence, RuleCheck, Severity, SourceLocation, WebFinding,
};

use crate::ui;
use std::path::Path;

/// Сколько путей перечислять в одном limitation (W6).
pub const MAX_LISTED_PATHS: usize = 5;

/// Версия схемы результата (контракт V2).
pub const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Default)]
pub struct WebScanOptions {
    pub budgets: Budgets,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WebScanStats {
    pub walk: EnumStats,
    /// Сколько раз токенайзер восстанавливался после незакрытой строки/комментария.
    pub lexer_recoveries: usize,
    /// Файлов с восстановлением — их разметка приблизительна.
    pub files_with_recoveries: usize,
    /// Первые такие файлы (не больше `MAX_LISTED_PATHS`) — чтобы было видно, где разметка приблизительна.
    pub recovery_paths: Vec<String>,
    /// Находки, подавленные `jetscan:ignore`.
    pub ignored_inline: usize,
}

#[derive(Clone, Debug)]
pub struct WebScanResult {
    pub schema_version: u32,
    pub framework: FrameworkInfo,
    /// Отсортированы по (путь, строка, колонка, правило).
    pub findings: Vec<WebFinding>,
    pub checks: Vec<RuleCheck>,
    pub limitations: Vec<String>,
    pub stats: WebScanStats,
    /// Сетевых действий нет и не бывает: поле — для контракта (`network_activities`).
    pub network_activities: Vec<String>,
}

impl WebScanResult {
    /// Скан полный: ни одна проверка не `partial`/`error`.
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

/// Правила, которые есть в каталоге, но в этой версии не реализованы. Отдаются как
/// `skipped` с причиной, чтобы отсутствие находок не читалось как «проверено, чисто».
const NOT_IMPLEMENTED: &[&str] = &["WEB-DEPS-008"];

/// Сканирует веб-проект в каталоге `root`. Ошибка — только если корень не открыть;
/// всё остальное (битый манифест, бюджеты, неподдержанный синтаксис) — в `checks`/`limitations`.
pub fn scan_source(root: &Path, options: &WebScanOptions) -> Result<WebScanResult, String> {
    let framework = framework::detect(root);
    let mut findings = Vec::new();
    let mut stats = WebScanStats::default();
    let mut rule_stats = rules::RuleStats::default();
    let mut env = rules::env::EnvCollector::default();
    let mut auth = rules::auth::AuthCollector::default();
    let mut project = project::Project::new(root);
    let mut xss_pending: Vec<rules::xss::Pending> = Vec::new();
    let mut rls = rules::rls::RlsCollector::default();
    let mut firebase = rules::firebase::FirebaseCollector::default();

    let walk = enumerate::enumerate(root, &options.budgets, &mut |file| {
        match file.kind {
            enumerate::FileKind::Sql => return rls.sql_file(&file.relative_path, &file.text),
            enumerate::FileKind::SupabaseConfig => {
                return rls.config_file(&file.relative_path, &file.text);
            }
            enumerate::FileKind::FirebaseRules => {
                return firebase.rules_file(&file.relative_path, &file.text);
            }
            enumerate::FileKind::FirebaseDatabaseRules => {
                return firebase.database_file(&file.relative_path, &file.text);
            }
            enumerate::FileKind::FirebaseConfig => {
                return firebase.config_file(&file.relative_path, &file.text);
            }
            _ => {}
        }
        if file.kind == enumerate::FileKind::Env {
            let is_supabase = |value: &str| rules::supabase::classify_value(value).is_some();
            env.env_file(&file.relative_path, &file.text, &framework, &is_supabase);
            rules::supabase::env_file(
                &file.relative_path,
                &file.text,
                &framework,
                &mut findings,
                &mut rule_stats.ignored_inline,
            );
            return;
        }
        let ctx = rules::FileContext::new(&file.relative_path, file.kind, &file.text, &framework);
        if ctx.lexed.recovered > 0 {
            stats.lexer_recoveries += ctx.lexed.recovered;
            stats.files_with_recoveries += 1;
            if stats.recovery_paths.len() < MAX_LISTED_PATHS {
                stats.recovery_paths.push(ui::sanitize_line(ctx.path));
            }
        }
        rules::secret::check(&ctx, &mut findings, &mut rule_stats);
        rules::supabase::check(&ctx, &mut findings, &mut rule_stats);
        rules::xss::check(&ctx, &mut xss_pending, &mut rule_stats);
        rules::cors::check(&ctx, &mut findings, &mut rule_stats.ignored_inline);
        rules::debug::check(&ctx, &mut findings, &mut rule_stats.ignored_inline);
        auth.file(&ctx, &mut rule_stats.ignored_inline);
        if ctx.kind == enumerate::FileKind::Script {
            let imports = project::import_bindings(ctx.text, &ctx.lexed);
            project.add(
                ctx.path,
                project::FileFacts {
                    reach: ctx.reach,
                    auth_signal: rules::auth::file_has_auth_signal(&ctx),
                    sanitizer: rules::xss::file_uses_sanitizer(&ctx, &imports),
                    imports,
                },
            );
        }
        env.source_file(&ctx);
    })?;
    stats.walk = walk;
    let rls = rls.finish(framework.uses_supabase);
    let firebase = firebase.finish();
    stats.ignored_inline = rule_stats.ignored_inline
        + env.ignored_inline
        + rls.ignored_inline
        + firebase.ignored_inline;
    findings.extend(rls.findings.iter().cloned());
    findings.extend(firebase.findings.iter().cloned());
    findings.extend(env.finish(&framework));
    let (auth_findings, auth_partial) = auth.finish(&project);
    findings.extend(rules::xss::finish(xss_pending, &project));
    describe_importers(&mut findings, &project);
    findings.extend(auth_findings);

    findings.sort_by(|a, b| (&a.location, a.rule_id, &a.id).cmp(&(&b.location, b.rule_id, &b.id)));

    let mut limitations = vec![
        "static analysis only: nothing was built or executed, so bundling of a file is inferred \
         from framework rules, not proven"
            .to_string(),
        "built output (.next, dist, out, build) is not scanned".to_string(),
    ];
    limitations.extend(framework.notes.iter().cloned());

    let walk_reason = walk_incomplete_reason(&stats.walk);
    let mut checks = vec![RuleCheck::new(
        "web.discovery",
        match framework.manifest {
            Manifest::Found | Manifest::Missing => CheckStatus::Completed,
            Manifest::Unreadable(_) | Manifest::Invalid(_) => CheckStatus::Partial,
        },
        match &framework.manifest {
            Manifest::Unreadable(why) | Manifest::Invalid(why) => {
                Some(format!("package.json: {why}"))
            }
            _ => None,
        },
    )];
    if stats.walk.skipped_unsupported > 0 {
        limitations.push(format!(
            "{} Vue/Svelte/Astro file(s) not checked: syntax not supported",
            stats.walk.skipped_unsupported
        ));
    }
    if stats.files_with_recoveries > 0 {
        let more = stats.files_with_recoveries - stats.recovery_paths.len();
        limitations.push(format!(
            "{} file(s) had unterminated strings/comments; their comment/string boundaries are approximate: {}{}",
            stats.files_with_recoveries,
            stats.recovery_paths.join(", "),
            if more > 0 { format!(" and {more} more") } else { String::new() }
        ));
    }
    for id in [
        rules::secret::RULE_ID,
        rules::env::RULE_ID,
        rules::supabase::RULE_ID,
        rules::xss::RULE_ID,
        rules::auth::RULE_ID,
        rules::cors::RULE_ID,
        rules::debug::RULE_ID,
    ] {
        let capped: Vec<&String> = rule_stats
            .capped
            .iter()
            .filter(|(rule, _)| *rule == id)
            .map(|(_, path)| path)
            .collect();
        // Правило, которое для этого фреймворка не запускалось, — `skipped`, а не «completed»
        // (полевой тест 2026-11-12, W3).
        if id == rules::auth::RULE_ID && framework.kind != FrameworkKind::NextJs {
            checks.push(RuleCheck::new(
                id,
                CheckStatus::Skipped,
                Some(format!(
                    "not_applicable: framework is {}; this rule only understands Next.js route handlers, pages/api and Server Actions",
                    framework.kind.label()
                )),
            ));
            continue;
        }
        let mut reasons: Vec<String> = walk_reason.iter().cloned().collect();
        if id == rules::auth::RULE_ID {
            reasons.extend(auth_partial.iter().cloned());
        }
        if let Some(first) = capped.first() {
            reasons.push(format!(
                "more than {} matches in {} file(s) (e.g. {}); the rest of those files was not analysed",
                rules::MAX_HITS_PER_FILE,
                capped.len(),
                ui::sanitize_line(first)
            ));
        }
        let status = if reasons.is_empty() {
            CheckStatus::Completed
        } else {
            CheckStatus::Partial
        };
        let reason = (!reasons.is_empty()).then(|| reasons.join("; "));
        checks.push(RuleCheck::new(id, status, reason));
    }
    let supabase_used = framework.uses_supabase
        || rls.files > 0
        || findings
            .iter()
            .any(|f| f.rule_id == rules::supabase::RULE_ID);
    checks.push(rls_check(
        &rls,
        supabase_used,
        &walk_reason,
        &mut limitations,
    ));
    checks.push(firebase_check(
        &firebase,
        framework.uses_firebase,
        &walk_reason,
        &mut limitations,
    ));
    for id in NOT_IMPLEMENTED {
        checks.push(RuleCheck::new(
            id,
            CheckStatus::Skipped,
            Some("not implemented in this version".to_string()),
        ));
    }

    Ok(WebScanResult {
        schema_version: SCHEMA_VERSION,
        framework,
        findings,
        checks,
        limitations,
        stats,
        network_activities: Vec::new(),
    })
}

/// Находки SECRET-001 / SUPABASE-005 в модуле без границы клиент/сервер: кто его импортирует.
/// Заголовок говорит ровно то, что видно (полевой тест 2026-11-12, паттерн 10): «модуль без границы»,
/// а не «клиентский код»; если импортируют только серверные файлы — `info` и совет `server-only`.
fn describe_importers(findings: &mut [WebFinding], project: &project::Project) {
    for f in findings.iter_mut() {
        let shared = f.tags.iter().any(|t| t == "reach:shared");
        if !shared || !matches!(f.rule_id, "WEB-SECRET-001" | "WEB-SUPABASE-005") {
            continue;
        }
        let importers = project.importers(&f.location.relative_path);
        let list = |filter: &dyn Fn(provenance::Reach) -> bool| -> Vec<String> {
            importers
                .iter()
                .filter(|(_, r)| filter(*r))
                .map(|(p, _)| ui::sanitize_line(p))
                .take(MAX_LISTED_PATHS)
                .collect()
        };
        let client =
            list(&|r| matches!(r, provenance::Reach::Client(_) | provenance::Reach::Shared));
        let server = list(&|r| matches!(r, provenance::Reach::Server(_) | provenance::Reach::Test));
        f.title = f
            .title
            .replace(
                "Client-reachable code reads",
                "Module without a client/server boundary reads",
            )
            .replace(
                "in client-reachable code",
                "in a module without a client/server boundary",
            );
        if importers.is_empty() {
            f.title.push_str(" (no importer found)");
            f.explanation
                .push_str(" No file in the scanned source imports this module.");
        } else if client.is_empty() {
            // Раунд 2, N4: старое начало объяснения («клиентский код… в браузере») здесь противоречит
            // выводу — объяснение пишется заново, из того, что действительно видно.
            let subject = f.title.clone();
            f.title.push_str(" (imported only by server code)");
            f.severity = Severity::Info;
            f.confidence = Confidence::NeedsReview;
            let repo = if f.evidence.fingerprint.is_some() {
                " The value itself is still committed to the repository; `jetscan secrets` reports it \
                 as a leaked secret."
            } else {
                ""
            };
            f.explanation = format!(
                "{subject}. The module has neither 'use client' nor 'server-only', so the file alone \
                 does not say where it runs. It is imported only by server-side files ({}), so it does \
                 not reach the browser today. Add `import \"server-only\"` to the module so that a \
                 future client import fails the build instead of shipping it.{repo}",
                server.join(", ")
            );
            f.tags.push("importers:server-only".to_string());
        } else {
            f.title.push_str(&format!(
                " (imported by client or shared code: {})",
                client.join(", ")
            ));
            f.explanation.push_str(&format!(
                " Imported by client or shared code: {}.",
                client.join(", ")
            ));
            f.tags.push("importers:client".to_string());
        }
    }
}

/// Проверка WEB-RLS-009: `completed`, когда SQL-схема разобрана; иначе `skipped` с причиной и
/// подсказкой, как выгрузить схему.
fn rls_check(
    rls: &rules::rls::RlsOutcome,
    supabase_used: bool,
    walk_reason: &Option<String>,
    limitations: &mut Vec<String>,
) -> RuleCheck {
    let id = rules::rls::RULE_ID;
    if rls.files == 0 {
        if !supabase_used {
            return RuleCheck::new(
                id,
                CheckStatus::Skipped,
                Some("not_applicable: no Supabase client or Supabase SQL schema found".to_string()),
            );
        }
        limitations.push(
            "Supabase Row Level Security was not verified: anon/publishable keys are safe only if RLS policies protect every exposed table"
                .to_string(),
        );
        return RuleCheck::new(
            id,
            CheckStatus::Skipped,
            Some(format!(
                "not_checked: no SQL schema in the repository (supabase/migrations/*.sql, supabase/schema.sql); export it with `{}` and scan again",
                rules::rls::DUMP_HINT
            )),
        );
    }
    limitations.push(format!(
        "{id}: {} SQL file(s) with {} statement(s) analysed in migration order; Row Level Security or policies changed in the Supabase dashboard, or by SQL that is not in the repository, are not seen. API-exposed schemas assumed: {}",
        rls.files,
        rls.statements,
        if rls.exposed.is_empty() {
            "none (Data API disabled in config.toml)".to_string()
        } else {
            rls.exposed.join(", ")
        }
    ));
    limitations.push(format!(
        "{id}: anon/authenticated are assumed to have Supabase's default privileges on new tables unless the SQL revokes them; projects with automatic Data API exposure turned off grant less, so a table without RLS there may not be reachable"
    ));
    if !rls.unknown.is_empty() {
        let total: usize = rls.unknown.values().sum();
        let mut kinds: Vec<(&String, &usize)> = rls.unknown.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let sample: Vec<String> = kinds
            .iter()
            .take(MAX_LISTED_PATHS)
            .map(|(k, n)| format!("{k} ×{n}"))
            .collect();
        limitations.push(format!(
            "{id}: {total} SQL statement(s) were not understood, and their effect on RLS is not modelled: {}",
            sample.join(", ")
        ));
    }
    if rls.dynamic_rls {
        limitations.push(format!(
            "{id}: a DO block, function body or event trigger mentions row level security; dynamic SQL is not evaluated, so tables without RLS are reported as needs_review"
        ));
    }
    let mut reasons: Vec<String> = walk_reason.iter().cloned().collect();
    if !rls.unterminated.is_empty() {
        reasons.push(format!(
            "{} SQL file(s) have an unterminated string, comment or $$ body, so the rest of each was not analysed: {}",
            rls.unterminated.len(),
            rls.unterminated
                .iter()
                .take(MAX_LISTED_PATHS)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if reasons.is_empty() {
        RuleCheck::new(id, CheckStatus::Completed, None)
    } else {
        RuleCheck::new(id, CheckStatus::Partial, Some(reasons.join("; ")))
    }
}

/// Проверка WEB-FIREBASE-010: `completed`, когда файлы правил разобраны.
fn firebase_check(
    fb: &rules::firebase::FirebaseOutcome,
    uses_firebase: bool,
    walk_reason: &Option<String>,
    limitations: &mut Vec<String>,
) -> RuleCheck {
    let id = rules::firebase::RULE_ID;
    if !fb.missing.is_empty() {
        limitations.push(format!(
            "{id}: firebase.json points to rules file(s) that were not analysed (missing, outside the scan or not named *.rules / *.rules.json): {}",
            fb.missing
                .iter()
                .take(MAX_LISTED_PATHS)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if fb.files == 0 {
        if !uses_firebase {
            return RuleCheck::new(
                id,
                CheckStatus::Skipped,
                Some(
                    "not_applicable: no Firebase SDK, firebase.json or rules file found"
                        .to_string(),
                ),
            );
        }
        limitations.push(
            "Firebase security rules were not verified: the web config (apiKey) is public by design, so only Firestore/Storage/Realtime Database rules protect the data"
                .to_string(),
        );
        return RuleCheck::new(
            id,
            CheckStatus::Skipped,
            Some(
                "not_checked: no firestore.rules, storage.rules or database.rules.json in the repository; copy the deployed rules from the Firebase console into those files (as firebase.json references them) and scan again"
                    .to_string(),
            ),
        );
    }
    limitations.push(format!(
        "{id}: {} rules file(s) analysed; rules deployed from the Firebase console, rules that depend on stored data (get()/exists()) and functions with parameters are not evaluated",
        fb.files
    ));
    let mut reasons: Vec<String> = walk_reason.iter().cloned().collect();
    if !fb.broken.is_empty() {
        reasons.push(format!(
            "{} rules file(s) could not be parsed to the end: {}",
            fb.broken.len(),
            fb.broken
                .iter()
                .take(MAX_LISTED_PATHS)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if reasons.is_empty() {
        RuleCheck::new(id, CheckStatus::Completed, None)
    } else {
        RuleCheck::new(id, CheckStatus::Partial, Some(reasons.join("; ")))
    }
}

fn walk_incomplete_reason(walk: &EnumStats) -> Option<String> {
    let mut parts = Vec::new();
    if walk.budget_exhausted {
        parts.push("scan budget exhausted (files/bytes)".to_string());
    }
    if walk.skipped_large > 0 {
        parts.push(format!(
            "{} file(s) over the size limit",
            walk.skipped_large
        ));
    }
    if walk.skipped_unreadable > 0 {
        parts.push(format!("{} unreadable path(s)", walk.skipped_unreadable));
    }
    if walk.outside_root_skipped > 0 {
        parts.push(format!(
            "{} directory(ies) resolving outside the root",
            walk.outside_root_skipped
        ));
    }
    if walk.depth_limited > 0 {
        parts.push(format!(
            "{} directory(ies) over the depth limit",
            walk.depth_limited
        ));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;
