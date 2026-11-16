//! WEB-SECRET-001: привилегированный ключ в коде, который может попасть в браузер.
//!
//! Формат ключа определяют матчеры ядра (`secrets::rules`) — здесь их не дублируем.
//! Своё здесь — только «куда этот файл попадёт»:
//! - комментарии вырезаны до поиска (в бандл не идут);
//! - серверные модули (`"use server"`, `server-only`, route handlers, `pages/api`,
//!   `getServerSideProps`, конфиги) и тесты — не находка этого правила
//!   (ключ там всё равно найдёт `jetscan secrets`: это утечка в репозиторий, а не в браузер);
//! - публичные по замыслу ключи не считаются привилегированными: Google/Firebase `AIza…`
//!   (браузерный ключ, ограничивается в консоли), Stripe `pk_…`, Supabase anon/publishable
//!   (последние ядро и не ищет; Supabase service-role — правило WEB-SUPABASE-005).

use super::{FileContext, RuleStats};
use crate::secrets::{self, rules};
use crate::web_audit::location::code_excerpt;
use crate::web_audit::provenance::Reach;
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};

pub const RULE_ID: &str = "WEB-SECRET-001";

/// Правила ядра, чьи значения публичны по замыслу и в клиентском коде сами по себе — норма.
const PUBLIC_BY_DESIGN: &[&str] = &["google-api"];

pub const REFERENCES: &[&str] = &[
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://react.dev/reference/rsc/use-client",
    "https://vite.dev/guide/env-and-mode",
];

/// Минимум символов base64 в теле PEM, чтобы считать его ключом (самый короткий реальный —
/// ключ Ed25519 в PKCS#8 — 64 символа base64).
pub const PEM_MIN_BODY: usize = 64;

/// После заголовка `-----BEGIN … PRIVATE KEY-----` (в начале `text`) до `-----END` или конца есть
/// тело base64 длиной не меньше [`PEM_MIN_BODY`]. Между символами тела допускаются пробелы,
/// переводы строк, экранирование `\n` и склейка литералов (`" + "`); любой другой символ (`;`, `)`,
/// код) — конец тела. Строка, где есть только заголовок, — это разбор/сборка PEM, а не ключ.
pub fn has_pem_body(text: &str) -> bool {
    let Some(first) = text.find("-----") else {
        return false;
    };
    let Some(second) = text[first + 5..].find("-----") else {
        return false;
    };
    let rest = &text[first + 5 + second + 5..];
    let body = rest.find("-----END").map_or(rest, |end| &rest[..end]);
    let mut count = 0;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_alphanumeric() || c == '/' || c == '=' {
            count += 1;
            if count >= PEM_MIN_BODY {
                return true;
            }
        } else if c == '\\' {
            // Экранирование `\n` / `\r` внутри литерала.
            if !matches!(chars.next(), Some('n' | 'r')) {
                return false;
            }
        } else if !(c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '+')) {
            return false;
        }
    }
    false
}

pub fn check(ctx: &FileContext, findings: &mut Vec<WebFinding>, stats: &mut RuleStats) {
    let (severity, confidence, where_) = match ctx.reach {
        Reach::Client(reason) => (Severity::Critical, Confidence::Potential, reason),
        Reach::Shared => (
            Severity::High,
            Confidence::NeedsReview,
            "module has no visible client/server boundary and may be imported by client code",
        ),
        Reach::Server(_) | Reach::Test => return,
    };
    let hits = secrets::scan_text(rules::all(), &ctx.stripped);
    stats.note_cap(RULE_ID, ctx.path, hits.len());
    for hit in hits.into_iter().take(super::MAX_HITS_PER_FILE) {
        if PUBLIC_BY_DESIGN.contains(&hit.rule.id) || rules::is_placeholder(&hit.secret) {
            continue;
        }
        let Some(start) = ctx.index.byte_at(ctx.text, hit.line, hit.col) else {
            continue;
        };
        let end = start + hit.secret.len();
        // Комментарии в `stripped` — пробелы, поэтому найденное обязано совпасть с исходником.
        if ctx.text.get(start..end) != Some(hit.secret.as_str()) || ctx.in_server_range(start) {
            continue;
        }
        // Строка-заголовок PEM без тела (строка «BEGIN … PRIVATE KEY» для разбора/склейки PEM) — не ключ.
        if hit.rule.id == "private-key" && !has_pem_body(&ctx.text[start..]) {
            continue;
        }
        if ctx.line_ignored(hit.line) {
            stats.ignored_inline += 1;
            continue;
        }
        let masked = secrets::mask(&hit.secret);
        let fingerprint = secrets::fingerprint(&hit.secret);
        let excerpt = code_excerpt(ctx.text, &ctx.lexed, &ctx.index, start, end, &masked);
        let (title, explanation) = match ctx.reach {
            Reach::Client(_) => (
                format!("{} in client-side code", hit.rule.name),
                format!(
                    "A value in the format of a {} appears in a file that is shipped to the browser ({where_}). \
                     Anyone who opens the site can read it from the JavaScript bundle. \
                     Static analysis cannot prove the file is actually imported; treat the key as exposed if it is.",
                    hit.rule.name
                ),
            ),
            _ => (
                format!(
                    "{} in a module without a client/server boundary",
                    hit.rule.name
                ),
                format!(
                    "A value in the format of a {} appears in a module that is neither marked \
                     'use client' nor server-only ({where_}). Check who imports it.",
                    hit.rule.name
                ),
            ),
        };
        findings.push(WebFinding {
            id: finding_id(RULE_ID, ctx.path, &fingerprint),
            rule_id: RULE_ID,
            title,
            category: "secret_exposure",
            severity,
            confidence,
            location: SourceLocation {
                relative_path: ctx.path.to_string(),
                line: u32::try_from(hit.line).ok(),
                column: u32::try_from(hit.col).ok(),
            },
            evidence: Evidence {
                redacted_excerpt: Some(excerpt),
                fingerprint: Some(fingerprint),
            },
            explanation,
            remediation_id: Some(format!("{RULE_ID}:move-to-server")),
            references: REFERENCES.to_vec(),
            cwe_ids: vec!["CWE-798", "CWE-200"],
            tags: vec![
                "web".to_string(),
                ctx.framework.kind.label().to_string(),
                format!("reach:{}", ctx.reach.label()),
                format!("key:{}", hit.rule.id),
            ],
        });
    }
}
