//! WEB-DEBUG-007: публичные source maps в продакшен-сборке по конфигу. `low`/`potential`.
//!
//! Source map раскрывает исходный код (с комментариями и путями) любому, кто откроет DevTools.
//! Само по себе это не секрет и не уязвимость — но облегчает анализ и иногда выдаёт то, что
//! прятали. Проверяем только конфиги, артефакты сборки не читаем:
//! - `next.config.*`: `productionBrowserSourceMaps: true` (Next.js отдаёт `.map` из `/_next/static`);
//! - `vite.config.*`: `sourcemap: true` или `sourcemap: "inline"` (`"hidden"` — не находка:
//!   файлы создаются, но бандл на них не ссылается).
//!
//! Не проверяется: загружает ли хостинг `.map` наружу, `devtool` в webpack-конфигах, флаги отладки
//! в коде — без сборки и рантайма это не определить надёжно.

use super::FileContext;
use super::xss::skip_ws;
use crate::web_audit::lexer::{self, plain_string};
use crate::web_audit::location::redacted_line;
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};

pub const RULE_ID: &str = "WEB-DEBUG-007";

pub const REFERENCES: &[&str] = &[
    "https://cwe.mitre.org/data/definitions/540.html",
    "https://vite.dev/config/build-options",
];

/// Значение после `name:` — `true` или строковый литерал.
fn value_after(ctx: &FileContext, at: usize, name: &str) -> Option<String> {
    let b = ctx.text.as_bytes();
    let after = at + name.len();
    if b.get(after)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
    {
        return None;
    }
    let colon = skip_ws(b, after);
    if b.get(colon) != Some(&b':') {
        return None;
    }
    let v = skip_ws(b, colon + 1);
    if ctx.text[v..].starts_with("true")
        && !b
            .get(v + 4)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
    {
        return Some("true".to_string());
    }
    let literal = ctx.lexed.literal_at(v).filter(|l| l.start == v)?;
    plain_string(ctx.text, literal)
}

pub fn check(ctx: &FileContext, findings: &mut Vec<WebFinding>, ignored: &mut usize) {
    if ctx.kind != crate::web_audit::enumerate::FileKind::Script {
        return;
    }
    let name = ctx.path.rsplit('/').next().unwrap_or(ctx.path);
    let (option, accepts): (&str, fn(&str) -> bool) = if name.starts_with("next.config.") {
        ("productionBrowserSourceMaps", |v| v == "true")
    } else if name.starts_with("vite.config.") {
        ("sourcemap", |v| v == "true" || v == "inline")
    } else {
        return;
    };
    for at in lexer::code_occurrences(ctx.text, &ctx.lexed, option) {
        let Some(value) = value_after(ctx, at, option) else {
            continue;
        };
        if !accepts(&value) {
            continue;
        }
        let Some((line, col)) = ctx.index.line_col(ctx.text, at) else {
            continue;
        };
        if ctx.line_ignored(line as usize) {
            *ignored += 1;
            continue;
        }
        findings.push(WebFinding {
            id: finding_id(RULE_ID, ctx.path, option),
            rule_id: RULE_ID,
            title: "Production build publishes browser source maps".to_string(),
            category: "information_disclosure",
            severity: Severity::Low,
            confidence: Confidence::Potential,
            location: SourceLocation {
                relative_path: ctx.path.to_string(),
                line: Some(line),
                column: Some(col),
            },
            evidence: Evidence {
                redacted_excerpt: Some(redacted_line(ctx.text, &ctx.lexed, &ctx.index, at)),
                fingerprint: None,
            },
            explanation: format!(
                "{option} is enabled, so the production build emits source maps that the browser \
                 can download: the original source, comments included, becomes readable. Not a \
                 vulnerability by itself; whether the .map files are actually served depends on \
                 hosting. Turn it off, or use 'hidden' maps uploaded only to your error tracker."
            ),
            remediation_id: Some(format!("{RULE_ID}:disable-public-source-maps")),
            references: REFERENCES.to_vec(),
            cwe_ids: vec!["CWE-540"],
            tags: vec![
                "web".to_string(),
                ctx.framework.kind.label().to_string(),
                "config".to_string(),
            ],
        });
    }
}
