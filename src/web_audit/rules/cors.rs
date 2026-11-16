//! WEB-CORS-006: CORS, который пускает любой сайт с куками/credentials.
//!
//! Опасная пара — **отражение** `Origin` запроса в `Access-Control-Allow-Origin` вместе с
//! `Access-Control-Allow-Credentials: true`: тогда любой сайт читает ответы от имени вошедшего
//! пользователя. Литерал `*` вместе с credentials браузеры не принимают (запрос падает) — это
//! сломанная настройка, а не утечка, но её часто «чинят» отражением Origin; поэтому `low`/`needs_review`.
//!
//! Формы, которые распознаём (в одном файле):
//! - заголовки: `setHeader("Access-Control-Allow-Origin", X)`, `headers.set(...)`, объект
//!   `{ "Access-Control-Allow-Origin": X }`, `next.config` `{ key: "...", value: X }`;
//! - пакет `cors`: `cors({ origin: true, credentials: true })` и `origin: (o, cb) => cb(null, true)`.
//!
//! Отражение = в выражении значения видно `origin` из заголовков запроса
//! (`req.headers.origin`, `request.headers.get("origin")`). Переменная `origin`, прошедшая
//! проверку по списку, отражением не считается (мы её не видим) — так меньше шума, но возможен пропуск.
//! `*` без credentials (публичный API) — не находка.

use super::FileContext;
use super::xss::{expression_end, skip_ws};
use crate::web_audit::lexer::{self, Class, plain_string};
use crate::web_audit::location::redacted_line;
use crate::web_audit::provenance::Reach;
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};

pub const RULE_ID: &str = "WEB-CORS-006";

/// Origin и Credentials считаются одной настройкой, если между ними не больше стольких строк.
const PAIR_LINES: u32 = 5;

pub const REFERENCES: &[&str] = &[
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    "https://cwe.mitre.org/data/definitions/942.html",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Star,
    Reflect,
    Other,
}

/// Код выражения без литералов, в нижнем регистре и без пробелов.
fn code_of(ctx: &FileContext, start: usize, end: usize) -> String {
    let b = ctx.text.as_bytes();
    (start..end)
        .filter(|&i| ctx.lexed.class_at(i) == Class::Code && !b[i].is_ascii_whitespace())
        .map(|i| b[i].to_ascii_lowercase() as char)
        .collect()
}

/// Полный текст выражения (с литералами) в нижнем регистре без пробелов.
fn text_of(ctx: &FileContext, start: usize, end: usize) -> String {
    ctx.text[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Начало значения для литерала-имени заголовка, заканчивающегося в `after`.
fn value_start(ctx: &FileContext, after: usize) -> Option<usize> {
    let b = ctx.text.as_bytes();
    let i = skip_ws(b, after);
    match b.get(i)? {
        b':' => Some(skip_ws(b, i + 1)),
        b',' => {
            let j = skip_ws(b, i + 1);
            // next.config: `{ key: "...", value: X }`
            if ctx.text[j..].starts_with("value") {
                let k = skip_ws(b, j + "value".len());
                if b.get(k) == Some(&b':') {
                    return Some(skip_ws(b, k + 1));
                }
            }
            Some(j)
        }
        _ => None,
    }
}

fn classify_origin(ctx: &FileContext, start: usize, end: usize) -> Origin {
    if let Some(literal) = ctx.lexed.literal_at(start)
        && literal.start == start
        && plain_string(ctx.text, literal).as_deref() == Some("*")
    {
        return Origin::Star;
    }
    let code = code_of(ctx, start, end);
    let text = text_of(ctx, start, end);
    let reflects = code.contains("headers.origin")
        || (code.contains("headers") && text.contains("get(\"origin\")"))
        || (code.contains("headers") && text.contains("get('origin')"));
    if reflects {
        Origin::Reflect
    } else {
        Origin::Other
    }
}

fn is_true(ctx: &FileContext, start: usize, end: usize) -> bool {
    matches!(
        text_of(ctx, start, end).as_str(),
        "true" | "\"true\"" | "'true'" | "`true`"
    )
}

pub fn check(ctx: &FileContext, findings: &mut Vec<WebFinding>, ignored: &mut usize) {
    if ctx.kind != crate::web_audit::enumerate::FileKind::Script || ctx.reach == Reach::Test {
        return;
    }
    // Заголовки считаются парой, только если стоят рядом (≤ PAIR_LINES строк): иначе `*` одного
    // обработчика и credentials другого, несвязанного, дали бы ложную находку.
    let line_of = |at: usize| ctx.index.line_col(ctx.text, at).map_or(0, |(l, _)| l);
    let mut origins: Vec<(usize, u32, Origin)> = Vec::new();
    let mut credential_lines: Vec<u32> = Vec::new();
    for literal in &ctx.lexed.literals {
        let Some(name) = plain_string(ctx.text, literal) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if lower != "access-control-allow-origin" && lower != "access-control-allow-credentials" {
            continue;
        }
        let Some(start) = value_start(ctx, literal.end) else {
            continue;
        };
        let end = expression_end(ctx, start, true);
        if lower == "access-control-allow-credentials" {
            if is_true(ctx, start, end) {
                credential_lines.push(line_of(literal.start));
            }
        } else {
            let kind = classify_origin(ctx, start, end);
            if kind != Origin::Other {
                origins.push((literal.start, line_of(literal.start), kind));
            }
        }
    }
    let mut paired: Vec<(usize, Origin)> = origins
        .iter()
        .filter(|(_, line, _)| {
            credential_lines
                .iter()
                .any(|c| c.abs_diff(*line) <= PAIR_LINES)
        })
        .map(|&(at, _, kind)| (at, kind))
        .collect();
    for at in lexer::code_occurrences(ctx.text, &ctx.lexed, "cors(") {
        let open = at + "cors".len();
        let end = expression_end(ctx, open + 1, false);
        let code = code_of(ctx, open + 1, end);
        let text = text_of(ctx, open + 1, end);
        if !code.contains("credentials:true") {
            continue;
        }
        if code.contains("origin:true")
            || code.contains("cb(null,true)")
            || code.contains("callback(null,true)")
        {
            paired.push((at, Origin::Reflect));
        } else if text.contains("origin:\"*\"") || text.contains("origin:'*'") {
            paired.push((at, Origin::Star));
        }
    }
    // Одна находка на файл: отражение важнее звёздочки, потом — первое по месту.
    paired.sort_by_key(|&(at, kind)| (kind != Origin::Reflect, at));
    let Some(&(at, kind)) = paired.first() else {
        return;
    };
    let Some((line, col)) = ctx.index.line_col(ctx.text, at) else {
        return;
    };
    if ctx.line_ignored(line as usize) {
        *ignored += 1;
        return;
    }
    let (title, severity, confidence, explanation) = match kind {
        Origin::Reflect => (
            "CORS reflects the request Origin and allows credentials",
            Severity::High,
            Confidence::Potential,
            "This file sends Access-Control-Allow-Credentials: true and copies the caller's Origin \
             into Access-Control-Allow-Origin (or lets the cors package accept every origin). Any \
             website a logged-in user visits can then call this endpoint with the user's cookies \
             and read the response. Not proven exploitable: the endpoint may need no cookies or \
             return nothing sensitive. Verify: send a request with 'Origin: https://evil.example' \
             and a session cookie and check whether the response echoes that origin.",
        ),
        Origin::Star => (
            "CORS wildcard origin combined with credentials",
            Severity::Low,
            Confidence::NeedsReview,
            "This file sends Access-Control-Allow-Origin: * together with \
             Access-Control-Allow-Credentials: true. Browsers refuse this combination, so \
             credentialed cross-origin calls fail rather than leak; the risk is the usual 'fix' \
             of echoing the request Origin. Use an explicit allowlist of origins instead.",
        ),
        Origin::Other => unreachable!("filtered above"),
    };
    let excerpt = redacted_line(ctx.text, &ctx.lexed, &ctx.index, at);
    findings.push(WebFinding {
        id: finding_id(RULE_ID, ctx.path, title),
        rule_id: RULE_ID,
        title: title.to_string(),
        category: "cors",
        severity,
        confidence,
        location: SourceLocation {
            relative_path: ctx.path.to_string(),
            line: Some(line),
            column: Some(col),
        },
        evidence: Evidence {
            redacted_excerpt: Some(excerpt),
            fingerprint: None,
        },
        explanation: explanation.to_string(),
        remediation_id: Some(format!("{RULE_ID}:origin-allowlist")),
        references: REFERENCES.to_vec(),
        cwe_ids: vec!["CWE-942"],
        tags: vec![
            "web".to_string(),
            ctx.framework.kind.label().to_string(),
            format!("reach:{}", ctx.reach.label()),
        ],
    });
}
