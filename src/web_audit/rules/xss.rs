//! WEB-XSS-003: запись HTML в DOM-синк. Только `potential` — потока данных мы не доказываем.
//!
//! Синки: `dangerouslySetInnerHTML={{ __html: X }}`, `el.innerHTML = X` / `+=`, `el.outerHTML = X`,
//! `el.insertAdjacentHTML(pos, X)`, `document.write(X)` / `writeln`.
//!
//! Не находка: X — только строковые литералы (константа, `"a" + "b"`, шаблон без `${}`);
//! X — вызов санитайзера/экранирования (`DOMPurify.sanitize(…)`, `sanitizeHtml(…)`,
//! `escapeHtml(…)`, ...). Имя функции — не доказательство корректной очистки, но и сигнала
//! «сырые данные в HTML» тут уже нет; это ограничение описано в docs/rules/web/WEB-XSS-003.md.
//!
//! Severity `high`, если в самом выражении видно недоверенный источник (`location`, `searchParams`,
//! `document.cookie`, `.value`, ...), иначе `medium`. Confidence — всегда `potential`.

use super::{FileContext, MAX_HITS_PER_FILE, RuleStats};
use crate::web_audit::enumerate::FileKind;
use crate::web_audit::lexer::{self, Class};
use crate::web_audit::location::redacted_line;
use crate::web_audit::provenance::Reach;
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};

pub const RULE_ID: &str = "WEB-XSS-003";

pub const REFERENCES: &[&str] = &[
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
    "https://cwe.mitre.org/data/definitions/79.html",
];

/// Выражение длиннее — не разбираем (и считаем непостоянным).
const MAX_EXPR: usize = 2000;

const SANITIZERS: &[&str] = &[
    // `markdownToSafeHTML`, `toSafeHtml` (полевой тест 2026-11-12, паттерн 5).
    "safe",
    "sanitize",
    "purify",
    "escape",
    "xss",
    "encodehtml",
    "htmlencode",
];

const SOURCES: &[&str] = &[
    "location.",
    "location[",
    "searchparams",
    "usesearchparams",
    "urlsearchparams",
    "document.cookie",
    "document.referrer",
    "window.name",
    ".value",
    "req.query",
    "req.body",
    "router.query",
    "params.",
    "postmessage",
    "event.data",
    "e.data",
];

#[derive(Clone, PartialEq, Eq)]
enum Verdict {
    Constant,
    Sanitized,
    /// `callee` — корень вызова, если всё выражение — один вызов (для проверки определения),
    /// и определена ли эта функция в самом файле.
    Dynamic {
        source_visible: bool,
        callee: Option<(String, bool)>,
    },
}

/// Пакеты-санитайзеры: файл, который их использует, считается очищающим HTML.
const SANITIZER_PACKAGES: &[&str] = &["sanitize-html", "dompurify", "isomorphic-dompurify", "xss"];

/// Подсветка кода: её вывод экранирован (паттерн 6).
const HIGHLIGHTERS: &[&str] = &[
    "shiki",
    "@shikijs/",
    "prismjs",
    "highlight.js",
    "lowlight",
    "refractor",
];

/// Файл вызывает санитайзер HTML (для «функция-санитайзер определена в проекте»).
pub fn file_uses_sanitizer(
    ctx: &FileContext,
    imports: &[crate::web_audit::project::ImportBinding],
) -> bool {
    imports
        .iter()
        .any(|b| SANITIZER_PACKAGES.contains(&b.specifier.as_str()))
        || ["DOMPurify.sanitize(", "sanitizeHtml(", "purify.sanitize("]
            .iter()
            .any(|m| ctx.stripped.contains(m))
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Значение составлено только из литералов: строки/числа/шаблоны без `${}`, объекты и массивы из них
/// (идентификаторы допустимы только как ключи `key:` и `true/false/null/undefined`).
fn literal_only_value(ctx: &FileContext, start: usize, end: usize) -> bool {
    let b = ctx.text.as_bytes();
    let mut i = start;
    let mut any = false;
    while i < end {
        match ctx.lexed.class_at(i) {
            Class::Str | Class::Comment => {
                any |= ctx.lexed.class_at(i) == Class::Str;
                i += 1;
            }
            Class::Template => {
                let Some(l) = ctx.lexed.literal_at(i) else {
                    return false;
                };
                let chunk = &ctx.text[l.start..l.end];
                if chunk.ends_with("${") || chunk.starts_with('}') {
                    return false;
                }
                any = true;
                i = l.end;
            }
            Class::Regex => return false,
            Class::Code => {
                let c = b[i];
                if c.is_ascii_digit() {
                    while i < end && (b[i].is_ascii_alphanumeric() || b[i] == b'.') {
                        i += 1;
                    }
                    any = true;
                } else if is_ident_byte(c) {
                    let s = i;
                    while i < end && is_ident_byte(b[i]) {
                        i += 1;
                    }
                    let word = &ctx.text[s..i];
                    let key = b.get(skip_ws(b, i)) == Some(&b':');
                    if !(key || matches!(word, "true" | "false" | "null" | "undefined")) {
                        return false;
                    }
                    any = true;
                } else if c.is_ascii_whitespace() || b"{}[]:,-+".contains(&c) {
                    i += 1;
                } else {
                    return false;
                }
            }
        }
    }
    any
}

/// Локальная переменная, которой присваиваются только литералы (`let s = "200"; … s = "404"`).
fn literal_only_local(ctx: &FileContext, ident: &str) -> bool {
    let b = ctx.text.as_bytes();
    let mut declared = false;
    let mut assignments = 0;
    for at in crate::web_audit::lexer::code_occurrences(ctx.text, &ctx.lexed, ident) {
        if b.get(at + ident.len()).is_some_and(|c| is_ident_byte(*c)) {
            continue;
        }
        let before = ctx.text[..at].trim_end();
        if before.ends_with("let") || before.ends_with("const") || before.ends_with("var") {
            declared = true;
        }
        let eq = skip_ws(b, at + ident.len());
        if b.get(eq) == Some(&b'=') && !matches!(b.get(eq + 1), Some(b'=' | b'>')) {
            let end = expression_end(ctx, eq + 1, true);
            if !literal_only_value(ctx, eq + 1, end) {
                return false;
            }
            assignments += 1;
        } else if matches!(b.get(eq), Some(b'+' | b'-'))
            && matches!(b.get(eq + 1), Some(b'=' | b'+' | b'-'))
        {
            return false;
        }
    }
    declared && assignments > 0
}

/// Всё выражение — константа по построению: литералы, `process.env.*`/`import.meta.env.*`
/// (значения сборки/оператора), локальные переменные только с литералами, `JSON.stringify` литерала
/// или константы модуля из литералов (паттерн 7).
fn constant_by_construction(ctx: &FileContext, start: usize, end: usize) -> bool {
    let b = ctx.text.as_bytes();
    let code: String = (start..end)
        .map(|i| {
            if ctx.lexed.class_at(i) == Class::Code {
                b[i] as char
            } else {
                ' '
            }
        })
        .collect();
    let trimmed = code.trim();
    if let Some(rest) = trimmed.strip_prefix("JSON.stringify(") {
        let arg = rest.trim_end().trim_end_matches(')').trim();
        let open = start + code.find("JSON.stringify(").unwrap_or(0) + "JSON.stringify(".len();
        let close = end.min(b.len());
        if literal_only_value(ctx, open, close.saturating_sub(1)) {
            return true;
        }
        if !arg.is_empty() && arg.bytes().all(is_ident_byte) && literal_only_local(ctx, arg) {
            return true;
        }
        return false;
    }
    // Остаток кода (вне литералов): только `+`, пробелы и «константные» имена.
    let mut i = 0;
    let cb = code.as_bytes();
    let mut saw_name = false;
    while i < cb.len() {
        let c = cb[i];
        if c.is_ascii_whitespace() || c == b'+' {
            i += 1;
            continue;
        }
        if !is_ident_byte(c) {
            return false;
        }
        let s = i;
        while i < cb.len() && (is_ident_byte(cb[i]) || cb[i] == b'.') {
            i += 1;
        }
        let path = &code[s..i];
        let env = path
            .strip_prefix("process.env.")
            .or_else(|| path.strip_prefix("import.meta.env."));
        let ok = env.is_some_and(|n| !n.is_empty() && n.bytes().all(is_ident_byte))
            || (path.bytes().all(is_ident_byte) && literal_only_local(ctx, path));
        if !ok {
            return false;
        }
        saw_name = true;
    }
    saw_name
}

/// Конец выражения от `start`: до `,`/`;`/закрывающей скобки на нулевой глубине (или конца
/// строки для присваиваний, если `stop_at_newline`). Литералы и комментарии пропускаются.
pub(super) fn expression_end(ctx: &FileContext, start: usize, stop_at_newline: bool) -> usize {
    let b = ctx.text.as_bytes();
    let limit = (start + MAX_EXPR).min(b.len());
    let mut depth = 0usize;
    let mut i = start;
    while i < limit {
        if ctx.lexed.class_at(i) != Class::Code {
            i += 1;
            continue;
        }
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            b',' | b';' if depth == 0 => return i,
            b'\n' if depth == 0 && stop_at_newline => return i,
            _ => {}
        }
        i += 1;
    }
    limit
}

fn verdict(ctx: &FileContext, start: usize, end: usize) -> Verdict {
    let b = ctx.text.as_bytes();
    let expr = &ctx.text[start..end];
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Verdict::Dynamic {
            source_visible: false,
            callee: None,
        };
    }
    // Только литералы и `+` между ними. Шаблон с `${}` даёт байты кода внутри — не константа.
    let constant = (start..end).all(|i| match ctx.lexed.class_at(i) {
        Class::Str | Class::Comment => true,
        Class::Template => ctx.lexed.literal_at(i).is_some_and(|l| {
            let chunk = &ctx.text[l.start..l.end];
            !chunk.ends_with("${") && !chunk.starts_with('}')
        }),
        Class::Regex => false,
        Class::Code => b[i].is_ascii_whitespace() || b[i] == b'+',
    });
    if constant || constant_by_construction(ctx, start, end) {
        return Verdict::Constant;
    }
    // Код без литералов — для поиска имён.
    let code: String = (start..end)
        .filter(|&i| ctx.lexed.class_at(i) == Class::Code)
        .map(|i| b[i] as char)
        .collect::<String>()
        .to_ascii_lowercase();
    let code = code.trim_start();
    // Всё выражение — один вызов санитайзера: `name.path(args)`.
    if let Some(paren) = code.find('(') {
        let callee = &code[..paren];
        let whole_call = code.trim_end().ends_with(')')
            && callee
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'$'));
        if whole_call && SANITIZERS.iter().any(|s| callee.contains(s)) {
            return Verdict::Sanitized;
        }
        if whole_call {
            // Регистр имени нужен для поиска импорта — берём из исходного кода.
            let original: String = (start..end)
                .filter(|&i| ctx.lexed.class_at(i) == Class::Code)
                .map(|i| b[i] as char)
                .collect();
            let root: String = original
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$'))
                .collect();
            let local = defined_locally(ctx, &root);
            return Verdict::Dynamic {
                source_visible: SOURCES.iter().any(|s| code.contains(s)),
                callee: (!root.is_empty()).then_some((root, local)),
            };
        }
    }
    Verdict::Dynamic {
        source_visible: SOURCES.iter().any(|s| code.contains(s)),
        callee: None,
    }
}

pub(super) fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// (байт синка, имя синка, начало выражения, конец выражения)
fn sinks(ctx: &FileContext) -> Vec<(usize, &'static str, usize, usize)> {
    let b = ctx.text.as_bytes();
    let mut out = Vec::new();
    for at in lexer::code_occurrences(ctx.text, &ctx.lexed, "dangerouslySetInnerHTML") {
        // `dangerouslySetInnerHTML={{ __html: X }}` или `dangerouslySetInnerHTML: { __html: X }`.
        let window_end = (at + 200).min(b.len());
        let Some(rel) = ctx.text[at..window_end].find("__html") else {
            continue;
        };
        let mut i = skip_ws(b, at + rel + "__html".len());
        if b.get(i) != Some(&b':') {
            continue;
        }
        i = skip_ws(b, i + 1);
        out.push((
            at,
            "dangerouslySetInnerHTML",
            i,
            expression_end(ctx, i, false),
        ));
    }
    for (needle, name) in [(".innerHTML", "innerHTML"), (".outerHTML", "outerHTML")] {
        for (at, _) in ctx.text.match_indices(needle) {
            if ctx.lexed.class_at(at) != Class::Code {
                continue;
            }
            let after = at + needle.len();
            if b.get(after)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                continue;
            }
            let mut i = skip_ws(b, after);
            if b.get(i) == Some(&b'+') {
                i += 1;
            }
            if b.get(i) != Some(&b'=') || b.get(i + 1) == Some(&b'=') {
                continue;
            }
            let start = skip_ws(b, i + 1);
            out.push((at + 1, name, start, expression_end(ctx, start, true)));
        }
    }
    for (needle, name, arg) in [
        (".insertAdjacentHTML(", "insertAdjacentHTML", 1),
        ("document.write(", "document.write", 0),
        ("document.writeln(", "document.writeln", 0),
    ] {
        for (at, _) in ctx.text.match_indices(needle) {
            if ctx.lexed.class_at(at) != Class::Code {
                continue;
            }
            let mut start = skip_ws(b, at + needle.len());
            let mut end = expression_end(ctx, start, false);
            for _ in 0..arg {
                if b.get(end) != Some(&b',') {
                    break;
                }
                start = skip_ws(b, end + 1);
                end = expression_end(ctx, start, false);
            }
            let sink_at = if needle.starts_with('.') { at + 1 } else { at };
            out.push((sink_at, name, start, end));
        }
    }
    out.sort_by_key(|s| s.0);
    out
}

/// Функция `name` объявлена в этом файле (`function name`, `const name =`).
fn defined_locally(ctx: &FileContext, name: &str) -> bool {
    let b = ctx.text.as_bytes();
    !name.is_empty()
        && crate::web_audit::lexer::code_occurrences(ctx.text, &ctx.lexed, name)
            .into_iter()
            .any(|at| {
                let before = ctx.text[..at].trim_end();
                !b.get(at + name.len()).is_some_and(|c| is_ident_byte(*c))
                    && (before.ends_with("function")
                        || before.ends_with("const")
                        || before.ends_with("let"))
            })
}

/// Находка, которую ещё можно снять после обхода: вызов функции, определённой в проекте.
pub struct Pending {
    pub finding: WebFinding,
    /// (корень вызова, определён ли в этом же файле).
    pub callee: Option<(String, bool)>,
}

/// Снимает находки, чей вызов — функция проекта, которая использует санитайзер (паттерн 5).
pub fn finish(
    pending: Vec<Pending>,
    project: &crate::web_audit::project::Project,
) -> Vec<WebFinding> {
    pending
        .into_iter()
        .filter(|p| {
            let Some((callee, local)) = &p.callee else {
                return true;
            };
            let path = &p.finding.location.relative_path;
            let sanitizing = match project.binding(path, callee) {
                Some(b) => project
                    .resolve(path, &b.specifier)
                    .and_then(|t| project.files.get(&t))
                    .is_some_and(|f| f.sanitizer),
                // Функция объявлена в этом же файле, и файл использует санитайзер.
                None => *local && project.files.get(path).is_some_and(|f| f.sanitizer),
            };
            !sanitizing
        })
        .map(|p| p.finding)
        .collect()
}

/// Типы `<script>`, чьё содержимое браузер не исполняет как JS, а читает как JSON.
const JSON_SCRIPT_TYPES: [&str; 4] = [
    "application/ld+json",
    "application/json",
    "speculationrules",
    "importmap",
];

/// Значение целиком — `JSON.stringify(…)`, в том числе внутри шаблона `` `${JSON.stringify(x)}` ``.
fn stringify_only(value: &str) -> bool {
    let mut v = value.trim();
    if let Some(inner) = v.strip_prefix("`${").and_then(|s| s.strip_suffix("}`")) {
        if inner.contains("${") {
            return false;
        }
        v = inner.trim();
    }
    v.starts_with("JSON.stringify(") && v.ends_with(')')
}

/// Тип JSON-скрипта, если синк стоит в атрибутах тега `<script>` / `<Script>` с таким `type`.
/// Тег ищется назад от синка (не дальше 400 байт, без закрытия `/>` или `</` между ними),
/// `type` — в его атрибутах до синка или после значения, до конца тега.
fn json_script_type(text: &str, at: usize, end: usize) -> Option<&'static str> {
    let from = floor_boundary(text, at.saturating_sub(400));
    let before = &text[from..at];
    let tag = ["<script", "<Script"]
        .iter()
        .filter_map(|t| {
            before
                .rmatch_indices(t)
                .find(|(i, _)| {
                    before[i + t.len()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_whitespace())
                })
                .map(|(i, _)| i)
        })
        .max()?;
    let head = &before[tag..];
    if head.contains("/>") || head.contains("</") {
        return None;
    }
    let to = floor_boundary(text, (end + 400).min(text.len()));
    let after = &text[end..to];
    let tail_end = ["/>", "</"]
        .iter()
        .filter_map(|t| after.find(t))
        .min()
        .unwrap_or(after.len());
    let tail = &after[..tail_end];
    JSON_SCRIPT_TYPES.iter().copied().find(|ty| {
        [head, tail].iter().any(|part| {
            part.contains(&format!("type=\"{ty}\"")) || part.contains(&format!("type='{ty}'"))
        })
    })
}

fn floor_boundary(text: &str, mut i: usize) -> usize {
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub fn check(ctx: &FileContext, findings: &mut Vec<Pending>, stats: &mut RuleStats) {
    if ctx.kind != FileKind::Script || ctx.reach == Reach::Test {
        return;
    }
    let sinks = sinks(ctx);
    stats.note_cap(RULE_ID, ctx.path, sinks.len());
    let imports = crate::web_audit::project::import_bindings(ctx.text, &ctx.lexed);
    let highlighter = imports
        .iter()
        .any(|b| HIGHLIGHTERS.iter().any(|h| b.specifier.starts_with(h)))
        || ctx.stripped.contains("codeToHtml(");
    for (at, sink, start, end) in sinks.into_iter().take(MAX_HITS_PER_FILE) {
        let (source_visible, callee) = match verdict(ctx, start, end) {
            Verdict::Constant | Verdict::Sanitized => continue,
            Verdict::Dynamic {
                source_visible,
                callee,
            } => (source_visible, callee),
        };
        let json_type = if stringify_only(&ctx.text[start..end]) {
            json_script_type(ctx.text, at, end)
        } else {
            None
        };
        let json_ld = json_type.is_some();
        let Some((line, col)) = ctx.index.line_col(ctx.text, at) else {
            continue;
        };
        if ctx.line_ignored(line as usize) {
            stats.ignored_inline += 1;
            continue;
        }
        let mut excerpt = redacted_line(ctx.text, &ctx.lexed, &ctx.index, at);
        // Многострочный синк: показать и строку значения (`__html: …`) — паттерн 8.
        if let Some((value_line, _)) = ctx.index.line_col(ctx.text, start)
            && value_line != line
        {
            excerpt = format!(
                "{excerpt} … {}",
                redacted_line(ctx.text, &ctx.lexed, &ctx.index, start)
            );
        }
        let severity = if highlighter {
            Severity::Info
        } else if json_ld {
            Severity::Low
        } else if source_visible {
            Severity::High
        } else {
            Severity::Medium
        };
        let note = if highlighter {
            " This file uses a syntax highlighter (Shiki/Prism/highlight.js/lowlight), whose HTML \
             output is escaped; check only the highlighter inputs (language, theme)."
                .to_string()
        } else if let Some(ty) = json_type {
            format!(
                " This is JSON.stringify inside a <script type=\"{ty}\">: JSON.stringify does not \
                 escape \"</script>\", so content that can contain it should be escaped."
            )
        } else {
            String::new()
        };
        let source = if source_visible {
            " The expression itself reads a value an attacker can often control (URL, form \
             field, message, request)."
        } else {
            ""
        };
        findings.push(Pending {
            callee,
            finding: WebFinding {
            id: finding_id(RULE_ID, ctx.path, &format!("{sink}\0{excerpt}")),
            rule_id: RULE_ID,
            title: format!("Non-constant HTML written through {sink}"),
            category: "xss",
            severity,
            confidence: Confidence::Potential,
            location: SourceLocation {
                relative_path: ctx.path.to_string(),
                line: Some(line),
                column: Some(col),
            },
            evidence: Evidence {
                redacted_excerpt: Some(excerpt),
                fingerprint: None,
            },
            explanation: format!(
                "{sink} turns its value into live HTML. The value here is not a constant string \
                 and does not go through a recognised sanitizer.{source}{note} jetscan does not track \
                 data flow, so whether untrusted input reaches this line is not proven."
            ),
            remediation_id: Some(format!("{RULE_ID}:render-as-text-or-sanitize")),
            references: REFERENCES.to_vec(),
            cwe_ids: vec!["CWE-79"],
            tags: vec![
                "web".to_string(),
                ctx.framework.kind.label().to_string(),
                format!("sink:{sink}"),
                format!("reach:{}", ctx.reach.label()),
            ],
            },
        });
    }
}
