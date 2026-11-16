//! WEB-AUTH-004: изменяющий серверный обработчик без видимой проверки доступа. Только `needs_review`.
//!
//! Отсутствие `auth()` в файле — НЕ доказательство уязвимости. Поэтому правило узкое:
//! - App Router `app/**/route.*`, экспортирующий `POST`/`PUT`/`PATCH`/`DELETE`;
//! - Pages Router `pages/api/**`, сравнивающий `req.method` с изменяющим методом;
//! - модуль `"use server"`: каждый экспорт — публичный POST-эндпоинт (Server Action), в том числе
//!   не-`async` экспорт вида `export const x = unstable_cache(async …)` (полевой тест, W7);
//! - и признака проверки доступа нет ни в файле (без комментариев), ни там, куда обработчик ведёт:
//!   **обёртка** (`export const POST = withCron(…)`, `export const { POST } = serve(…)`,
//!   `export default withAuth(handler)`) и **делегирование в один шаг** (`return revalidate(req)`)
//!   разрешаются через импорт до файла проекта, и его признаки засчитываются (полевой тест
//!   2026-11-12, паттерны 1–2). Внешние пакеты-верификаторы (`@upstash/workflow` `serve`,
//!   `@upstash/qstash`, `next-auth`, `@clerk/nextjs`, `@auth/*`) и обёртки `with<Auth|Cron|…>` —
//!   признак по имени.
//! - Server Action, тело которой — только `revalidatePath`/`revalidateTag`, — не находка (паттерн 3).
//!
//! Middleware (`middleware.*`, а для Next.js ≥ 16 и `proxy.*` — W5) удерживает находку, только если
//! это настоящий шлюз доступа (признак проверки + блокировка: redirect/rewrite/401/403/`withAuth`)
//! и его `matcher` может покрыть этот маршрут; проверка `partial`, только если что-то удержано (W4).

use super::FileContext;
use super::xss::expression_end;
use crate::web_audit::framework::{FrameworkKind, next_major};
use crate::web_audit::lexer::{self, Class, plain_string};
use crate::web_audit::location::redacted_line;
use crate::web_audit::project::Project;
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};

pub const RULE_ID: &str = "WEB-AUTH-004";

pub const REFERENCES: &[&str] = &[
    "https://cwe.mitre.org/data/definitions/862.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
];

/// Признаки проверки доступа (в нижнем регистре, подстрокой по коду и строкам без комментариев).
/// Список намеренно широкий: лучше пропустить находку, чем шуметь.
const AUTH_SIGNALS: &[&str] = &[
    "auth",
    "session",
    "getuser",
    "currentuser",
    "verify",
    "jwt",
    "bearer",
    "cookie",
    "clerk",
    "signature",
    "apikey",
    "api_key",
    "x-api-key",
    "gettoken",
    "csrf",
    "permission",
    "isadmin",
    "requireuser",
    "requireadmin",
    "guard",
    "protect",
    "cron_secret",
    "timingsafeequal",
    "unauthorized",
    "forbidden",
    "401",
    "403",
];

/// То, чем middleware действительно останавливает запрос (а не только обновляет сессию).
const BLOCKING: &[&str] = &[
    "redirect(",
    "rewrite(",
    "new response(",
    "nextresponse.json(",
    "401",
    "403",
    "unauthorized",
    "forbidden",
    "withauth(",
    "as middleware",
    "auth((",
];

/// Пакеты, которые сами проверяют подпись/сессию (обёртка из них — признак проверки).
const VERIFIER_PACKAGES: &[&str] = &[
    "@upstash/workflow",
    "@upstash/qstash",
    "next-auth",
    "@auth/",
    "@clerk/nextjs",
    "@kinde-oss/",
    "@workos-inc/authkit-nextjs",
];

/// Части имени обёртки/вызова, которые говорят «здесь проверка доступа».
const GUARD_WORDS: &[&str] = &[
    "auth",
    "session",
    "cron",
    "signature",
    "verify",
    "admin",
    "permission",
    "role",
    "guard",
    "protect",
    "apikey",
    "token",
    "secret",
    "user",
    "workspace",
    "team",
];

/// Сегменты пути, где обработчик публичен по замыслу.
const PUBLIC_SEGMENTS: &[&str] = &[
    "health",
    "healthz",
    "ping",
    "status",
    "og",
    "auth",
    "callback",
    "callbacks",
    "public",
    "login",
    "logout",
    "signin",
    "signup",
    "sign-in",
    "sign-up",
    "register",
];

const MUTATING: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Признак проверки доступа в файле: слова-маркеры в коде и строках (без комментариев) или
/// сравнение `process.env.*SECRET*`/`*TOKEN*` через `===`/`!==` (паттерн 2).
pub fn file_has_auth_signal(ctx: &FileContext) -> bool {
    let lower = ctx.stripped.to_ascii_lowercase();
    if AUTH_SIGNALS.iter().any(|s| lower.contains(s)) {
        return true;
    }
    lexer::code_occurrences(ctx.text, &ctx.lexed, "process.env.")
        .into_iter()
        .any(|at| {
            let name: String = ctx.text[at + 12..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
                .to_ascii_uppercase();
            let line = ctx
                .index
                .line_col(ctx.text, at)
                .and_then(|(l, _)| ctx.index.line_range(ctx.text, l as usize))
                .map_or("", |(s, e)| &ctx.text[s..e]);
            (name.contains("SECRET") || name.contains("TOKEN"))
                && (line.contains("===") || line.contains("!=="))
        })
}

fn public_by_path(path: &str) -> bool {
    path.to_ascii_lowercase().split('/').any(|seg| {
        let seg = seg.split('.').next().unwrap_or(seg);
        seg.contains("webhook")
            || PUBLIC_SEGMENTS.contains(&seg.trim_matches(|c| c == '[' || c == ']' || c == '.'))
    })
}

/// URL-путь маршрута (`app/api/items/route.ts` → `/api/items`).
fn route_url(path: &str, dir: &str, strip_route_file: bool) -> String {
    let rest = path.strip_prefix(dir).unwrap_or(path);
    let rest = if strip_route_file {
        rest.rsplit_once('/').map_or("", |(d, _)| d).to_string()
    } else {
        rest.rsplit_once('.').map_or(rest, |(p, _)| p).to_string()
    };
    let url: Vec<&str> = rest
        .split('/')
        .filter(|s| !s.is_empty() && !(s.starts_with('(') && s.ends_with(')')))
        .collect();
    let url = format!("/{}", url.join("/"));
    url.strip_suffix("/index")
        .map(str::to_string)
        .unwrap_or(url)
}

fn skip_ws(text: &str, mut at: usize) -> usize {
    let b = text.as_bytes();
    while at < b.len() && b[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

/// Конец парной скобки для `open` (байт на `(`/`{`/`[`), по коду без литералов.
fn matching(ctx: &FileContext, open: usize) -> Option<usize> {
    let b = ctx.text.as_bytes();
    let mut depth = 0usize;
    for (i, &c) in b.iter().enumerate().skip(open) {
        if ctx.lexed.class_at(i) != Class::Code {
            continue;
        }
        match c {
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Код диапазона без литералов (для поиска идентификаторов).
fn code_of(ctx: &FileContext, start: usize, end: usize) -> String {
    let b = ctx.text.as_bytes();
    (start..end.min(b.len()))
        .map(|i| {
            if ctx.lexed.class_at(i) == Class::Code {
                b[i] as char
            } else {
                ' '
            }
        })
        .collect()
}

/// Идентификатор (с `.путём`) в начале `code` и вызывается ли он: `withCron(` → `withCron`.
fn leading_call(code: &str) -> Option<String> {
    let code = code.trim_start();
    let code = code.strip_prefix("await").map_or(code, str::trim_start);
    let ident: String = code
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))
        .collect();
    let mut rest = code[ident.len()..].trim_start();
    // TypeScript: аргументы типа между именем и скобкой — `serve<Input>(…)` (раунд 2, N2).
    if rest.starts_with('<') {
        let mut depth = 0usize;
        let mut end = None;
        for (i, c) in rest.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                '(' | ')' | ';' | '{' | '}' => break,
                _ => {}
            }
        }
        rest = rest[end?..].trim_start();
    }
    (!ident.is_empty() && rest.starts_with('(') && !matches!(ident.as_str(), "async" | "function"))
        .then_some(ident)
}

/// Тело функции, начиная поиск с `from` (после имени): `(…)` затем `{…}`.
fn function_body(ctx: &FileContext, from: usize) -> Option<(usize, usize)> {
    let b = ctx.text.as_bytes();
    let open_paren =
        (from..b.len()).find(|&i| ctx.lexed.class_at(i) == Class::Code && b[i] == b'(')?;
    let close_paren = matching(ctx, open_paren)?;
    let open_brace =
        (close_paren..b.len()).find(|&i| ctx.lexed.class_at(i) == Class::Code && b[i] == b'{')?;
    Some((open_brace, matching(ctx, open_brace)?))
}

/// Что делает экспортируемое значение: обёртка (`IDENT(…)`), тело функции и делегат из тела.
#[derive(Default, Debug)]
struct Shape {
    refs: Vec<String>,
    body: Option<(usize, usize)>,
}

/// Форма функции/значения, начинающегося в `start` (после `=` или для `function NAME`).
fn value_shape(ctx: &FileContext, start: usize, end: usize) -> Shape {
    let code = code_of(ctx, start, end);
    let trimmed = code.trim_start();
    let mut shape = Shape::default();
    if let Some(callee) = leading_call(trimmed) {
        shape.refs.push(callee);
        shape.body = Some((start, end));
        return shape;
    }
    // Стрелка или function-выражение: тело после `=>` или `{` функции.
    if let Some(arrow) = code.find("=>") {
        let body_start = skip_ws(ctx.text, start + arrow + 2);
        if ctx.text.as_bytes().get(body_start) == Some(&b'{') {
            shape.body = matching(ctx, body_start).map(|e| (body_start, e));
        } else {
            shape.body = Some((body_start, end));
        }
    } else if trimmed.starts_with("async function") || trimmed.starts_with("function") {
        shape.body = function_body(ctx, start);
    }
    if let Some((s, e)) = shape.body {
        shape.refs.extend(delegate(ctx, s, e));
    }
    shape
}

/// Делегирование в один шаг: короткое тело, первая инструкция — `return [await] IDENT(…)`,
/// или выражение-тело `IDENT(…)`.
fn delegate(ctx: &FileContext, start: usize, end: usize) -> Option<String> {
    let code = code_of(ctx, start, end);
    if code.split_whitespace().collect::<String>().len() > 400 {
        return None;
    }
    let inner = code.trim().trim_start_matches('{').trim_start();
    let after_return = inner
        .strip_prefix("return")
        .map(str::trim_start)
        .unwrap_or(inner);
    // Ответ-обёртка вокруг делегата: `NextResponse.json(await handle(req))`, `new Response(await …)`
    // — делегат в первом аргументе (раунд 2, FP 2).
    let wrapped = after_return
        .strip_prefix("new Response")
        .map(str::trim_start);
    let call = leading_call(after_return);
    let response = matches!(
        call.as_deref(),
        Some("NextResponse.json" | "Response.json" | "NextResponse.redirect" | "Response.redirect")
    );
    if wrapped.is_some() || response {
        let rest = wrapped.unwrap_or(after_return);
        let open = rest.find('(')?;
        return leading_call(&rest[open + 1..]);
    }
    call
}

/// Тело содержит только `revalidatePath(…)` / `revalidateTag(…)` (паттерн 3).
fn revalidate_only(ctx: &FileContext, start: usize, end: usize) -> bool {
    let mut code = code_of(ctx, start, end);
    let mut found = false;
    for call in ["revalidatePath(", "revalidateTag("] {
        while let Some(at) = code.find(call) {
            found = true;
            let open = at + call.len() - 1;
            let mut depth = 0usize;
            let mut close = code.len();
            for (i, c) in code[open..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            code.replace_range(at..close, " ");
        }
    }
    found
        && code
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
            .filter(|w| !w.is_empty() && !w.starts_with(|c: char| c.is_ascii_digit()))
            .all(|w| matches!(w, "await" | "return" | "async"))
}

/// Одна защищаемая «единица»: изменяющий экспорт маршрута или Server Action.
#[derive(Debug)]
struct Unit {
    line: u32,
    col: u32,
    excerpt: String,
    refs: Vec<String>,
}

#[derive(Debug)]
enum Kind {
    Route { method: &'static str, url: String },
    Pages { url: String },
    Actions,
}

#[derive(Debug)]
struct Candidate {
    path: String,
    kind: Kind,
    reach: &'static str,
    units: Vec<Unit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Matcher {
    /// `matcher` нет — middleware выполняется на всех маршрутах.
    All,
    /// Литеральные пути; `None` в элементе — регулярка/непонятный шаблон.
    Paths(Vec<Option<PathPattern>>),
    /// Не литерал — не знаем.
    Unknown,
}

/// Литеральный шаблон `matcher`: префикс до первого параметра (`/dashboard` из `/dashboard/:path*`)
/// или, если шаблон начинается с параметра, литеральный хвост (`/embed` из `/:path*/embed`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct PathPattern {
    prefix: String,
    suffix: Option<String>,
}

impl PathPattern {
    /// `None` — регулярка (`(…)`): не знаем, что покрывает.
    fn parse(s: &str) -> Option<PathPattern> {
        if s.contains('(') {
            return None;
        }
        let special = |seg: &str| seg.contains([':', '*', '[', '?']);
        let end = s.find([':', '*', '[', '?']).unwrap_or(s.len());
        let prefix = s[..end].trim_end_matches('/').to_string();
        let suffix = if prefix.is_empty() {
            let segments: Vec<&str> = s.split('/').filter(|seg| !seg.is_empty()).collect();
            let tail: Vec<&str> = segments
                .iter()
                .rev()
                .take_while(|seg| !special(seg))
                .copied()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            (!tail.is_empty() && tail.len() < segments.len())
                .then(|| format!("/{}", tail.join("/")))
        } else {
            None
        };
        Some(PathPattern { prefix, suffix })
    }

    fn covers(&self, url: &str) -> bool {
        match (&self.prefix, &self.suffix) {
            (p, _) if !p.is_empty() => url == p || url.starts_with(&format!("{p}/")),
            (_, Some(tail)) => url.ends_with(tail.as_str()) || url.contains(&format!("{tail}/")),
            _ => true,
        }
    }
}

impl Matcher {
    /// Может ли middleware выполниться для маршрута `url`.
    fn may_cover(&self, url: &str) -> bool {
        match self {
            Matcher::All | Matcher::Unknown => true,
            Matcher::Paths(paths) => paths
                .iter()
                .any(|p| p.as_ref().is_none_or(|p| p.covers(url))),
        }
    }
}

fn parse_matcher(ctx: &FileContext) -> Matcher {
    let b = ctx.text.as_bytes();
    let Some(at) = lexer::code_occurrences(ctx.text, &ctx.lexed, "matcher")
        .into_iter()
        .find(|&at| b.get(skip_ws(ctx.text, at + 7)) == Some(&b':'))
    else {
        return Matcher::All;
    };
    let value = skip_ws(ctx.text, skip_ws(ctx.text, at + 7) + 1);
    let literal_prefix = PathPattern::parse;
    if let Some(l) = ctx.lexed.literal_at(value).filter(|l| l.start == value)
        && let Some(s) = plain_string(ctx.text, l)
    {
        return Matcher::Paths(vec![literal_prefix(&s)]);
    }
    if b.get(value) != Some(&b'[') {
        return Matcher::Unknown;
    }
    let Some(end) = matching(ctx, value) else {
        return Matcher::Unknown;
    };
    let mut paths = Vec::new();
    let mut i = value + 1;
    while i < end - 1 {
        match ctx.lexed.class_at(i) {
            Class::Str => {
                let Some(l) = ctx.lexed.literal_at(i) else {
                    return Matcher::Unknown;
                };
                match plain_string(ctx.text, l) {
                    Some(s) => paths.push(literal_prefix(&s)),
                    None => return Matcher::Unknown,
                }
                i = l.end;
            }
            Class::Comment => i += 1,
            Class::Code if b[i].is_ascii_whitespace() || b[i] == b',' => i += 1,
            _ => return Matcher::Unknown,
        }
    }
    Matcher::Paths(paths)
}

#[derive(Debug)]
struct Middleware {
    path: String,
    matcher: Matcher,
}

#[derive(Default)]
pub struct AuthCollector {
    candidates: Vec<Candidate>,
    middleware: Option<Middleware>,
}

fn unit(ctx: &FileContext, at: usize, refs: Vec<String>, ignored: &mut usize) -> Option<Unit> {
    let (line, col) = ctx.index.line_col(ctx.text, at)?;
    if ctx.line_ignored(line as usize) {
        *ignored += 1;
        return None;
    }
    Some(Unit {
        line,
        col,
        excerpt: redacted_line(ctx.text, &ctx.lexed, &ctx.index, at),
        refs,
    })
}

/// Изменяющие экспорты route handler: (байт имени, метод, обёртки/делегаты).
fn route_exports(ctx: &FileContext) -> Vec<(usize, &'static str, Vec<String>)> {
    let b = ctx.text.as_bytes();
    let mut out = Vec::new();
    for method in MUTATING {
        for at in lexer::code_occurrences(ctx.text, &ctx.lexed, method) {
            if b.get(at + method.len()).is_some_and(|c| is_ident_byte(*c)) {
                continue;
            }
            let before = ctx.text[..at].trim_end();
            let refs = if before.ends_with("function") {
                function_body(ctx, at)
                    .and_then(|(s, e)| delegate(ctx, s, e))
                    .into_iter()
                    .collect()
            } else if before.ends_with("const")
                || before.ends_with("let")
                || before.ends_with("var")
            {
                // `export const POST = …`
                let eq = skip_ws(ctx.text, at + method.len());
                if b.get(eq) != Some(&b'=') {
                    continue;
                }
                let start = eq + 1;
                let end = expression_end(ctx, start, false);
                value_shape(ctx, start, end).refs
            } else if before.ends_with('{') || before.ends_with(',') {
                // `export const { POST } = serve(…)` или `export { handler as POST }`.
                let close =
                    (at..b.len()).find(|&i| ctx.lexed.class_at(i) == Class::Code && b[i] == b'}');
                let Some(close) = close else { continue };
                let eq = skip_ws(ctx.text, close + 1);
                if b.get(eq) == Some(&b'=') {
                    let end = expression_end(ctx, eq + 1, false);
                    value_shape(ctx, eq + 1, end).refs
                } else {
                    continue;
                }
            } else if let Some(stem) = before.strip_suffix(" as") {
                // `export { handler as POST }` → форма локального `handler`.
                let local: String = stem
                    .trim_end()
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                local_shape(ctx, &local)
            } else {
                continue;
            };
            out.push((at, *method, refs));
        }
    }
    out.sort_by_key(|(at, _, _)| *at);
    out
}

/// Форма локального объявления `const NAME = …` / `function NAME(…)`.
fn local_shape(ctx: &FileContext, name: &str) -> Vec<String> {
    let b = ctx.text.as_bytes();
    for at in lexer::code_occurrences(ctx.text, &ctx.lexed, name) {
        if b.get(at + name.len()).is_some_and(|c| is_ident_byte(*c)) {
            continue;
        }
        let before = ctx.text[..at].trim_end();
        if before.ends_with("function") {
            return function_body(ctx, at)
                .and_then(|(s, e)| delegate(ctx, s, e))
                .into_iter()
                .collect();
        }
        if before.ends_with("const") || before.ends_with("let") || before.ends_with("var") {
            let eq = skip_ws(ctx.text, at + name.len());
            if b.get(eq) == Some(&b'=') {
                let end = expression_end(ctx, eq + 1, false);
                return value_shape(ctx, eq + 1, end).refs;
            }
        }
    }
    Vec::new()
}

/// Экспорты модуля `"use server"`: (байт, обёртки/делегаты), без revalidate-only.
fn server_action_units(ctx: &FileContext) -> (Vec<(usize, Vec<String>)>, usize) {
    let b = ctx.text.as_bytes();
    let mut actions = Vec::new();
    let mut revalidate = 0;
    for at in lexer::code_occurrences(ctx.text, &ctx.lexed, "export") {
        let i = skip_ws(ctx.text, at + 6);
        let rest = &ctx.text[i..];
        let (shape, counted) = if let Some(r) = [
            "default async function",
            "async function",
            "default function",
            "function",
        ]
        .iter()
        .find_map(|kw| rest.strip_prefix(kw).map(|_| kw.len()))
        {
            let mut shape = Shape {
                body: function_body(ctx, i + r),
                ..Shape::default()
            };
            if let Some((s, e)) = shape.body {
                shape.refs.extend(delegate(ctx, s, e));
            }
            (shape, true)
        } else if rest.starts_with("const ") || rest.starts_with("let ") {
            let Some(eq) = (i..(i + 200).min(b.len())).find(|&j| {
                ctx.lexed.class_at(j) == Class::Code
                    && b[j] == b'='
                    && b.get(j + 1) != Some(&b'>')
                    && b.get(j + 1) != Some(&b'=')
            }) else {
                continue;
            };
            let end = expression_end(ctx, eq + 1, false);
            (value_shape(ctx, eq + 1, end), true)
        } else {
            (Shape::default(), false)
        };
        if !counted {
            continue;
        }
        if let Some((s, e)) = shape.body
            && shape
                .refs
                .iter()
                .all(|r| r == "revalidatePath" || r == "revalidateTag")
            && revalidate_only(ctx, s, e)
        {
            revalidate += 1;
            continue;
        }
        actions.push((at, shape.refs));
    }
    (actions, revalidate)
}

impl AuthCollector {
    pub fn file(&mut self, ctx: &FileContext, ignored: &mut usize) {
        if ctx.framework.kind != FrameworkKind::NextJs
            || ctx.kind != crate::web_audit::enumerate::FileKind::Script
        {
            return;
        }
        let name = ctx.path.rsplit('/').next().unwrap_or(ctx.path);
        let stem = name.split('.').next().unwrap_or(name);
        let root_level = !ctx.path.contains('/')
            || ctx
                .path
                .strip_prefix("src/")
                .is_some_and(|r| !r.contains('/'));
        let next16 = next_major(ctx.framework).is_none_or(|m| m >= 16);
        // Ровно `middleware.<ext>` / `proxy.<ext>`: `proxy.test.ts`, `middleware.spec.ts` — не шлюз
        // (раунд 2, N3; раньше выигрывал последний обработанный файл).
        let single_ext = name.split('.').count() == 2
            && name.rsplit('.').next().is_some_and(|ext| {
                ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"].contains(&ext)
            });
        if root_level && single_ext && (stem == "middleware" || (stem == "proxy" && next16)) {
            let lower = ctx.stripped.to_ascii_lowercase();
            if file_has_auth_signal(ctx) && BLOCKING.iter().any(|m| lower.contains(m)) {
                self.middleware = Some(Middleware {
                    path: ctx.path.to_string(),
                    matcher: parse_matcher(ctx),
                });
            }
            return;
        }
        if public_by_path(ctx.path) || file_has_auth_signal(ctx) {
            return;
        }
        let app_dir = ctx
            .framework
            .app_dirs
            .iter()
            .find(|d| ctx.path.starts_with(&format!("{d}/")));
        let pages_api = ctx
            .framework
            .pages_dirs
            .iter()
            .find(|d| ctx.path.starts_with(&format!("{d}/api/")));
        let reach = ctx.reach.label();
        if let (Some(dir), "route") = (app_dir, stem) {
            let url = route_url(ctx.path, dir, true);
            let exports = route_exports(ctx);
            let Some(method) = exports.first().map(|(_, m, _)| *m) else {
                return;
            };
            let units = exports
                .into_iter()
                .filter_map(|(at, _, refs)| unit(ctx, at, refs, ignored))
                .collect::<Vec<_>>();
            if !units.is_empty() {
                self.candidates.push(Candidate {
                    path: ctx.path.to_string(),
                    kind: Kind::Route { method, url },
                    reach,
                    units,
                });
            }
        } else if let Some(dir) = pages_api {
            let checks_method = ["req.method", "request.method"]
                .iter()
                .any(|n| !lexer::code_occurrences(ctx.text, &ctx.lexed, n).is_empty());
            let Some(at) = ctx
                .lexed
                .literals
                .iter()
                .find(|l| plain_string(ctx.text, l).is_some_and(|v| MUTATING.contains(&v.as_str())))
                .map(|l| l.start)
                .filter(|_| checks_method)
            else {
                return;
            };
            // `export default withAuth(handler)` — обёртка.
            let refs = lexer::code_occurrences(ctx.text, &ctx.lexed, "export")
                .into_iter()
                .find_map(|e| {
                    let i = skip_ws(ctx.text, e + 6);
                    let rest = ctx.text[i..].strip_prefix("default")?;
                    let start = i + 7;
                    let end = expression_end(ctx, start, false);
                    leading_call(&code_of(ctx, start, end))
                        .filter(|_| !rest.trim_start().starts_with("function"))
                })
                .into_iter()
                .collect();
            if let Some(u) = unit(ctx, at, refs, ignored) {
                self.candidates.push(Candidate {
                    path: ctx.path.to_string(),
                    kind: Kind::Pages {
                        url: route_url(ctx.path, dir, false),
                    },
                    reach,
                    units: vec![u],
                });
            }
        } else if ctx.directives.iter().any(|d| d == "use server") {
            let (actions, _revalidate_only) = server_action_units(ctx);
            let units: Vec<Unit> = actions
                .into_iter()
                .filter_map(|(at, refs)| unit(ctx, at, refs, ignored))
                .collect();
            if !units.is_empty() {
                self.candidates.push(Candidate {
                    path: ctx.path.to_string(),
                    kind: Kind::Actions,
                    reach,
                    units,
                });
            }
        }
    }

    /// Находки и причина неполноты (только если middleware что-то удержало).
    pub fn finish(self, project: &Project) -> (Vec<WebFinding>, Option<String>) {
        let mut findings = Vec::new();
        let mut withheld = 0usize;
        for c in self.candidates {
            let open: Vec<&Unit> = c
                .units
                .iter()
                .filter(|u| !u.refs.iter().any(|r| guarded(project, &c.path, r)))
                .collect();
            let Some(first) = open.first() else {
                continue;
            };
            // Server Actions не удерживаются никогда: страницу, где их вызывают, статически не
            // узнать, а удержание прятало ровно то, ради чего правило есть (полевой тест, N5).
            let note = match (&c.kind, &self.middleware) {
                (Kind::Route { url, .. } | Kind::Pages { url }, Some(mw))
                    if mw.matcher.may_cover(url) =>
                {
                    withheld += 1;
                    continue;
                }
                (Kind::Actions, Some(mw)) => Some(format!(
                    " An access gate exists in {}; check whether it covers the pages that use these actions — Server Actions are POSTed to the page URL, so that is what the gate sees.",
                    crate::ui::sanitize_line(&mw.path)
                )),
                _ => None,
            };
            let mut finding = build(&c, first, open.len());
            if let Some(note) = note {
                finding.explanation.push_str(&note);
                finding.tags.push("gate:unknown-coverage".to_string());
            }
            findings.push(finding);
        }
        let reason = self.middleware.filter(|_| withheld > 0).map(|mw| {
            format!(
                "{} contains an access gate whose matcher may cover {withheld} handler(s); their \
                 findings are withheld (route coverage is approximated from literal matcher paths)",
                crate::ui::sanitize_line(&mw.path)
            )
        });
        (findings, reason)
    }
}

/// Обёртка/делегат `ident` из файла `path` проверяет доступ: файл проекта с признаком,
/// пакет-верификатор или имя `with<Guard…>`/`verify…`/`require…`.
fn guarded(project: &Project, path: &str, ident: &str) -> bool {
    let root = ident.split('.').next().unwrap_or(ident);
    if let Some(binding) = project.binding(path, root) {
        if let Some(target) = project.resolve(path, &binding.specifier) {
            return project.files.get(&target).is_some_and(|f| f.auth_signal);
        }
        if VERIFIER_PACKAGES
            .iter()
            .any(|p| binding.specifier.starts_with(p))
        {
            return true;
        }
    }
    let lower = ident.to_ascii_lowercase();
    let named =
        lower.starts_with("with") || lower.starts_with("verify") || lower.starts_with("require");
    named && GUARD_WORDS.iter().any(|w| lower.contains(w))
}

fn build(c: &Candidate, first: &Unit, count: usize) -> WebFinding {
    let (title, what, url_hint) = match &c.kind {
        Kind::Route { method, url } => (
            format!("{method} route handler without a visible access check"),
            format!("The App Router handler exports {method}"),
            format!("curl -i -X {method} https://<your-host>{url}"),
        ),
        Kind::Pages { url } => (
            "State-changing API route without a visible access check".to_string(),
            "The Pages Router API route handles a state-changing method".to_string(),
            format!("curl -i -X POST https://<your-host>{url}"),
        ),
        Kind::Actions => (
            format!("{count} Server Action(s) without a visible access check"),
            "Every export of a 'use server' module is a public POST endpoint that anyone can call, \
             not only your own forms"
                .to_string(),
            "call the action from a logged-out browser session (or replay its POST request \
             without cookies)"
                .to_string(),
        ),
    };
    WebFinding {
        id: finding_id(RULE_ID, &c.path, &title),
        rule_id: RULE_ID,
        title,
        category: "access_control",
        severity: Severity::Medium,
        confidence: Confidence::NeedsReview,
        location: SourceLocation {
            relative_path: c.path.clone(),
            line: Some(first.line),
            column: Some(first.col),
        },
        evidence: Evidence {
            redacted_excerpt: Some(first.excerpt.clone()),
            fingerprint: None,
        },
        explanation: format!(
            "{what}, and nothing in this file — nor in the wrapper or function it hands the request \
             to, when that is a file of this project — looks like an authentication or authorization \
             check (session, auth(), token or signature verification). The check may still live \
             somewhere jetscan cannot follow; this is a pointer for review, not a proven bug. To \
             verify manually: {url_hint} without credentials and confirm it is rejected (401/403) \
             before any data changes."
        ),
        remediation_id: Some(format!("{RULE_ID}:add-server-side-check")),
        references: REFERENCES.to_vec(),
        cwe_ids: vec!["CWE-862"],
        tags: vec![
            "web".to_string(),
            "nextjs".to_string(),
            format!("reach:{}", c.reach),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_urls() {
        assert_eq!(
            route_url("app/api/items/route.ts", "app", true),
            "/api/items"
        );
        assert_eq!(
            route_url("src/app/(admin)/api/x/[id]/route.ts", "src/app", true),
            "/api/x/[id]"
        );
        assert_eq!(
            route_url("pages/api/charge.ts", "pages", false),
            "/api/charge"
        );
        assert_eq!(
            route_url("pages/api/users/index.ts", "pages", false),
            "/api/users"
        );
    }

    #[test]
    fn public_paths() {
        assert!(public_by_path("app/api/stripe-webhook/route.ts"));
        assert!(public_by_path("app/api/auth/[...nextauth]/route.ts"));
        assert!(public_by_path("pages/api/health.ts"));
        assert!(!public_by_path("app/api/items/route.ts"));
        assert!(!public_by_path("app/api/authors/route.ts"));
    }

    #[test]
    fn matcher_coverage() {
        let paths = Matcher::Paths(vec![
            PathPattern::parse("/dashboard/:path*"),
            PathPattern::parse("/login"),
        ]);
        assert!(!paths.may_cover("/api/items"));
        assert!(paths.may_cover("/dashboard/x"));
        assert!(Matcher::Paths(vec![PathPattern::parse("/((?!_next).*)")]).may_cover("/api/x"));
        assert!(Matcher::All.may_cover("/api/x"));
        // Полевой тест 2026-11-12, N5: шаблон с параметром в начале покрывает только свой хвост.
        let embed = Matcher::Paths(vec![PathPattern::parse("/:path*/embed")]);
        assert!(!embed.may_cover("/api/items"));
        assert!(embed.may_cover("/team/x/embed"));
        assert!(Matcher::Paths(vec![PathPattern::parse("/:path*")]).may_cover("/api/items"));
    }

    #[test]
    fn leading_calls() {
        assert_eq!(
            leading_call(" withCron(async (req) => {})").as_deref(),
            Some("withCron")
        );
        assert_eq!(
            leading_call("await revalidate(req)").as_deref(),
            Some("revalidate")
        );
        assert_eq!(leading_call("async (req) => x").as_deref(), None);
        assert_eq!(
            leading_call("serve<Input>(async (ctx) => {})").as_deref(),
            Some("serve")
        );
        assert_eq!(
            leading_call("withX<Map<string, number>>(handler)").as_deref(),
            Some("withX")
        );
        assert_eq!(leading_call("a < b").as_deref(), None);
        assert_eq!(
            leading_call("lib.verify(req)").as_deref(),
            Some("lib.verify")
        );
    }
}
