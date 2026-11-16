//! Шаблоны в коде Swift / Objective-C (по токенам: комментарии и строки не срабатывают).
//! Это НЕ анализ потоков данных: правило видит вызов и его литеральные аргументы, но не откуда
//! пришло значение и выполняется ли код. Поэтому только `potential` / `needs_review`.
//!
//! - IOS-STORAGE-006: `UserDefaults….set(token, forKey: "authToken")`, `@AppStorage("authToken")`,
//!   `[defaults setObject:token forKey:@"authToken"]` — ключ или значение с «секретным» именем (medium/needs_review).
//! - IOS-KEYCHAIN-007: `kSecAttrAccessibleAlways(ThisDeviceOnly)` и аналоги обёрток (KeychainAccess
//!   `.always`, KeychainSwift `.accessibleAlways`) — high/potential (устарели с iOS 12).
//! - IOS-TLS-008: делегат `URLSession`/`WKWebView`, отвечающий `.useCredential` + `URLCredential(trust:)`
//!   без проверки доверия; `allowsAnyHTTPSCertificateForHost`, `kCFStreamSSLValidatesCertificateChain = false`,
//!   Alamofire `DisabledTrustEvaluator` / `.disableEvaluation`, AFNetworking `allowInvalidCertificates = YES`,
//!   `validatesDomainName = NO`, Starscream `disableSSLCertValidation = true` — high/potential.
//! - IOS-WEBVIEW-009: `UIWebView` (устарел, info); `setValue(true, forKey: "allowFileAccessFromFileURLs" /
//!   "allowUniversalAccessFromFileURLs")` (medium); `loadHTMLString(…, baseURL: <file URL>)` (low/needs_review).
//! - IOS-CRYPTO-010: CommonCrypto `kCCOptionECBMode`, DES/3DES/RC4/RC2/Blowfish/CAST, CryptoSwift `ECB()`
//!   (medium/potential); `CC_MD5`/`CC_SHA1`/`Insecure.MD5`/`Insecure.SHA1`/`.md5()` рядом со словом «пароль» (low/needs_review).
//! - IOS-LOG-011: `print`/`debugPrint`/`NSLog`/`DDLog*`/логгеры с переменной вроде password/token (low/needs_review);
//!   `os_log` / `Logger` — только с `%{public}` / `privacy: .public` (по умолчанию динамические строки скрыты).
//!   Внутри `#if DEBUG` — не находка.
//! - IOS-PASTEBOARD-012: `UIPasteboard….string = token` / `setString:` с «секретной» переменной (low/needs_review).
//!
//! Внутри `#if DEBUG` severity не выше `low`. Тестовые файлы не проверяются (решает вызывающий).

use super::{
    CRYPTO_ID, KEYCHAIN_ID, LOG_ID, MAX_HITS_PER_FILE, New, PASTEBOARD_ID, REF_MASVS, RuleOutput,
    STORAGE_ID, TLS_ID, WEBVIEW_ID, is_sensitive_name, words,
};
use crate::ios_audit::lex::{self, Kind, Lang, Lexed, Token};
use crate::ios_audit::types::{Confidence, Severity, normalized_key};
use crate::web_audit::location::LineIndex;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeStats {
    pub files_checked: usize,
    pub files_with_recoveries: usize,
    pub capped: Vec<String>,
}

const REF_USERDEFAULTS: &str = "https://developer.apple.com/documentation/foundation/userdefaults";
const REF_KEYCHAIN: &str =
    "https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility";
const REF_ALWAYS: &str =
    "https://developer.apple.com/documentation/security/ksecattraccessiblealways";
const REF_TRUST: &str = "https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication";
const REF_UIWEBVIEW: &str = "https://developer.apple.com/documentation/uikit/uiwebview";
const REF_WKWEBVIEW: &str = "https://developer.apple.com/documentation/webkit/wkwebview";
const REF_CRYPTO: &str = "https://developer.apple.com/documentation/cryptokit";
const REF_LOG: &str =
    "https://developer.apple.com/documentation/os/logging/generating-log-messages-from-your-code";
const REF_PASTEBOARD: &str = "https://developer.apple.com/documentation/uikit/uipasteboard";

struct File<'a> {
    path: &'a str,
    text: &'a str,
    lang: Lang,
    lexed: &'a Lexed,
    /// Значимые токены: без директив и строк `import`.
    t: Vec<&'a Token>,
    /// Строка каждого значимого токена.
    lines: Vec<u32>,
    idents: HashSet<&'a str>,
    index: LineIndex,
    occurrences: HashMap<String, usize>,
    /// Объявленный тип имени в файле (`token: ActionToken`) — первое объявление.
    types: HashMap<String, String>,
}

/// Проверяет один файл Swift/ObjC (не тестовый). `lexed` — уже размеченный текст.
pub fn check(
    path: &str,
    text: &str,
    lang: Lang,
    lexed: &Lexed,
    out: &mut RuleOutput,
    stats: &mut CodeStats,
) {
    stats.files_checked += 1;
    if lexed.unterminated > 0 {
        stats.files_with_recoveries += 1;
    }
    let index = LineIndex::new(text);
    let line_of = |t: &Token| index.line_col(text, t.start).map_or(0, |(l, _)| l);
    // `import Foundation` (Swift): контекст, а не место находки.
    let mut import_lines = HashSet::new();
    for (k, tok) in lexed.tokens.iter().enumerate() {
        if tok.is_ident("import") && (k == 0 || line_of(&lexed.tokens[k - 1]) != line_of(tok)) {
            import_lines.insert(line_of(tok));
        }
    }
    let mut t = Vec::new();
    let mut lines = Vec::new();
    for tok in &lexed.tokens {
        if tok.kind == Kind::Directive {
            continue;
        }
        let l = line_of(tok);
        if import_lines.contains(&l) {
            continue;
        }
        t.push(tok);
        lines.push(l);
    }
    let idents = lexed
        .tokens
        .iter()
        .filter(|t| t.kind == Kind::Ident || t.kind == Kind::Directive)
        .flat_map(|t| {
            if t.kind == Kind::Directive {
                // `#import <WebKit/WebKit.h>` — тоже контекст.
                t.text
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|w| !w.is_empty())
                    .collect::<Vec<_>>()
            } else {
                vec![t.text.as_str()]
            }
        })
        .collect();
    let mut file = File {
        path,
        text,
        lang,
        lexed,
        t,
        lines,
        idents,
        index,
        occurrences: HashMap::new(),
        types: HashMap::new(),
    };
    file.types = declared_types(&file.t);
    let before = out.findings.len();
    storage(&mut file, out);
    keychain(&mut file, out);
    tls(&mut file, out);
    webview(&mut file, out);
    crypto(&mut file, out);
    logging(&mut file, out);
    pasteboard(&mut file, out);
    if out.findings.len() - before > MAX_HITS_PER_FILE {
        out.findings.truncate(before + MAX_HITS_PER_FILE);
        stats.capped.push(path.to_string());
    }
}

struct Hit {
    rule: &'static str,
    category: &'static str,
    title: String,
    severity: Severity,
    confidence: Confidence,
    explanation: String,
    remediation: &'static str,
    references: Vec<&'static str>,
    cwe: &'static str,
    masvs: &'static str,
}

impl File<'_> {
    fn has(&self, ident: &str) -> bool {
        self.idents.contains(ident)
    }

    fn tok(&self, i: usize) -> Option<&Token> {
        self.t.get(i).copied()
    }

    fn prev(&self, i: usize) -> Option<&Token> {
        i.checked_sub(1).and_then(|p| self.tok(p))
    }

    fn is_dot(&self, i: usize) -> bool {
        self.tok(i)
            .is_some_and(|t| t.is_punct(".") || t.is_punct("?."))
    }

    /// `name(` — вызов, а не объявление (`func name(`, `init(`).
    fn is_call(&self, i: usize) -> bool {
        self.tok(i + 1).is_some_and(|n| n.is_punct("("))
            && !self
                .prev(i)
                .is_some_and(|p| p.is_ident("func") || p.is_ident("class") || p.is_ident("struct"))
    }

    /// Использование имени, а не его объявление (`class X`, `let X =`, `func X`, `case X`).
    fn is_use(&self, i: usize) -> bool {
        !self.prev(i).is_some_and(|p| {
            matches!(
                p.text.as_str(),
                "class"
                    | "struct"
                    | "enum"
                    | "func"
                    | "let"
                    | "var"
                    | "case"
                    | "protocol"
                    | "typealias"
                    | "extension"
                    | "@interface"
                    | "@implementation"
            ) && p.kind == Kind::Ident
        })
    }

    fn close_of(&self, open: usize, o: &str, c: &str) -> Option<usize> {
        let mut depth = 0usize;
        for k in open..self.t.len() {
            if self.t[k].is_punct(o) {
                depth += 1;
            } else if self.t[k].is_punct(c) {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(k);
                }
            }
        }
        None
    }

    /// Аргументы Swift-вызова `name(` в `i`: (метка, начало, конец) без метки.
    fn args(&self, i: usize) -> Option<Vec<(Option<&str>, usize, usize)>> {
        let open = i + 1;
        let close = self.close_of(open, "(", ")")?;
        let mut ranges = Vec::new();
        let mut depth = 0usize;
        let mut from = open + 1;
        for k in open + 1..close {
            let tok = self.t[k];
            if tok.is_punct("(") || tok.is_punct("[") || tok.is_punct("{") {
                depth += 1;
            } else if tok.is_punct(")") || tok.is_punct("]") || tok.is_punct("}") {
                depth = depth.saturating_sub(1);
            } else if tok.is_punct(",") && depth == 0 {
                ranges.push((from, k));
                from = k + 1;
            }
        }
        if from < close {
            ranges.push((from, close));
        }
        Some(
            ranges
                .into_iter()
                .map(|(a, b)| {
                    if b - a >= 2 && self.t[a].kind == Kind::Ident && self.t[a + 1].is_punct(":") {
                        (Some(self.t[a].text.as_str()), a + 2, b)
                    } else {
                        (None, a, b)
                    }
                })
                .collect(),
        )
    }

    /// Идентификаторы цепочки получателя перед `.name` в `i` (`UserDefaults.standard.set` → [standard, UserDefaults]).
    fn receiver_chain(&self, i: usize) -> Vec<&str> {
        let mut out = Vec::new();
        let mut k = i;
        while k >= 2 && self.is_dot(k - 1) {
            let r = self.t[k - 2];
            if r.kind == Kind::Ident {
                out.push(r.text.as_str());
                k -= 2;
            } else if r.is_punct(")") {
                // `UserDefaults(suiteName: x).set` — до парной `(` и имени перед ней.
                let mut depth = 0usize;
                let mut j = k - 2;
                loop {
                    if self.t[j].is_punct(")") {
                        depth += 1;
                    } else if self.t[j].is_punct("(") {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    if j == 0 {
                        return out;
                    }
                    j -= 1;
                }
                if j == 0 || self.t[j - 1].kind != Kind::Ident {
                    return out;
                }
                out.push(self.t[j - 1].text.as_str());
                k = j - 1;
            } else {
                break;
            }
        }
        out
    }

    /// Литерал `true`/`YES`/`1` (в т. ч. `@YES`, `@(YES)`, `NSNumber(value: true)`) в диапазоне.
    fn truthy(&self, from: usize, to: usize) -> bool {
        (from..to).any(|k| {
            let t = self.t[k];
            (t.kind == Kind::Ident && matches!(t.text.as_str(), "true" | "YES" | "kCFBooleanTrue"))
                || (t.kind == Kind::Num && t.text == "1")
        })
    }

    fn falsy(&self, from: usize, to: usize) -> bool {
        (from..to).any(|k| {
            let t = self.t[k];
            (t.kind == Kind::Ident && matches!(t.text.as_str(), "false" | "NO" | "kCFBooleanFalse"))
                || (t.kind == Kind::Num && t.text == "0")
        })
    }

    /// Конец «оператора»: `;` или следующая строка.
    fn statement_end(&self, from: usize) -> usize {
        let line = self.lines.get(from).copied().unwrap_or(0);
        let mut k = from;
        while k < self.t.len() && self.lines[k] == line && !self.t[k].is_punct(";") {
            k += 1;
        }
        k
    }

    fn sites(&self, pred: impl Fn(usize) -> bool) -> Vec<usize> {
        (0..self.t.len()).filter(|&i| pred(i)).collect()
    }

    /// Блок `{…}` функции/метода, в которой стоит токен `at` (или ближайший блок; или весь файл).
    fn function_block(&self, at: usize) -> (usize, usize) {
        let mut opens = Vec::new();
        let mut depth = 0usize;
        for k in (0..at).rev() {
            if self.t[k].is_punct("}") {
                depth += 1;
            } else if self.t[k].is_punct("{") {
                if depth == 0 {
                    opens.push(k);
                } else {
                    depth -= 1;
                }
            }
        }
        let mut innermost = None;
        for &open in &opens {
            let close = self.close_of(open, "{", "}").unwrap_or(self.t.len());
            innermost.get_or_insert((open, close));
            // Заголовок: от предыдущей границы до `{`.
            let mut h = open;
            while h > 0
                && !(self.t[h - 1].is_punct("{")
                    || self.t[h - 1].is_punct("}")
                    || self.t[h - 1].is_punct(";"))
            {
                h -= 1;
            }
            let header = &self.t[h..open];
            let swift_func = header
                .iter()
                .any(|t| t.is_ident("func") || t.is_ident("init"));
            let objc_method = header
                .first()
                .is_some_and(|t| t.is_punct("-") || t.is_punct("+"))
                && header.get(1).is_some_and(|t| t.is_punct("("));
            if swift_func || objc_method {
                return (open, close);
            }
        }
        innermost.unwrap_or((0, self.t.len()))
    }

    fn position(&self, byte: usize) -> (u32, u32) {
        self.index.line_col(self.text, byte).unwrap_or((1, 1))
    }

    /// Строка исходника: комментарии убраны, строковые литералы — `"…"` (кроме ключей из `allow`).
    fn excerpt(&self, byte: usize, allow: &[&str]) -> String {
        let (line, _) = self.position(byte);
        let Some((start, end)) = self.index.line_range(self.text, line as usize) else {
            return String::new();
        };
        let mut out = String::new();
        let mut last = start;
        for tok in &self.lexed.tokens {
            if tok.end <= start {
                continue;
            }
            if tok.start >= end {
                break;
            }
            let from = tok.start.max(start);
            if from > last {
                let gap = &self.text[last..from];
                if gap.chars().all(char::is_whitespace) {
                    out.push_str(gap);
                } else {
                    out.push(' ');
                }
            }
            let at = if self.text.as_bytes().get(tok.start) == Some(&b'@') {
                "@"
            } else {
                ""
            };
            match tok.kind {
                Kind::Str | Kind::Char if allow.contains(&tok.text.as_str()) => {
                    out.push_str(&format!("{at}\"{}\"", tok.text));
                }
                // Интерполяция — код (имена), а не данные: показываем её, литеральные части — `…`.
                Kind::Str if !tok.interps.is_empty() && tok.end <= end => {
                    out.push_str("\"…");
                    for &(s, e) in &tok.interps {
                        out.push_str(&format!("\\({})…", &self.text[s..e]));
                    }
                    out.push('"');
                }
                Kind::Str | Kind::Char => out.push_str(&format!("{at}\"…\"")),
                _ => out.push_str(&self.text[from..tok.end.min(end)]),
            }
            last = tok.end.min(end);
        }
        out
    }

    fn push(&mut self, out: &mut RuleOutput, at: usize, hit: Hit, allow: &[&str]) {
        let tok = self.t[at];
        let (line, column) = self.position(tok.start);
        let excerpt = self.excerpt(tok.start, allow);
        let base = format!("{}\0{}", hit.title, normalized_key(&excerpt));
        let n = self.occurrences.entry(base.clone()).or_insert(0);
        *n += 1;
        let key = format!("{base}\0{n}");
        let (severity, explanation, mut tags) = if tok.debug && hit.severity < Severity::Low {
            (
                Severity::Low,
                format!(
                    "{} The code is inside an `#if DEBUG` block, so it is compiled only into debug builds.",
                    hit.explanation
                ),
                vec!["build:debug-only".to_string()],
            )
        } else {
            (hit.severity, hit.explanation, Vec::new())
        };
        tags.push(format!("masvs:{}", hit.masvs));
        tags.push(format!("lang:{}", self.lang.label()));
        let mut references = hit.references;
        references.push(REF_MASVS);
        out.findings.push(
            New {
                rule: hit.rule,
                category: hit.category,
                title: hit.title,
                severity,
                confidence: hit.confidence,
                path: self.path,
                line: Some(line),
                column: Some(column),
                component: None,
                excerpt: Some(excerpt),
                fingerprint: None,
                key,
                explanation,
                remediation: hit.remediation,
                references,
                cwe_ids: vec![hit.cwe],
                tags,
            }
            .build(),
        );
    }
}

fn is_constant(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Слова, которые делают «токен» не секретом: идентификаторы push/APNs (без ключа провайдера ими
/// нельзя отправить уведомление), курсоры страниц и синхронизации, токены отмены/наблюдения
/// (полевой тест: Element, Signal `pushDeviceToken`/`apnsDeviceToken`, Firefox `ActionToken`).
const NON_SECRET_QUALIFIERS: &[&str] = &[
    "push",
    "device",
    "apns",
    "fcm",
    "voip",
    "notification",
    "registration",
    "page",
    "next",
    "continuation",
    "cursor",
    "sync",
    "change",
    "cancellation",
    "cancel",
    "observer",
    "observation",
    "subscription",
    "action",
    "event",
    "lock",
    "resume",
    "request",
    "completion",
];

/// Имя «секретное» (`password`, `accessToken`, `apiKey`), и рядом нет слова, делающего его не секретом.
pub fn secret_name(name: &str) -> bool {
    is_sensitive_name(name)
        && !words(name)
            .iter()
            .any(|w| NON_SECRET_QUALIFIERS.contains(&w.as_str()))
}

/// Тип не хранит секрет: числа/даты/UUID, наблюдатели, и типы со словами из [`NON_SECRET_QUALIFIERS`].
fn non_secret_type(ty: &str) -> bool {
    matches!(
        ty,
        "Int"
            | "UInt"
            | "Int64"
            | "UInt64"
            | "Bool"
            | "Date"
            | "UUID"
            | "Double"
            | "TimeInterval"
            | "NSNumber"
            | "NSObjectProtocol"
            | "AnyObject"
            | "Any"
            | "AnyCancellable"
            | "NSKeyValueObservation"
            | "CKServerChangeToken"
            | "DispatchWorkItem"
    ) || words(ty)
        .iter()
        .any(|w| NON_SECRET_QUALIFIERS.contains(&w.as_str()))
}

/// Swift: `name: Type` (параметры, свойства, `let`) — первое объявление каждого имени.
fn declared_types(t: &[&Token]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for k in 0..t.len().saturating_sub(2) {
        if t[k].kind == Kind::Ident
            && t[k + 1].is_punct(":")
            && t[k + 2].kind == Kind::Ident
            && t[k + 2]
                .text
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
        {
            out.entry(t[k].text.clone())
                .or_insert_with(|| t[k + 2].text.clone());
        }
    }
    out
}

/// Идентификатор `toks[k]` секретный по имени и выводится значением (не `.count`, `== nil`, ресурсы).
fn value_at(toks: &[&Token], k: usize, types: &HashMap<String, String>) -> bool {
    let tok = toks[k];
    if tok.kind != Kind::Ident || !secret_name(&tok.text) || is_constant(&tok.text) {
        return false;
    }
    // Тип имени говорит, что это не секрет (`token: ActionToken`, `token: NSObjectProtocol`):
    // полевой тест, Firefox `EventQueue`.
    if types.get(&tok.text).is_some_and(|t| non_secret_type(t)) {
        return false;
    }
    // Значение проходит через маскирующую функцию: `redact(pushToken)`, `mask(token)`.
    if k >= 2 && toks[k - 1].is_punct("(") && toks[k - 2].kind == Kind::Ident {
        let f = toks[k - 2].text.to_ascii_lowercase();
        if [
            "redact",
            "mask",
            "hash",
            "sanitiz",
            "obfuscat",
            "truncat",
            "prefix",
            "suffix",
            "fingerprint",
        ]
        .iter()
        .any(|w| f.contains(w))
        {
            return false;
        }
    }
    // Метка аргумента `token:` — не значение.
    if toks.get(k + 1).is_some_and(|n| n.is_punct(":")) {
        return false;
    }
    if let Some(next) = toks.get(k + 1) {
        let member = if next.is_punct(".") || next.is_punct("?.") {
            toks.get(k + 2)
        } else if next.is_punct("?") || next.is_punct("!") {
            toks.get(k + 3)
                .filter(|_| toks.get(k + 2).is_some_and(|d| d.is_punct(".")))
        } else {
            None
        };
        // Поле объекта (`token.version`, `token.expiresAt`) — не сам секрет; выводит значение только
        // поле-представление (`token.value`, `token.rawValue`, `token.base64EncodedString()`…).
        // Поле с «секретным» именем (`session.accessToken`) проверяется как отдельный идентификатор.
        if member.is_some_and(|m| {
            m.kind == Kind::Ident
                && !matches!(
                    m.text.as_str(),
                    "value"
                        | "rawValue"
                        | "string"
                        | "stringValue"
                        | "data"
                        | "utf8"
                        | "base64EncodedString"
                        | "hexadecimalString"
                        | "hexString"
                        | "hex"
                        | "absoluteString"
                        | "debugDescription"
                        | "description"
                        | "token"
                        | "secret"
                        | "password"
                )
        }) {
            return false;
        }
        if next.is_punct("==")
            || next.is_punct("!=")
            || next.is_punct("===")
            || next.is_punct("!==")
        {
            return false;
        }
    }
    if k >= 1 && (toks[k - 1].is_punct("==") || toks[k - 1].is_punct("!=")) {
        return false;
    }
    true
}

/// Секретные переменные в диапазоне токенов (включая интерполяцию строк).
fn sensitive_values(f: &File, from: usize, to: usize) -> Vec<String> {
    let mut found = Vec::new();
    let slice: Vec<&Token> = f.t[from..to].to_vec();
    for k in 0..slice.len() {
        match slice[k].kind {
            Kind::Ident if value_at(&slice, k, &f.types) => found.push(slice[k].text.clone()),
            Kind::Str => {
                let inner = lex::interp_idents(f.text, slice[k], f.lang);
                let inner: Vec<&Token> = inner.iter().collect();
                for j in 0..inner.len() {
                    if value_at(&inner, j, &f.types) {
                        found.push(inner[j].text.clone());
                    }
                }
            }
            _ => {}
        }
    }
    found.dedup();
    found
}

/// Ключ хранения «секретный»: литерал-строка или последний идентификатор (`Keys.authToken`, `.authToken`).
fn sensitive_key(f: &File, from: usize, to: usize) -> Option<String> {
    let toks = &f.t[from..to];
    if let [one] = toks
        && let Some(s) = one.literal_str()
    {
        return secret_name(s).then(|| s.to_string());
    }
    let last = toks.iter().rev().find(|t| t.kind == Kind::Ident)?;
    if toks.iter().any(|t| t.kind == Kind::Str) {
        return None;
    }
    secret_name(&last.text).then(|| last.text.clone())
}

/// Значение — литерал (`""`, `nil`, `false`, число): не секрет.
fn literal_value(f: &File, from: usize, to: usize) -> bool {
    to - from == 1
        && (matches!(f.t[from].kind, Kind::Str | Kind::Num)
            || matches!(
                f.t[from].text.as_str(),
                "nil" | "true" | "false" | "YES" | "NO"
            ))
}

fn storage_hit(what: String) -> Hit {
    Hit {
        rule: STORAGE_ID,
        category: "data_storage",
        title: "Token-like value stored in UserDefaults".to_string(),
        severity: Severity::Medium,
        confidence: Confidence::NeedsReview,
        explanation: format!(
            "{what} UserDefaults is a plain property list in the app's Library/Preferences folder: it is not \
             encrypted beyond the device's data protection, it is included in backups, and it is readable on a \
             jailbroken device or from an unencrypted backup. Store tokens and passwords in the Keychain. Needs \
             review: the name may not match the content (an expiry date, a non-secret flag)."
        ),
        remediation: "use-keychain",
        references: vec![
            REF_USERDEFAULTS,
            REF_KEYCHAIN,
            "https://cwe.mitre.org/data/definitions/312.html",
        ],
        cwe: "CWE-312",
        masvs: "MASVS-STORAGE",
    }
}

fn defaults_receiver(chain: &[&str]) -> bool {
    chain.iter().any(|r| {
        let l = r.to_ascii_lowercase();
        l.contains("defaults") || *r == "standard" && chain.contains(&"UserDefaults")
    })
}

fn storage(f: &mut File, out: &mut RuleOutput) {
    // Swift: `….set(value, forKey: key)`.
    let sites = f.sites(|i| {
        let t = f.t[i];
        (t.is_ident("set") || t.is_ident("setValue")) && f.is_call(i) && f.is_dot(i.wrapping_sub(1))
    });
    for i in sites {
        if !defaults_receiver(&f.receiver_chain(i)) {
            continue;
        }
        let Some(args) = f.args(i) else { continue };
        if args.len() != 2 || args[1].0 != Some("forKey") {
            continue;
        }
        let (_, va, vb) = args[0];
        let (_, ka, kb) = args[1];
        if literal_value(f, va, vb) {
            continue;
        }
        let key = sensitive_key(f, ka, kb);
        let values = sensitive_values(f, va, vb);
        if key.is_none() && values.is_empty() {
            continue;
        }
        let what = match (&key, values.first()) {
            (Some(k), _) => format!(
                "A value is saved to UserDefaults under the key \"{}\".",
                crate::ui::sanitize_line(k)
            ),
            (None, Some(v)) => format!(
                "The variable {} is saved to UserDefaults.",
                crate::ui::sanitize_line(v)
            ),
            _ => String::new(),
        };
        let allow: Vec<String> = key.iter().cloned().collect();
        let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
        f.push(out, i, storage_hit(what), &allow);
    }
    // Swift: `@AppStorage("authToken") var …`.
    let sites = f.sites(|i| {
        f.t[i].is_ident("AppStorage") && f.prev(i).is_some_and(|p| p.is_punct("@")) && f.is_call(i)
    });
    for i in sites {
        let Some(args) = f.args(i) else { continue };
        let Some(&(None, a, b)) = args.first() else {
            continue;
        };
        let Some(key) = sensitive_key(f, a, b) else {
            continue;
        };
        let what = format!(
            "@AppStorage(\"{}\") keeps this property in UserDefaults.",
            crate::ui::sanitize_line(&key)
        );
        f.push(out, i, storage_hit(what), &[key.as_str()]);
    }
    // Objective-C: `[recv setObject:value forKey:key]`.
    if f.lang != Lang::ObjC {
        return;
    }
    let sites = f.sites(|i| {
        let t = f.t[i];
        (t.is_ident("setObject") || t.is_ident("setValue"))
            && f.tok(i + 1).is_some_and(|c| c.is_punct(":"))
    });
    for i in sites {
        // Открывающая `[` сообщения и закрывающая `]`.
        let mut depth = 0usize;
        let mut open = None;
        for k in (0..i).rev() {
            if f.t[k].is_punct("]") {
                depth += 1;
            } else if f.t[k].is_punct("[") {
                if depth == 0 {
                    open = Some(k);
                    break;
                }
                depth -= 1;
            }
        }
        let Some(open) = open else { continue };
        let Some(close) = f.close_of(open, "[", "]") else {
            continue;
        };
        let receiver = &f.t[open + 1..i];
        if !receiver
            .iter()
            .any(|t| t.kind == Kind::Ident && (t.text.to_ascii_lowercase().contains("defaults")))
        {
            continue;
        }
        let mut depth = 0usize;
        let mut for_key = None;
        for k in i + 2..close {
            let t = f.t[k];
            if t.is_punct("[") || t.is_punct("(") {
                depth += 1;
            } else if t.is_punct("]") || t.is_punct(")") {
                depth = depth.saturating_sub(1);
            } else if depth == 0
                && t.is_ident("forKey")
                && f.tok(k + 1).is_some_and(|c| c.is_punct(":"))
            {
                for_key = Some(k);
                break;
            }
        }
        let Some(fk) = for_key else { continue };
        let (va, vb) = (i + 2, fk);
        let (ka, kb) = (fk + 2, close);
        // `@"token"`: `@` + строка.
        let ka = if f.tok(ka).is_some_and(|t| t.is_punct("@")) {
            ka + 1
        } else {
            ka
        };
        if vb <= va || kb <= ka || literal_value(f, va, vb) {
            continue;
        }
        let key = sensitive_key(f, ka, kb);
        let values = sensitive_values(f, va, vb);
        if key.is_none() && values.is_empty() {
            continue;
        }
        let what = match (&key, values.first()) {
            (Some(k), _) => format!(
                "A value is saved to NSUserDefaults under the key \"{}\".",
                crate::ui::sanitize_line(k)
            ),
            (None, Some(v)) => format!(
                "The variable {} is saved to NSUserDefaults.",
                crate::ui::sanitize_line(v)
            ),
            _ => String::new(),
        };
        let allow: Vec<String> = key.iter().cloned().collect();
        let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
        f.push(out, i, storage_hit(what), &allow);
    }
}

fn keychain(f: &mut File, out: &mut RuleOutput) {
    let sites = f.sites(|i| {
        let t = f.t[i];
        if t.kind != Kind::Ident || !f.is_use(i) {
            return false;
        }
        match t.text.as_str() {
            "kSecAttrAccessibleAlways" | "kSecAttrAccessibleAlwaysThisDeviceOnly" => true,
            // KeychainSwift `.accessibleAlways`, Valet/Locksmith аналоги.
            "accessibleAlways" | "accessibleAlwaysThisDeviceOnly" => f.is_dot(i.wrapping_sub(1)),
            // KeychainAccess `.accessibility(.always)` / `Accessibility.always`.
            "always" | "alwaysThisDeviceOnly" => {
                f.is_dot(i.wrapping_sub(1))
                    && (f.has("KeychainAccess") || f.has("Keychain"))
                    && (i >= 2 && f.t[i - 2].is_ident("Accessibility")
                        || i >= 3
                            && f.t[i - 2].is_punct("(")
                            && f.t[i - 3].is_ident("accessibility"))
            }
            _ => false,
        }
    });
    for i in sites {
        let name = f.t[i].text.clone();
        let this_device = name.ends_with("ThisDeviceOnly");
        f.push(
            out,
            i,
            Hit {
                rule: KEYCHAIN_ID,
                category: "data_storage",
                title: format!("Keychain item readable while the device is locked ({name})"),
                severity: Severity::High,
                confidence: Confidence::Potential,
                explanation: format!(
                    "{name} makes the keychain item readable at any time, even when the device is locked and \
                     before the first unlock, so it gets no protection from the passcode.{} Apple deprecated the \
                     Always classes in iOS 12. Use kSecAttrAccessibleWhenUnlocked(ThisDeviceOnly) or, for \
                     background access, kSecAttrAccessibleAfterFirstUnlock(ThisDeviceOnly). Potential: what is \
                     stored in the item is not analysed.",
                    if this_device {
                        ""
                    } else {
                        " Without ThisDeviceOnly the item also migrates to other devices through encrypted backups."
                    }
                ),
                remediation: "use-stricter-keychain-accessibility",
                references: vec![REF_ALWAYS, REF_KEYCHAIN, "https://cwe.mitre.org/data/definitions/311.html"],
                cwe: "CWE-311",
                masvs: "MASVS-STORAGE",
            },
            &[],
        );
    }
}

fn tls_hit(title: &str, explanation: String) -> Hit {
    Hit {
        rule: TLS_ID,
        category: "network",
        title: title.to_string(),
        severity: Severity::High,
        confidence: Confidence::Potential,
        explanation,
        remediation: "use-default-trust-evaluation",
        references: vec![REF_TRUST, "https://cwe.mitre.org/data/definitions/295.html"],
        cwe: "CWE-295",
        masvs: "MASVS-NETWORK",
    }
}

/// В блоке есть проверка доверия: оценка, пиннинг, сверка сертификата, делегирование проверяющему.
fn evaluates_trust(f: &File, from: usize, to: usize) -> bool {
    (from..to.min(f.t.len())).any(|k| {
        let t = f.t[k];
        if t.kind != Kind::Ident {
            return false;
        }
        let l = t.text.to_ascii_lowercase();
        [
            "evaluat",
            "pin",
            "validat",
            "verif",
            "seccertificate",
            "sectrustget",
            "sectrustcopy",
            "trustkit",
            "checkserver",
            "istrusted",
            "sectrustsetanchor",
            "secpolicycreate",
        ]
        .iter()
        .any(|w| l.contains(w))
    })
}

fn tls(f: &mut File, out: &mut RuleOutput) {
    // Делегат: `.useCredential` + `URLCredential(trust:)` без проверки.
    let sites = f.sites(|i| {
        let t = f.t[i];
        (t.is_ident("URLCredential")
            && f.tok(i + 1).is_some_and(|p| p.is_punct("("))
            && f.tok(i + 2).is_some_and(|l| l.is_ident("trust")))
            || (t.is_ident("credentialForTrust") && f.tok(i + 1).is_some_and(|c| c.is_punct(":")))
    });
    let mut reported_blocks = HashSet::new();
    for i in sites {
        let (open, close) = f.function_block(i);
        let use_credential = (open..close.min(f.t.len())).any(|k| {
            let t = f.t[k];
            t.is_ident("useCredential") || t.is_ident("NSURLSessionAuthChallengeUseCredential")
        });
        if !use_credential || evaluates_trust(f, open, close) || !reported_blocks.insert(open) {
            continue;
        }
        let host_scoped = (open..close.min(f.t.len())).any(|k| f.t[k].is_ident("host"));
        f.push(
            out,
            i,
            tls_hit(
                "Authentication challenge accepts any server certificate",
                format!(
                    "This challenge handler answers .useCredential with a credential built from the server's own \
                     trust object without evaluating it (no SecTrustEvaluateWithError, no pinning check), so any \
                     certificate is accepted{} and the connection can be intercepted with a self-signed \
                     certificate. Potential: whether this delegate is installed on a session that is used is not \
                     traced. Call completionHandler(.performDefaultHandling, nil) unless you evaluate the trust \
                     yourself (pinning) and it passes.",
                    if host_scoped {
                        " (the handler checks the host name, but that does not verify the certificate)"
                    } else {
                        ""
                    }
                ),
            ),
            &[],
        );
    }
    // Явные флаги «принимать всё».
    let sites = f.sites(|i| {
        let t = f.t[i];
        if t.kind != Kind::Ident || !f.is_use(i) {
            return false;
        }
        match t.text.as_str() {
            "allowsAnyHTTPSCertificateForHost" | "setAllowsAnyHTTPSCertificate" => true,
            "DisabledTrustEvaluator" | "DisabledEvaluator" => true,
            "disableEvaluation" => f.is_dot(i.wrapping_sub(1)),
            "kCFStreamSSLValidatesCertificateChain"
            | "validatesDomainName"
            | "setValidatesDomainName" => {
                let end = f.statement_end(i).min(i + 8);
                f.falsy(i + 1, end)
            }
            "kCFStreamSSLAllowsAnyRoot"
            | "kCFStreamSSLAllowsExpiredCertificates"
            | "kCFStreamSSLAllowsExpiredRoots"
            | "allowInvalidCertificates"
            | "setAllowInvalidCertificates"
            | "disableSSLCertValidation"
            | "allowSelfSignedCertificates" => {
                let end = f.statement_end(i).min(i + 8);
                f.truthy(i + 1, end)
            }
            _ => false,
        }
    });
    for i in sites {
        let name = f.t[i].text.clone();
        let (title, what) = match name.as_str() {
            "allowsAnyHTTPSCertificateForHost" | "setAllowsAnyHTTPSCertificate" => (
                "Private API accepts any HTTPS certificate",
                format!(
                    "{name} (a private NSURLRequest API) turns off certificate checks for a host."
                ),
            ),
            "DisabledTrustEvaluator" | "DisabledEvaluator" | "disableEvaluation" => (
                "Alamofire server trust evaluation disabled",
                format!(
                    "Alamofire {name} accepts every server certificate for the hosts it is mapped to."
                ),
            ),
            "validatesDomainName" | "setValidatesDomainName" => (
                "TLS host name validation disabled",
                format!(
                    "{name} = NO accepts a valid certificate issued for any domain, so an attacker's own \
                     certificate passes for your server."
                ),
            ),
            _ => (
                "TLS certificate validation disabled",
                format!("{name} turns off certificate validation for these connections."),
            ),
        };
        f.push(
            out,
            i,
            tls_hit(
                title,
                format!(
                    "{what} Anyone on the network path can then read and change the traffic with a self-signed \
                     certificate. Potential: whether this code path runs in release builds is not traced. Keep \
                     the default trust evaluation; for custom CAs or pinning, evaluate the trust explicitly."
                ),
            ),
            &[],
        );
    }
}

/// Аргумент — файловый URL (`Bundle.main.bundleURL`, `URL(fileURLWithPath:)`, `"file://…"`).
fn file_url(f: &File, from: usize, to: usize) -> bool {
    (from..to).any(|k| {
        let t = f.t[k];
        match t.kind {
            Kind::Ident => matches!(
                t.text.as_str(),
                "bundleURL"
                    | "resourceURL"
                    | "fileURLWithPath"
                    | "documentDirectory"
                    | "documentsDirectory"
                    | "cachesDirectory"
                    | "temporaryDirectory"
                    | "libraryDirectory"
                    | "NSDocumentDirectory"
                    | "NSCachesDirectory"
                    | "fileURLWithPath:"
            ),
            Kind::Str => t.text.starts_with("file://"),
            _ => false,
        }
    })
}

fn webview(f: &mut File, out: &mut RuleOutput) {
    let uiwebview = f.sites(|i| f.t[i].is_ident("UIWebView") && f.is_use(i));
    let uses_uiwebview = !uiwebview.is_empty();
    if let Some(&i) = uiwebview.first() {
        f.push(
            out,
            i,
            Hit {
                rule: WEBVIEW_ID,
                category: "platform",
                title: "Deprecated UIWebView is used".to_string(),
                severity: Severity::Info,
                confidence: Confidence::NeedsReview,
                explanation: "UIWebView is deprecated (iOS 12) and App Store Connect no longer accepts new apps or \
                              updates that use it. It cannot disable JavaScript, lets file:// pages read other \
                              files, and has no per-origin content controls. Migrate to WKWebView. (One finding per \
                              file.)"
                    .to_string(),
                remediation: "migrate-to-wkwebview",
                references: vec![REF_UIWEBVIEW, REF_WKWEBVIEW, "https://cwe.mitre.org/data/definitions/477.html"],
                cwe: "CWE-477",
                masvs: "MASVS-PLATFORM",
            },
            &[],
        );
    }
    // `setValue(true, forKey: "allowFileAccessFromFileURLs")` (скрытые свойства WKPreferences).
    let keys = [
        "allowFileAccessFromFileURLs",
        "allowUniversalAccessFromFileURLs",
    ];
    let sites = f.sites(|i| {
        let t = f.t[i];
        t.literal_str().is_some_and(|s| keys.contains(&s))
            && (i.saturating_sub(12)..i).any(|k| f.t[k].is_ident("setValue"))
    });
    for i in sites {
        let from = (i.saturating_sub(12)..i)
            .rev()
            .find(|&k| f.t[k].is_ident("setValue"))
            .unwrap_or(i);
        if !f.truthy(from + 1, i) {
            continue;
        }
        let key = f.t[i].text.clone();
        f.push(
            out,
            i,
            Hit {
                rule: WEBVIEW_ID,
                category: "platform",
                title: format!("WebView lets file:// pages read other files ({key})"),
                severity: Severity::Medium,
                confidence: Confidence::Potential,
                explanation: format!(
                    "Setting the private WebKit preference {key} to true through setValue(_:forKey:) lets JavaScript \
                     in a file:// page read {} — a malicious HTML file opened in this web view can read the app's \
                     files and send them out. Remove it; use loadFileURL(_:allowingReadAccessTo:) with the narrowest \
                     folder.",
                    if key.starts_with("allowUniversal") {
                        "any origin, including other sites"
                    } else {
                        "other file:// URLs"
                    }
                ),
                remediation: "restrict-webview-file-access",
                references: vec![REF_WKWEBVIEW, "https://cwe.mitre.org/data/definitions/200.html"],
                cwe: "CWE-200",
                masvs: "MASVS-PLATFORM",
            },
            &[key.as_str()],
        );
    }
    // `loadHTMLString(html, baseURL: <file URL>)`.
    let sites = f.sites(|i| f.t[i].is_ident("loadHTMLString"));
    for i in sites {
        let base = if f.is_call(i) {
            f.args(i).and_then(|args| {
                args.iter()
                    .find(|(l, _, _)| *l == Some("baseURL"))
                    .map(|&(_, a, b)| (a, b))
            })
        } else if f.tok(i + 1).is_some_and(|c| c.is_punct(":")) {
            // ObjC `loadHTMLString:html baseURL:url]`.
            let end = f.statement_end(i);
            (i..end)
                .find(|&k| {
                    f.t[k].is_ident("baseURL") && f.tok(k + 1).is_some_and(|c| c.is_punct(":"))
                })
                .map(|k| (k + 2, end))
        } else {
            None
        };
        let Some((a, b)) = base else { continue };
        if !file_url(f, a, b) {
            continue;
        }
        f.push(
            out,
            i,
            Hit {
                rule: WEBVIEW_ID,
                category: "platform",
                title: "HTML string loaded with a file:// base URL".to_string(),
                severity: if uses_uiwebview { Severity::Medium } else { Severity::Low },
                confidence: Confidence::NeedsReview,
                explanation: format!(
                    "loadHTMLString(_:baseURL:) is given a file URL as the base, so scripts in that HTML run with \
                     a file:// origin and can reach local files{}. If any part of the HTML comes from the network \
                     or the user, that is a path to reading app data. Needs review: fine for fully static, bundled \
                     HTML; otherwise pass nil (or an https URL) as baseURL.",
                    if uses_uiwebview {
                        " (UIWebView allows such pages to read any file the app can)"
                    } else {
                        ""
                    }
                ),
                remediation: "restrict-webview-file-access",
                references: vec![REF_WKWEBVIEW, "https://cwe.mitre.org/data/definitions/73.html"],
                cwe: "CWE-73",
                masvs: "MASVS-PLATFORM",
            },
            &[],
        );
    }
}

/// В функции вокруг `at` (или ±40 токенов) есть слово password/passphrase/pwd/credential.
fn password_nearby(f: &File, at: usize) -> bool {
    let (open, close) = f.function_block(at);
    let (from, to) = if open == 0 && close == f.t.len() {
        (at.saturating_sub(40), (at + 40).min(f.t.len()))
    } else {
        (open.saturating_sub(30), close.min(f.t.len()))
    };
    (from..to).any(|k| {
        let tok = f.t[k];
        if !matches!(tok.kind, Kind::Ident | Kind::Str) {
            return false;
        }
        words(&tok.text).iter().any(|x| {
            matches!(
                x.as_str(),
                "password" | "passwd" | "passphrase" | "pwd" | "credential" | "credentials"
            )
        })
    })
}

/// Токен — часть объявления константы-псевдонима (`static let ecbMode = Options(rawValue: kCCOptionECBMode)`,
/// `case ecb = kCCOptionECBMode`): обёртка библиотеки, а не использование (полевой тест, Signal).
fn alias_declaration(f: &File, i: usize) -> bool {
    let line = f.lines[i];
    let mut k = i;
    while k > 0 && f.lines[k - 1] == line {
        k -= 1;
    }
    let head: Vec<&str> = f.t[k..i].iter().map(|t| t.text.as_str()).collect();
    let decl = head
        .iter()
        .position(|w| matches!(*w, "let" | "case"))
        .is_some_and(|p| head.get(p + 2) == Some(&"="));
    decl && head.iter().any(|w| matches!(*w, "static" | "case"))
}

fn crypto(f: &mut File, out: &mut RuleOutput) {
    let sites = f.sites(|i| {
        let t = f.t[i];
        t.kind == Kind::Ident
            && f.is_use(i)
            && !alias_declaration(f, i)
            && (matches!(
                t.text.as_str(),
                "kCCOptionECBMode"
                    | "kCCAlgorithmDES"
                    | "kCCAlgorithm3DES"
                    | "kCCAlgorithmRC4"
                    | "kCCAlgorithmRC2"
                    | "kCCAlgorithmBlowfish"
                    | "kCCAlgorithmCAST"
            ) || (t.text == "ECB"
                && f.tok(i + 1).is_some_and(|p| p.is_punct("("))
                && f.tok(i + 2).is_some_and(|p| p.is_punct(")"))
                && (f.has("CryptoSwift") || f.has("blockMode"))))
    });
    for i in sites {
        let name = f.t[i].text.clone();
        let (title, problem) = match name.as_str() {
            "kCCOptionECBMode" | "ECB" => (
                "Block cipher in ECB mode".to_string(),
                "ECB encrypts equal plaintext blocks to equal ciphertext blocks (patterns leak) and has no \
                 integrity. Use AES-GCM (CryptoKit AES.GCM) or ChaCha20-Poly1305."
                    .to_string(),
            ),
            other => (
                format!("Broken or legacy cipher ({other})"),
                format!(
                    "{other} is a broken or legacy cipher (short keys or 64-bit blocks). Use AES-GCM (CryptoKit \
                     AES.GCM) or ChaCha20-Poly1305."
                ),
            ),
        };
        f.push(
            out,
            i,
            Hit {
                rule: CRYPTO_ID,
                category: "cryptography",
                title,
                severity: Severity::Medium,
                confidence: Confidence::Potential,
                explanation: format!(
                    "{problem} Potential: what is encrypted (and whether it is sensitive) is not analysed."
                ),
                remediation: "use-authenticated-encryption",
                references: vec![REF_CRYPTO, "https://cwe.mitre.org/data/definitions/327.html"],
                cwe: "CWE-327",
                masvs: "MASVS-CRYPTO",
            },
            &[],
        );
    }
    let sites = f.sites(|i| {
        let t = f.t[i];
        if t.kind != Kind::Ident || !f.is_use(i) {
            return false;
        }
        match t.text.as_str() {
            "CC_MD5" | "CC_SHA1" => f.is_call(i),
            "MD5" | "SHA1" => i >= 2 && f.is_dot(i - 1) && f.t[i - 2].is_ident("Insecure"),
            "md5" | "sha1" => f.is_dot(i.wrapping_sub(1)) && f.is_call(i),
            _ => false,
        }
    });
    for i in sites {
        if !password_nearby(f, i) {
            continue;
        }
        let name = f.t[i].text.clone();
        let alg = if name.to_ascii_uppercase().contains("MD5") {
            "MD5"
        } else {
            "SHA-1"
        };
        f.push(
            out,
            i,
            Hit {
                rule: CRYPTO_ID,
                category: "cryptography",
                title: format!("Fast hash {alg} used near password handling"),
                severity: Severity::Low,
                confidence: Confidence::NeedsReview,
                explanation: format!(
                    "{name} appears in code that mentions a password. {alg} is fast (and here probably unsalted), so \
                     a leaked hash is cheap to brute-force; for passwords use a slow, salted KDF (PBKDF2 via \
                     CCKeyDerivationPBKDF, scrypt, Argon2). Needs review: the hash may be used for something else, \
                     such as a checksum or a protocol that requires it."
                ),
                remediation: "use-password-kdf",
                references: vec![REF_CRYPTO, "https://cwe.mitre.org/data/definitions/916.html"],
                cwe: "CWE-916",
                masvs: "MASVS-CRYPTO",
            },
            &[],
        );
    }
}

const PLAIN_LOG_FUNCS: &[&str] = &[
    "print",
    "debugPrint",
    "NSLog",
    "DDLogVerbose",
    "DDLogDebug",
    "DDLogInfo",
    "DDLogWarn",
    "DDLogError",
];
const LOGGER_METHODS: &[&str] = &[
    "trace", "debug", "info", "notice", "warning", "error", "critical", "fault", "verbose", "log",
];

fn log_hit(call: &str, names: &[String], extra: &str) -> Hit {
    let names = crate::ui::sanitize_line(&names.join(", "));
    Hit {
        rule: LOG_ID,
        category: "logging",
        title: format!("Possibly sensitive value logged ({names})"),
        severity: Severity::Low,
        confidence: Confidence::NeedsReview,
        explanation: format!(
            "{call}(…) is passed {names}, whose name says it is a secret.{extra} Device logs are visible in \
             Console.app and in sysdiagnose/bug reports, and log files written by logging libraries end up in \
             backups and support uploads. Needs review: the name may not match the content. Log a redacted form \
             or nothing."
        ),
        remediation: "redact-logs",
        references: vec![REF_LOG, "https://cwe.mitre.org/data/definitions/532.html"],
        cwe: "CWE-532",
        masvs: "MASVS-STORAGE",
    }
}

fn logging(f: &mut File, out: &mut RuleOutput) {
    let os_logger = f.has("Logger") && (f.has("os") || f.has("OSLog"));
    // `print(…)`, `NSLog(…)`, `DDLogInfo(…)` — без получателя.
    let sites = f.sites(|i| {
        let t = f.t[i];
        t.kind == Kind::Ident
            && PLAIN_LOG_FUNCS.contains(&t.text.as_str())
            && f.is_call(i)
            && !t.debug
            && (!f.is_dot(i.wrapping_sub(1)) || i >= 2 && f.t[i - 2].is_ident("Swift"))
    });
    for i in sites {
        let Some(args) = f.args(i) else { continue };
        let mut names = Vec::new();
        for &(label, a, b) in &args {
            if matches!(label, Some("separator" | "terminator" | "to")) {
                continue;
            }
            names.extend(sensitive_values(f, a, b));
        }
        names.dedup();
        if names.is_empty() {
            continue;
        }
        let call = f.t[i].text.clone();
        let extra = if call == "print" || call == "debugPrint" {
            " print() writes to standard output, which is shown in the Xcode console and captured by some crash and \
             logging SDKs."
        } else {
            ""
        };
        f.push(out, i, log_hit(&call, &names, extra), &[]);
    }
    // `os_log("…%{public}@…", token)`.
    let sites = f.sites(|i| f.t[i].is_ident("os_log") && f.is_call(i) && !f.t[i].debug);
    for i in sites {
        let Some(args) = f.args(i) else { continue };
        let public = args.iter().any(|&(_, a, b)| {
            (a..b).any(|k| f.t[k].kind == Kind::Str && f.t[k].text.contains("%{public}"))
        });
        if !public {
            continue;
        }
        let mut names = Vec::new();
        for &(_, a, b) in &args {
            names.extend(sensitive_values(f, a, b));
        }
        names.dedup();
        if names.is_empty() {
            continue;
        }
        f.push(
            out,
            i,
            log_hit(
                "os_log",
                &names,
                " The format string marks arguments %{public}, so they are not redacted.",
            ),
            &[],
        );
    }
    // Логгеры: `logger.info("…\(token, privacy: .public)…")` (os.Logger) или `log.debug(token)` (прочие).
    let sites = f.sites(|i| {
        let t = f.t[i];
        t.kind == Kind::Ident
            && LOGGER_METHODS.contains(&t.text.as_str())
            && f.is_call(i)
            && !t.debug
            && f.is_dot(i.wrapping_sub(1))
            && i >= 2
            && f.t[i - 2].kind == Kind::Ident
            && f.t[i - 2].text.to_ascii_lowercase().contains("log")
    });
    for i in sites {
        let Some(args) = f.args(i) else { continue };
        let receiver = f.t[i - 2].text.clone();
        let method = f.t[i].text.clone();
        let mut names = Vec::new();
        if os_logger {
            // Только интерполяции с `privacy: .public`.
            for &(_, a, b) in &args {
                for k in a..b {
                    let tok = f.t[k];
                    if tok.kind != Kind::Str {
                        continue;
                    }
                    for &(s, e) in &tok.interps {
                        let inner = &f.text[s..e];
                        if !inner.contains(".public") {
                            continue;
                        }
                        let lexed = lex::lex(inner, f.lang);
                        let toks: Vec<&Token> = lexed.tokens.iter().collect();
                        for j in 0..toks.len() {
                            if value_at(&toks, j, &f.types) {
                                names.push(toks[j].text.clone());
                            }
                        }
                    }
                }
            }
        } else {
            for &(_, a, b) in &args {
                names.extend(sensitive_values(f, a, b));
            }
        }
        names.dedup();
        if names.is_empty() {
            continue;
        }
        let extra = if os_logger {
            " The interpolation is marked privacy: .public, so the unified log stores it unredacted."
        } else {
            ""
        };
        f.push(
            out,
            i,
            log_hit(&format!("{receiver}.{method}"), &names, extra),
            &[],
        );
    }
}

fn pasteboard(f: &mut File, out: &mut RuleOutput) {
    let on_pasteboard_line = |f: &File, i: usize| {
        let line = f.lines[i];
        (0..i).rev().take_while(|&k| f.lines[k] == line).any(|k| {
            f.t[k].kind == Kind::Ident && f.t[k].text.to_ascii_lowercase().contains("pasteboard")
        })
    };
    let sites = f.sites(|i| {
        let t = f.t[i];
        let assign = (t.is_ident("string") || t.is_ident("strings"))
            && f.is_dot(i.wrapping_sub(1))
            && f.tok(i + 1).is_some_and(|e| e.is_punct("="));
        let setter = (t.is_ident("setString") || t.is_ident("setValue"))
            && f.tok(i + 1)
                .is_some_and(|c| c.is_punct("(") || c.is_punct(":"));
        (assign || setter) && on_pasteboard_line(f, i)
    });
    for i in sites {
        let end = f.statement_end(i);
        let names = sensitive_values(f, i + 2, end.max(i + 2));
        if names.is_empty() {
            continue;
        }
        let names = crate::ui::sanitize_line(&names.join(", "));
        f.push(
            out,
            i,
            Hit {
                rule: PASTEBOARD_ID,
                category: "data_storage",
                title: format!("Possibly sensitive value copied to the pasteboard ({names})"),
                severity: Severity::Low,
                confidence: Confidence::NeedsReview,
                explanation: format!(
                    "{names} is written to the general pasteboard, which every app can read (iOS shows a paste \
                     banner, but the value stays there) and which Universal Clipboard syncs to the user's other \
                     devices. Needs review: copying a password is sometimes the feature; if so, use \
                     UIPasteboard.setItems(_:options:) with .localOnly and an .expirationDate."
                ),
                remediation: "limit-pasteboard-exposure",
                references: vec![REF_PASTEBOARD, "https://cwe.mitre.org/data/definitions/200.html"],
                cwe: "CWE-200",
                masvs: "MASVS-PLATFORM",
            },
            &[],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(path: &str, text: &str, lang: Lang) -> Vec<(String, String, Severity, u32)> {
        let mut out = RuleOutput::default();
        let mut stats = CodeStats::default();
        let lexed = lex::lex(text, lang);
        check(path, text, lang, &lexed, &mut out, &mut stats);
        out.findings
            .into_iter()
            .map(|f| {
                (
                    f.rule_id.to_string(),
                    f.title,
                    f.severity,
                    f.location.line.unwrap(),
                )
            })
            .collect()
    }

    fn lines(got: &[(String, String, Severity, u32)]) -> Vec<u32> {
        let mut v: Vec<u32> = got.iter().map(|g| g.3).collect();
        v.sort();
        v
    }

    fn sorted(
        mut got: Vec<(String, String, Severity, u32)>,
    ) -> Vec<(String, String, Severity, u32)> {
        got.sort_by_key(|g| g.3);
        got
    }

    const SW: &str = "App/A.swift";
    const OC: &str = "App/A.m";

    #[test]
    fn user_defaults_tokens() {
        let text = "import Foundation\nfunc save(accessToken: String, theme: String) {\n UserDefaults.standard.set(accessToken, forKey: \"access_token\")\n UserDefaults.standard.set(theme, forKey: \"theme\")\n UserDefaults.standard.set(\"\", forKey: \"authToken\")\n let defaults = UserDefaults(suiteName: \"g\")\n defaults?.set(user.password, forKey: Keys.pw)\n cache.set(accessToken, forKey: \"token\")\n UserDefaults.standard.set(Date(), forKey: \"tokenRefreshedAt\")\n}\nstruct V { @AppStorage(\"authToken\") var token = \"\" }";
        let got = sorted(run(SW, text, Lang::Swift));
        assert_eq!(lines(&got), vec![3, 7, 11]);
        assert!(
            got.iter()
                .all(|g| g.0 == STORAGE_ID && g.2 == Severity::Medium)
        );
        let objc = "- (void)save:(NSString *)token {\n [[NSUserDefaults standardUserDefaults] setObject:token forKey:@\"authToken\"];\n [[NSUserDefaults standardUserDefaults] setObject:@\"dark\" forKey:@\"theme\"];\n [dict setObject:token forKey:@\"token\"];\n}";
        assert_eq!(lines(&run(OC, objc, Lang::ObjC)), vec![2]);
    }

    #[test]
    fn keychain_always() {
        let text = "let q: [String: Any] = [kSecAttrAccessible as String: kSecAttrAccessibleAlways]\nlet r = kSecAttrAccessibleAlwaysThisDeviceOnly\n// kSecAttrAccessibleAlways\nlet ok = kSecAttrAccessibleAfterFirstUnlock\nimport KeychainAccess\nlet k = Keychain(service: \"x\").accessibility(.always)\nlet s = KeychainSwift(); s.set(v, forKey: \"k\", withAccess: .accessibleAlways)\nlet a = Animation.always";
        let got = sorted(run(SW, text, Lang::Swift));
        assert_eq!(lines(&got), vec![1, 2, 6, 7]);
        assert!(
            got.iter()
                .all(|g| g.0 == KEYCHAIN_ID && g.2 == Severity::High)
        );
    }

    #[test]
    fn trust_all_delegates() {
        let bad = "class D: NSObject, URLSessionDelegate {\n func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {\n  completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))\n }\n}";
        let got = sorted(run(SW, bad, Lang::Swift));
        assert_eq!(lines(&got), vec![3]);
        assert_eq!(got[0].0, TLS_ID);
        let good = "class D: NSObject, URLSessionDelegate {\n func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {\n  guard let trust = challenge.protectionSpace.serverTrust, SecTrustEvaluateWithError(trust, nil), pinned(trust) else { return completionHandler(.cancelAuthenticationChallenge, nil) }\n  completionHandler(.useCredential, URLCredential(trust: trust))\n }\n}";
        assert!(run(SW, good, Lang::Swift).is_empty());
        let objc = "- (void)connection:(NSURLConnection *)c willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)ch {\n [ch.sender useCredential:[NSURLCredential credentialForTrust:ch.protectionSpace.serverTrust] forAuthenticationChallenge:ch];\n}\n@implementation NSURLRequest (X)\n+ (BOOL)allowsAnyHTTPSCertificateForHost:(NSString *)host { return YES; }\n@end\nsettings[(NSString *)kCFStreamSSLValidatesCertificateChain] = @NO;\npolicy.allowInvalidCertificates = YES;\npolicy.validatesDomainName = NO;\npolicy.allowInvalidCertificates = NO;";
        assert_eq!(lines(&run(OC, objc, Lang::ObjC)), vec![2, 5, 7, 8, 9]);
        let af = "let m = ServerTrustManager(evaluators: [\"dev.example.com\": DisabledTrustEvaluator()])\nlet p: [String: ServerTrustPolicy] = [\"x\": .disableEvaluation]\nsocket.disableSSLCertValidation = true\n/* DisabledTrustEvaluator() */";
        assert_eq!(lines(&run(SW, af, Lang::Swift)), vec![1, 2, 3]);
    }

    #[test]
    fn webview_patterns() {
        let text = "import WebKit\nclass V { let w = UIWebView()\n var u: UIWebView?\n func f(c: WKWebViewConfiguration, web: WKWebView) {\n  c.preferences.setValue(true, forKey: \"allowFileAccessFromFileURLs\")\n  c.setValue(false, forKey: \"allowUniversalAccessFromFileURLs\")\n  web.loadHTMLString(html, baseURL: Bundle.main.bundleURL)\n  web.loadHTMLString(html, baseURL: nil)\n }\n}";
        let got = sorted(run(SW, text, Lang::Swift));
        assert_eq!(lines(&got), vec![2, 5, 7]);
        assert_eq!(got[0].2, Severity::Info);
        assert_eq!(got[1].2, Severity::Medium);
        assert_eq!(got[2].2, Severity::Medium);
        let objc = "[web loadHTMLString:html baseURL:[NSURL fileURLWithPath:path]];\n[prefs setValue:@YES forKey:@\"allowUniversalAccessFromFileURLs\"];";
        let got = sorted(run(OC, objc, Lang::ObjC));
        assert_eq!(lines(&got), vec![1, 2]);
        assert_eq!(got[0].2, Severity::Low);
    }

    #[test]
    fn crypto_patterns() {
        let text = "import CommonCrypto\nfunc enc() { CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding), k, kl, nil, d, dl, o, ol, &n)\n CCCrypt(op, CCAlgorithm(kCCAlgorithmDES), 0, k, kl, iv, d, dl, o, ol, &n) }\nfunc hashPassword(_ password: String) -> Data { var d = Data(count: 16); CC_MD5(p, l, &d); return d }\nfunc cacheKey(url: String) { CC_MD5(p, l, &d) }\nfunc legacy(pwd: String) { let h = Insecure.SHA1.hash(data: Data(pwd.utf8)) }\nimport CryptoSwift\nlet a = try AES(key: k, blockMode: ECB(), padding: .pkcs7)";
        let got = sorted(run(SW, text, Lang::Swift));
        assert_eq!(lines(&got), vec![2, 3, 4, 6, 8]);
        assert_eq!(got[2].2, Severity::Low);
        assert_eq!(got[3].1, "Fast hash SHA-1 used near password handling");
    }

    #[test]
    fn logging_of_secrets() {
        let text = "func f(password: String, token: String?, tokens: [String]) {\n print(\"login \\(password)\")\n NSLog(\"t=%@\", token!)\n print(\"has token: \\(token != nil)\")\n print(\"n=\\(tokens.count)\")\n print(\"password reset requested\")\n #if DEBUG\n print(token)\n #endif\n debugPrint(user.refreshToken)\n print(token.isEmpty)\n}";
        let got = sorted(run(SW, text, Lang::Swift));
        assert_eq!(lines(&got), vec![2, 3, 10]);
        assert!(got.iter().all(|g| g.0 == LOG_ID && g.2 == Severity::Low));
        // os.Logger: по умолчанию приватно; `.public` — находка.
        let text = "import os\nlet logger = Logger(subsystem: \"a\", category: \"b\")\nfunc f(token: String) {\n logger.info(\"t=\\(token)\")\n logger.info(\"t=\\(token, privacy: .public)\")\n os_log(\"%@\", token)\n os_log(\"%{public}@\", token)\n}";
        assert_eq!(lines(&run(SW, text, Lang::Swift)), vec![5, 7]);
        // Прочие логгеры (SwiftyBeaver/XCGLogger) — как print.
        let text = "func f(token: String) { log.debug(\"t \\(token)\") }";
        assert_eq!(lines(&run(SW, text, Lang::Swift)), vec![1]);
        let objc = "- (void)f:(NSString *)password { NSLog(@\"pw %@\", password); DDLogInfo(@\"len %lu\", password.length); }";
        assert_eq!(lines(&run(OC, objc, Lang::ObjC)), vec![1]);
    }

    #[test]
    fn pasteboard_writes() {
        let text = "func copy(password: String, name: String) {\n UIPasteboard.general.string = password\n UIPasteboard.general.string = name\n let pb = UIPasteboard.general; pb.setString(password)\n label.string = password\n}";
        let got = sorted(run(SW, text, Lang::Swift));
        assert_eq!(lines(&got), vec![2, 4]);
        let objc = "[UIPasteboard generalPasteboard].string = self.authToken;";
        assert_eq!(lines(&run(OC, objc, Lang::ObjC)), vec![1]);
    }

    #[test]
    fn comments_strings_and_declarations_are_not_findings() {
        let text = "// UserDefaults.standard.set(token, forKey: \"token\")\n/* kSecAttrAccessibleAlways */\nlet s = \"completionHandler(.useCredential, URLCredential(trust: t))\"\nlet doc = \"\"\"\nprint(password)\nUIWebView\n\"\"\"\nclass DisabledTrustEvaluator {}\nfunc print(_ password: String) {}";
        assert!(run(SW, text, Lang::Swift).is_empty());
    }

    #[test]
    fn debug_blocks_are_capped_at_low() {
        let text = "#if DEBUG\nlet q = kSecAttrAccessibleAlways\n#endif";
        let got = sorted(run(SW, text, Lang::Swift));
        assert_eq!(got[0].2, Severity::Low);
    }

    #[test]
    fn field_test_false_positive_patterns() {
        // Signal: значение через `redact(…)`; поле объекта `token.version`; push-токены — не секрет.
        let text = "func f(pushToken: String, token: DisappearingToken) {\n Logger.info(\"t \\(redact(pushToken))\")\n Logger.info(\"v \\(token.version)\")\n print(\"raw \\(token.value)\")\n}";
        assert_eq!(lines(&run(SW, text, Lang::Swift)), vec![4]);
        // Element: APNs/push device token в NSUserDefaults — идентификатор, не учётные данные.
        let objc = "- (void)f:(NSData *)apnsDeviceToken { [[NSUserDefaults standardUserDefaults] setObject:apnsDeviceToken forKey:@\"apnsDeviceToken\"];\n [[NSUserDefaults standardUserDefaults] setObject:t forKey:@\"pushDeviceToken\"]; }";
        assert!(run(OC, objc, Lang::ObjC).is_empty());
        // Firefox: `token: ActionToken` — тип говорит, что это не секрет.
        let text = "func wait(token: ActionToken = ActionToken()) { logger.log(\"dup \\(token)\", level: .info) }\nfunc g(accessToken: String) { logger.log(\"t \\(accessToken)\") }";
        assert_eq!(lines(&run(SW, text, Lang::Swift)), vec![2]);
        // Signal: объявление псевдонима опции в обёртке CommonCrypto — не использование.
        let text = "struct Options: OptionSet { let rawValue: Int\n public static let ecbMode = Options(rawValue: kCCOptionECBMode)\n}\nfunc e() { CCCrypt(op, alg, CCOptions(kCCOptionECBMode), k, kl, nil, d, dl, o, ol, &n) }";
        assert_eq!(lines(&run(SW, text, Lang::Swift)), vec![4]);
    }

    #[test]
    fn ids_do_not_depend_on_lines() {
        let text = "let q = kSecAttrAccessibleAlways";
        let id = |t: &str| {
            let mut out = RuleOutput::default();
            let lexed = lex::lex(t, Lang::Swift);
            check(
                SW,
                t,
                Lang::Swift,
                &lexed,
                &mut out,
                &mut CodeStats::default(),
            );
            out.findings[0].id.clone()
        };
        assert_eq!(id(text), id(&format!("\n\n// moved\n{text}")));
    }
}
