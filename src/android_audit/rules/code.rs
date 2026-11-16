//! Шаблоны в коде Kotlin/Java (по токенам, не по тексту: комментарии и строки не срабатывают).
//! Это НЕ анализ потоков данных: правило видит вызов и его литеральные аргументы, но не откуда
//! пришло значение и выполняется ли код. Поэтому только `potential`/`needs_review`.
//!
//! - ANDROID-WEBVIEW-010: `addJavascriptInterface` при включённом JavaScript; `setAllowUniversalAccessFromFileURLs(true)`,
//!   `setAllowFileAccessFromFileURLs(true)`; `setAllowFileAccess(true)` вместе с JavaScript. Файл должен
//!   ссылаться на WebView (`android.webkit`, `WebView`, `WebSettings`) — иначе одноимённые методы чужих классов.
//! - ANDROID-TLS-011: `checkServerTrusted` с пустым телом (TrustManager принимает любой сертификат),
//!   `verify(…, SSLSession)` / лямбда HostnameVerifier, всегда возвращающие `true`, `ALLOW_ALL_HOSTNAME_VERIFIER`,
//!   `AllowAllHostnameVerifier`, `NoopHostnameVerifier`.
//! - ANDROID-CRYPTO-012: `Cipher.getInstance("AES")` (режим по умолчанию — ECB), `…/ECB/…` у блочных шифров,
//!   DES/RC4/RC2, RSA без паддинга; `MessageDigest` MD5/SHA-1 рядом со словами «пароль» (needs_review);
//!   `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE`.
//! - ANDROID-STORAGE-013: `putString` в SharedPreferences с ключом/значением вроде token/password (info).
//! - ANDROID-LOG-014: `Log.*`/`Timber.*` с переменной вроде password/token в аргументах (low).
//!
//! Тестовые наборы (`src/test`, `src/androidTest`, …) не проверяются; debug-набор — не выше `low`.
//! Объявления одноимённых методов (`fun setJavaScriptEnabled(…)`) — не вызовы.

use super::{
    CRYPTO_ID, LOG_ID, MAX_HITS_PER_FILE, New, REF_MASVS, RuleOutput, STORAGE_ID, TLS_ID,
    WEBVIEW_ID, is_sensitive_name, words,
};
use crate::android_audit::lex::{self, Kind, Lang, Lexed, Token};
use crate::android_audit::rules::secret::{Reach, reach_of};
use crate::android_audit::types::{Confidence, Severity};
use crate::web_audit::location::LineIndex;
use std::collections::HashMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeStats {
    pub files_checked: usize,
    pub test_files_skipped: usize,
    pub files_with_recoveries: usize,
    pub capped: Vec<String>,
}

struct File<'a> {
    path: &'a str,
    text: &'a str,
    lang: Lang,
    lexed: &'a Lexed,
    /// Значимые токены (без переводов строк и импортов).
    t: Vec<&'a Token>,
    /// Все идентификаторы файла, включая импорты (контекст: «файл про WebView»).
    idents: std::collections::HashSet<&'a str>,
    index: LineIndex,
    debug_set: bool,
    min_sdk: Option<i32>,
    /// Сколько раз встречался ключ (для стабильного id одинаковых строк).
    occurrences: HashMap<String, usize>,
}

const REF_WEBVIEW: &str =
    "https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges";
const REF_FILE_ACCESS: &str = "https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean)";
const REF_TLS: &str =
    "https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager";
const REF_HOSTNAME: &str =
    "https://developer.android.com/privacy-and-security/risks/unsafe-hostname";
const REF_CIPHER: &str =
    "https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm";
const REF_WORLD: &str =
    "https://developer.android.com/reference/android/content/Context#MODE_WORLD_READABLE";
const REF_LOG: &str =
    "https://developer.android.com/privacy-and-security/risks/log-info-disclosure";
const REF_PREFS: &str = "https://developer.android.com/privacy-and-security/security-tips#UserData";

/// Проверяет один файл исходника. Возвращает диапазоны комментариев (для правила ключей).
pub fn check(
    path: &str,
    text: &str,
    lang: Lang,
    min_sdk: Option<i32>,
    out: &mut RuleOutput,
    stats: &mut CodeStats,
) -> Vec<(usize, usize)> {
    let lexed = lex::lex(text, lang);
    let reach = reach_of(path);
    if reach == Reach::Test {
        stats.test_files_skipped += 1;
        return lexed.comments;
    }
    stats.files_checked += 1;
    if lexed.unterminated > 0 {
        stats.files_with_recoveries += 1;
    }
    // Импорты и package: контекст, но не места находок.
    let mut in_import = vec![false; lexed.tokens.len()];
    let mut k = 0;
    while k < lexed.tokens.len() {
        let tok = &lexed.tokens[k];
        if tok.is_ident("import") || tok.is_ident("package") {
            let mut j = k;
            while j < lexed.tokens.len()
                && lexed.tokens[j].kind != Kind::Newline
                && !lexed.tokens[j].is_punct(";")
            {
                in_import[j] = true;
                j += 1;
            }
            k = j;
        }
        k += 1;
    }
    let t: Vec<&Token> = lexed
        .tokens
        .iter()
        .enumerate()
        .filter(|(i, tok)| tok.kind != Kind::Newline && !in_import[*i])
        .map(|(_, tok)| tok)
        .collect();
    let idents = lexed
        .tokens
        .iter()
        .filter(|t| t.kind == Kind::Ident)
        .map(|t| t.text.as_str())
        .collect();
    let mut file = File {
        path,
        text,
        lang,
        lexed: &lexed,
        t,
        idents,
        index: LineIndex::new(text),
        debug_set: reach == Reach::Shipped(true),
        min_sdk,
        occurrences: HashMap::new(),
    };
    let before = out.findings.len();
    webview(&mut file, out);
    tls(&mut file, out);
    crypto(&mut file, out);
    storage(&mut file, out);
    logging(&mut file, out);
    if out.findings.len() - before > MAX_HITS_PER_FILE {
        out.findings.truncate(before + MAX_HITS_PER_FILE);
        stats.capped.push(path.to_string());
    }
    lexed.comments.clone()
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

    /// `name(` — вызов, а не объявление (`fun name(`, `void name(`, `fun Type.name(`).
    fn is_call(&self, i: usize) -> bool {
        if !self.tok(i + 1).is_some_and(|n| n.is_punct("(")) {
            return false;
        }
        match self.prev(i) {
            None => true,
            Some(p) if p.kind == Kind::Ident => matches!(
                p.text.as_str(),
                "return" | "else" | "in" | "is" | "throw" | "when" | "if" | "try" | "do"
            ),
            Some(p) if p.is_punct(".") || p.is_punct("?.") => {
                // `fun WebSettings.setX(` — объявление расширения.
                !(i >= 3
                    && self.tok(i - 3).is_some_and(|f| f.is_ident("fun"))
                    && self.tok(i - 2).is_some_and(|x| x.kind == Kind::Ident))
            }
            Some(p) => !p.is_punct(">") && !p.is_punct("::"),
        }
    }

    /// Получатель вызова `Recv.name(` (идентификатор перед `.`).
    fn receiver(&self, i: usize) -> Option<&str> {
        let dot = self.prev(i)?;
        if !(dot.is_punct(".") || dot.is_punct("?.")) {
            return None;
        }
        let r = self.tok(i.checked_sub(2)?)?;
        (r.kind == Kind::Ident).then_some(r.text.as_str())
    }

    /// Индекс парной `)` для `(` в `open`.
    fn close_of(&self, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for k in open..self.t.len() {
            if self.t[k].is_punct("(") {
                depth += 1;
            } else if self.t[k].is_punct(")") {
                depth -= 1;
                if depth == 0 {
                    return Some(k);
                }
            }
        }
        None
    }

    /// Аргументы вызова `name(` в `i`: диапазоны индексов токенов.
    fn args(&self, i: usize) -> Option<Vec<(usize, usize)>> {
        let open = i + 1;
        let close = self.close_of(open)?;
        let mut out = Vec::new();
        let mut depth = 0usize;
        let mut from = open + 1;
        for k in open + 1..close {
            let tok = self.t[k];
            if tok.is_punct("(") || tok.is_punct("[") || tok.is_punct("{") {
                depth += 1;
            } else if tok.is_punct(")") || tok.is_punct("]") || tok.is_punct("}") {
                depth = depth.saturating_sub(1);
            } else if tok.is_punct(",") && depth == 0 {
                out.push((from, k));
                from = k + 1;
            }
        }
        if from < close {
            out.push((from, close));
        }
        Some(out)
    }

    /// Единственный аргумент — литерал `true`.
    fn single_true(&self, i: usize) -> bool {
        self.args(i).is_some_and(|a| {
            a.len() == 1 && a[0].1 - a[0].0 == 1 && self.t[a[0].0].is_ident("true")
        })
    }

    /// `name = true` (свойство Kotlin), не объявление `val name = true`.
    fn assigned_true(&self, i: usize) -> bool {
        self.tok(i + 1).is_some_and(|t| t.is_punct("="))
            && self.tok(i + 2).is_some_and(|t| t.is_ident("true"))
            && !self
                .prev(i)
                .is_some_and(|p| p.is_ident("val") || p.is_ident("var"))
    }

    /// Вызов `setX(true)` или присваивание `x = true` (геттер-свойство Kotlin).
    fn enabled(&self, i: usize, setter: &str, property: &str) -> bool {
        let tok = self.t[i];
        (tok.is_ident(setter) && self.is_call(i) && self.single_true(i))
            || (tok.is_ident(property) && self.assigned_true(i))
    }

    fn sites(&self, pred: impl Fn(usize) -> bool) -> Vec<usize> {
        (0..self.t.len()).filter(|&i| pred(i)).collect()
    }

    fn position(&self, byte: usize) -> (u32, u32) {
        self.index.line_col(self.text, byte).unwrap_or((1, 1))
    }

    /// Строка исходника: комментарии убраны, строковые литералы — `"…"` (кроме `allow`).
    fn excerpt(&self, byte: usize, allow: Option<usize>) -> String {
        let (line, _) = self.position(byte);
        let Some((start, end)) = self.index.line_range(self.text, line as usize) else {
            return String::new();
        };
        let mut out = String::new();
        let mut last = start;
        for tok in &self.lexed.tokens {
            if tok.end <= start || tok.kind == Kind::Newline {
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
            match tok.kind {
                Kind::Str | Kind::Char if Some(tok.start) != allow => out.push_str("\"…\""),
                Kind::Str | Kind::Char => out.push_str(&format!("\"{}\"", tok.text)),
                _ => out.push_str(&self.text[from..tok.end.min(end)]),
            }
            last = tok.end.min(end);
        }
        out
    }

    fn key(&mut self, base: String) -> String {
        let n = self.occurrences.entry(base.clone()).or_insert(0);
        *n += 1;
        format!("{base}\0{n}")
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        out: &mut RuleOutput,
        rule: &'static str,
        category: &'static str,
        at: usize,
        title: String,
        severity: Severity,
        confidence: Confidence,
        explanation: String,
        remediation: &'static str,
        references: Vec<&'static str>,
        cwe: &'static str,
        masvs: &'static str,
        allow_literal: Option<usize>,
    ) {
        let tok = self.t[at];
        let (line, column) = self.position(tok.start);
        let excerpt = self.excerpt(tok.start, allow_literal);
        let key = self.key(format!(
            "{title}\0{}",
            super::super::types::normalized_key(&excerpt)
        ));
        let (severity, explanation, mut tags) = if self.debug_set && severity < Severity::Low {
            (
                Severity::Low,
                format!(
                    "{explanation} The file is in a debug source set, so this ships only in debug builds."
                ),
                vec!["source_set:debug".to_string()],
            )
        } else {
            (severity, explanation, Vec::new())
        };
        tags.push(format!("masvs:{masvs}"));
        tags.push(format!(
            "lang:{}",
            match self.lang {
                Lang::Kotlin => "kotlin",
                Lang::Java => "java",
                Lang::Groovy => "groovy",
            }
        ));
        let mut references = references;
        references.push(REF_MASVS);
        out.findings.push(
            New {
                rule,
                category,
                title,
                severity,
                confidence,
                path: self.path,
                line: Some(line),
                column: Some(column),
                component: None,
                excerpt: Some(excerpt),
                fingerprint: None,
                key,
                explanation,
                remediation,
                references,
                cwe_ids: vec![cwe],
                tags,
            }
            .build(),
        );
    }
}

fn webview(f: &mut File, out: &mut RuleOutput) {
    let context = [
        "WebView",
        "WebSettings",
        "webkit",
        "WebViewClient",
        "WebChromeClient",
    ]
    .iter()
    .any(|w| f.has(w));
    if !context {
        return;
    }
    let js = !f
        .sites(|i| f.enabled(i, "setJavaScriptEnabled", "javaScriptEnabled"))
        .is_empty();
    let bridges = f.sites(|i| f.t[i].is_ident("addJavascriptInterface") && f.is_call(i));
    for i in bridges {
        let legacy = f.min_sdk.is_some_and(|m| m < 17);
        let (severity, confidence, detail) = if legacy {
            (
                Severity::High,
                Confidence::Potential,
                " minSdk is below 17: on those Android versions every public method of the bridge \
                 object (including getClass()) is reachable from JavaScript, which allows code execution \
                 (CVE-2012-6636).",
            )
        } else if js {
            (
                Severity::Medium,
                Confidence::Potential,
                " JavaScript is enabled in this file, so any page loaded into this WebView (including \
                 one injected over a network or via a redirect) can call its @JavascriptInterface methods.",
            )
        } else {
            (
                Severity::Low,
                Confidence::NeedsReview,
                " JavaScript is not enabled in this file (it may be enabled elsewhere); without it the \
                 bridge is unreachable.",
            )
        };
        f.push(
            out,
            WEBVIEW_ID,
            "webview",
            i,
            "WebView exposes a JavaScript bridge (addJavascriptInterface)".to_string(),
            severity,
            confidence,
            format!(
                "addJavascriptInterface makes app methods callable from page JavaScript.{detail} Load only \
                 trusted, HTTPS content in this WebView, check the origin before acting, and keep the \
                 bridge surface minimal. Potential: what the WebView loads is not analysed."
            ),
            "restrict-webview-bridge",
            vec![REF_WEBVIEW, "https://cwe.mitre.org/data/definitions/749.html"],
            "CWE-749",
            "MASVS-PLATFORM",
            None,
        );
    }
    let universal = f.sites(|i| {
        f.enabled(
            i,
            "setAllowUniversalAccessFromFileURLs",
            "allowUniversalAccessFromFileURLs",
        )
    });
    let from_file = f.sites(|i| {
        f.enabled(
            i,
            "setAllowFileAccessFromFileURLs",
            "allowFileAccessFromFileURLs",
        )
    });
    for (sites, what) in [(universal, "any origin"), (from_file, "other file:// URLs")] {
        for i in sites {
            let name = f.t[i].text.clone();
            f.push(
                out,
                WEBVIEW_ID,
                "webview",
                i,
                format!("WebView lets file:// pages read {what} ({name})"),
                Severity::Medium,
                Confidence::Potential,
                format!(
                    "{name} = true lets JavaScript in a file:// page read {what}, so a malicious HTML file \
                     opened in this WebView can read the app's private files and send them out. The \
                     setting is deprecated and off by default; remove it."
                ),
                "restrict-webview-file-access",
                vec![REF_FILE_ACCESS, "https://cwe.mitre.org/data/definitions/200.html"],
                "CWE-200",
                "MASVS-PLATFORM",
                None,
            );
        }
    }
    if js {
        for i in f.sites(|i| f.enabled(i, "setAllowFileAccess", "allowFileAccess")) {
            f.push(
                out,
                WEBVIEW_ID,
                "webview",
                i,
                "JavaScript WebView can open file:// URLs (setAllowFileAccess(true))".to_string(),
                Severity::Low,
                Confidence::NeedsReview,
                "File access is turned on explicitly in a file that also enables JavaScript. If this \
                 WebView ever loads untrusted content or file:// URLs from outside, local files are \
                 exposed. Prefer WebViewAssetLoader and keep file access off (the default since API 30)."
                    .to_string(),
                "restrict-webview-file-access",
                vec![REF_FILE_ACCESS, "https://cwe.mitre.org/data/definitions/200.html"],
                "CWE-200",
                "MASVS-PLATFORM",
                None,
            );
        }
    }
}

/// Тело `{ … }`, начиная с индекса `open` (`{`): (индекс `}`, значимые токены внутри).
fn body(f: &File, open: usize) -> Option<(usize, Vec<usize>)> {
    if !f.tok(open)?.is_punct("{") {
        return None;
    }
    let mut depth = 0usize;
    for k in open..f.t.len() {
        if f.t[k].is_punct("{") {
            depth += 1;
        } else if f.t[k].is_punct("}") {
            depth -= 1;
            if depth == 0 {
                return Some((k, (open + 1..k).collect()));
            }
        }
    }
    None
}

/// После `)` объявления: пропускает `throws A, B` / `: Type` и отдаёт индекс начала тела.
fn after_signature(f: &File, close: usize) -> usize {
    let mut k = close + 1;
    if f.tok(k).is_some_and(|t| t.is_ident("throws")) {
        k += 1;
        while f
            .tok(k)
            .is_some_and(|t| t.kind == Kind::Ident || t.is_punct(".") || t.is_punct(","))
        {
            k += 1;
        }
    } else if f.tok(k).is_some_and(|t| t.is_punct(":")) {
        k += 1;
        while f
            .tok(k)
            .is_some_and(|t| t.kind == Kind::Ident || t.is_punct(".") || t.is_punct("?"))
        {
            k += 1;
        }
    }
    k
}

/// `fun name(` / `void name(` / `public boolean name(` — объявление метода.
fn is_declaration(f: &File, i: usize) -> bool {
    f.tok(i + 1).is_some_and(|t| t.is_punct("("))
        && f.prev(i).is_some_and(|p| {
            p.is_ident("fun")
                || (p.kind == Kind::Ident
                    && matches!(p.text.as_str(), "void" | "boolean" | "Boolean"))
        })
}

fn tls(f: &mut File, out: &mut RuleOutput) {
    let trust_context = [
        "X509TrustManager",
        "TrustManager",
        "X509ExtendedTrustManager",
    ]
    .iter()
    .any(|w| f.has(w));
    if trust_context {
        let sites = f.sites(|i| f.t[i].is_ident("checkServerTrusted") && is_declaration(f, i));
        for i in sites {
            let Some(close) = f.close_of(i + 1) else {
                continue;
            };
            let start = after_signature(f, close);
            let empty = match f.tok(start) {
                Some(t) if t.is_punct("{") => body(f, start).is_some_and(|(_, inner)| {
                    inner.is_empty()
                        || inner
                            .iter()
                            .all(|&k| f.t[k].is_ident("return") || f.t[k].is_punct(";"))
                }),
                Some(t) if t.is_punct("=") => f.tok(start + 1).is_some_and(|u| u.is_ident("Unit")),
                _ => false,
            };
            if !empty {
                continue;
            }
            f.push(
                out,
                TLS_ID,
                "network",
                i,
                "TrustManager accepts every server certificate".to_string(),
                Severity::High,
                Confidence::Potential,
                "checkServerTrusted has an empty body, so this X509TrustManager never rejects a \
                 certificate. Any TLS connection that uses it can be intercepted by anyone on the \
                 network (a self-signed certificate is enough). Potential: whether this TrustManager is \
                 actually installed into an SSLContext/HTTP client is not traced. Use the platform \
                 default trust (and a network security config for custom CAs or pinning)."
                    .to_string(),
                "use-default-trust",
                vec![REF_TLS, "https://cwe.mitre.org/data/definitions/295.html"],
                "CWE-295",
                "MASVS-NETWORK",
                None,
            );
        }
    }
    // HostnameVerifier.verify(…, SSLSession), который всегда true.
    if f.has("SSLSession") || f.has("HostnameVerifier") {
        let sites = f.sites(|i| f.t[i].is_ident("verify") && is_declaration(f, i));
        for i in sites {
            let Some(close) = f.close_of(i + 1) else {
                continue;
            };
            if !(i + 2..close).any(|k| f.t[k].is_ident("SSLSession")) {
                continue;
            }
            let start = after_signature(f, close);
            let always = match f.tok(start) {
                Some(t) if t.is_punct("=") => {
                    f.tok(start + 1).is_some_and(|u| u.is_ident("true"))
                        && !f.tok(start + 2).is_some_and(|u| {
                            u.kind == Kind::Punct && !u.is_punct("}") && !u.is_punct(";")
                        })
                }
                Some(t) if t.is_punct("{") => body(f, start).is_some_and(|(_, inner)| {
                    let sig: Vec<&Token> = inner
                        .iter()
                        .map(|&k| f.t[k])
                        .filter(|t| !t.is_punct(";"))
                        .collect();
                    sig.len() == 2 && sig[0].is_ident("return") && sig[1].is_ident("true")
                }),
                _ => false,
            };
            if always {
                hostname_finding(f, out, i);
            }
        }
    }
    // Лямбды: `HostnameVerifier { _, _ -> true }`, `.hostnameVerifier { _, _ -> true }`,
    // `setHostnameVerifier((h, s) -> true)`.
    let lambda_sites = f.sites(|i| {
        let tok = f.t[i];
        tok.kind == Kind::Ident
            && matches!(
                tok.text.as_str(),
                "HostnameVerifier"
                    | "hostnameVerifier"
                    | "setHostnameVerifier"
                    | "setDefaultHostnameVerifier"
            )
    });
    for i in lambda_sites {
        if lambda_always_true(f, i + 1) {
            hostname_finding(f, out, i);
        }
    }
    let allow_all = f.sites(|i| {
        let tok = f.t[i];
        tok.kind == Kind::Ident
            && matches!(
                tok.text.as_str(),
                "ALLOW_ALL_HOSTNAME_VERIFIER" | "AllowAllHostnameVerifier" | "NoopHostnameVerifier"
            )
            && !f
                .prev(i)
                .is_some_and(|p| p.is_ident("class") || p.is_ident("object"))
    });
    for i in allow_all {
        hostname_finding(f, out, i);
    }
}

/// С позиции `at`: `{ a, b -> true }`, `( { a, b -> true } )`, `( (a, b) -> true )`.
fn lambda_always_true(f: &File, at: usize) -> bool {
    let mut k = at;
    let call = f.tok(k).is_some_and(|t| t.is_punct("("));
    if call {
        k += 1;
    }
    let brace = f.tok(k).is_some_and(|t| t.is_punct("{"));
    if brace {
        k += 1;
    }
    if !call && !brace {
        return false;
    }
    // Параметры: `a, b` или `(a, b)`.
    let paren_params = f.tok(k).is_some_and(|t| t.is_punct("("));
    if paren_params {
        k += 1;
    }
    let mut params = 0;
    while let Some(t) = f.tok(k) {
        if t.kind == Kind::Ident {
            params += 1;
            k += 1;
            // Типы `hostname: String?`
            if f.tok(k).is_some_and(|t| t.is_punct(":")) {
                k += 1;
                while f
                    .tok(k)
                    .is_some_and(|t| t.kind == Kind::Ident || t.is_punct("?") || t.is_punct("."))
                {
                    k += 1;
                }
            }
            if f.tok(k).is_some_and(|t| t.is_punct(",")) {
                k += 1;
            }
        } else {
            break;
        }
    }
    if paren_params {
        if !f.tok(k).is_some_and(|t| t.is_punct(")")) {
            return false;
        }
        k += 1;
    }
    if params != 2 || !f.tok(k).is_some_and(|t| t.is_punct("->")) {
        return false;
    }
    k += 1;
    if !f.tok(k).is_some_and(|t| t.is_ident("true")) {
        return false;
    }
    k += 1;
    match f.tok(k) {
        Some(t) => t.is_punct("}") || t.is_punct(")") || t.is_punct(";") || t.is_punct(","),
        None => true,
    }
}

fn hostname_finding(f: &mut File, out: &mut RuleOutput, i: usize) {
    f.push(
        out,
        TLS_ID,
        "network",
        i,
        "HostnameVerifier accepts every host name".to_string(),
        Severity::High,
        Confidence::Potential,
        "This HostnameVerifier accepts any host name, so a valid certificate for any domain (one an \
         attacker owns) passes for your server and the connection can be intercepted. Potential: \
         whether the verifier is installed on a connection that is used is not traced. Remove it and \
         keep the default hostname verification."
            .to_string(),
        "use-default-hostname-verifier",
        vec![REF_HOSTNAME, "https://cwe.mitre.org/data/definitions/297.html"],
        "CWE-297",
        "MASVS-NETWORK",
        None,
    );
}

const BLOCK_CIPHERS: &[&str] = &[
    "AES",
    "DES",
    "DESEDE",
    "TRIPLEDES",
    "BLOWFISH",
    "RC2",
    "RC5",
];
const WEAK_CIPHERS: &[&str] = &["DES", "RC4", "ARCFOUR", "RC2"];

fn crypto(f: &mut File, out: &mut RuleOutput) {
    let ciphers = f.sites(|i| {
        f.t[i].is_ident("getInstance") && f.is_call(i) && f.receiver(i) == Some("Cipher")
    });
    for i in ciphers {
        let Some(args) = f.args(i) else { continue };
        let Some(&(a, b)) = args.first() else {
            continue;
        };
        if b - a != 1 {
            continue;
        }
        let Some(transformation) = f.t[a].literal_str() else {
            continue;
        };
        let literal_at = f.t[a].start;
        let upper = transformation.to_ascii_uppercase();
        let parts: Vec<&str> = upper.split('/').collect();
        let alg = parts[0];
        let mode = parts.get(1).copied();
        let padding = parts.get(2).copied();
        let problem = if WEAK_CIPHERS.contains(&alg) {
            Some(format!(
                "{alg} is a broken cipher (short key or biased keystream); use AES-GCM or ChaCha20-Poly1305."
            ))
        } else if BLOCK_CIPHERS.contains(&alg) && mode.is_none() {
            Some(format!(
                "\"{alg}\" without a mode uses the provider default, which is ECB on Android: equal \
                 plaintext blocks give equal ciphertext blocks and there is no integrity. Use \
                 \"AES/GCM/NoPadding\" with a random IV."
            ))
        } else if BLOCK_CIPHERS.contains(&alg) && mode == Some("ECB") {
            Some(
                "ECB mode leaks patterns (equal plaintext blocks give equal ciphertext blocks) and has \
                 no integrity. Use \"AES/GCM/NoPadding\" with a random IV."
                    .to_string(),
            )
        } else if alg == "RSA" && padding == Some("NOPADDING") {
            Some(
                "RSA without padding (textbook RSA) is deterministic and malleable. Use OAEP \
                 (\"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\")."
                    .to_string(),
            )
        } else {
            None
        };
        let Some(problem) = problem else { continue };
        f.push(
            out,
            CRYPTO_ID,
            "cryptography",
            i,
            format!("Weak cipher transformation \"{}\"", crate::ui::sanitize_line(transformation)),
            Severity::Medium,
            Confidence::Potential,
            format!(
                "Cipher.getInstance(\"{}\"): {problem} Potential: what is encrypted (and whether it is \
                 sensitive) is not analysed.",
                crate::ui::sanitize_line(transformation)
            ),
            "use-authenticated-encryption",
            vec![REF_CIPHER, "https://cwe.mitre.org/data/definitions/327.html"],
            "CWE-327",
            "MASVS-CRYPTO",
            Some(literal_at),
        );
    }
    let digests = f.sites(|i| {
        f.t[i].is_ident("getInstance") && f.is_call(i) && f.receiver(i) == Some("MessageDigest")
    });
    for i in digests {
        let Some(args) = f.args(i) else { continue };
        let Some(&(a, b)) = args.first() else {
            continue;
        };
        if b - a != 1 {
            continue;
        }
        let Some(alg) = f.t[a].literal_str() else {
            continue;
        };
        let upper = alg.to_ascii_uppercase();
        if !matches!(upper.as_str(), "MD5" | "SHA-1" | "SHA1" | "MD2" | "MD4") {
            continue;
        }
        if !password_nearby(f, i) {
            continue;
        }
        let literal_at = f.t[a].start;
        f.push(
            out,
            CRYPTO_ID,
            "cryptography",
            i,
            format!("Fast hash {upper} used near password handling"),
            Severity::Low,
            Confidence::NeedsReview,
            format!(
                "MessageDigest.getInstance(\"{upper}\") appears in code that mentions a password. {upper} is \
                 fast and (here) unsalted, so a leaked hash is cheap to brute-force; for passwords use a \
                 slow, salted KDF (PBKDF2, scrypt, Argon2). Needs review: the hash may be used for \
                 something else, such as a checksum."
            ),
            "use-password-kdf",
            vec![REF_CIPHER, "https://cwe.mitre.org/data/definitions/916.html"],
            "CWE-916",
            "MASVS-CRYPTO",
            Some(literal_at),
        );
    }
    let world = f.sites(|i| {
        let tok = f.t[i];
        tok.kind == Kind::Ident
            && matches!(
                tok.text.as_str(),
                "MODE_WORLD_READABLE" | "MODE_WORLD_WRITEABLE"
            )
            && !f
                .prev(i)
                .is_some_and(|p| p.is_ident("val") || p.is_ident("int") || p.is_ident("var"))
    });
    for i in world {
        let name = f.t[i].text.clone();
        f.push(
            out,
            CRYPTO_ID,
            "data_storage",
            i,
            format!("File or preferences created with {name}"),
            Severity::Medium,
            Confidence::Potential,
            format!(
                "{name} lets every app on the device {} this file. It is deprecated since API 17 and \
                 throws SecurityException for apps targeting API 24+, so it is either a crash or a leak. \
                 Use MODE_PRIVATE and share data through a FileProvider/ContentProvider.",
                if name.ends_with("READABLE") { "read" } else { "overwrite" }
            ),
            "use-mode-private",
            vec![REF_WORLD, "https://cwe.mitre.org/data/definitions/276.html"],
            "CWE-276",
            "MASVS-STORAGE",
            None,
        );
    }
}

/// В объемлющем блоке (функции) есть слово password/passwd/passphrase/pwd/credential.
fn password_nearby(f: &File, at: usize) -> bool {
    // Ищем ближайшую незакрытую `{` слева, затем её пару; плюс заголовок функции перед ней.
    let mut depth = 0i32;
    let mut open = None;
    for k in (0..at).rev() {
        if f.t[k].is_punct("}") {
            depth += 1;
        } else if f.t[k].is_punct("{") {
            if depth == 0 {
                open = Some(k);
                break;
            }
            depth -= 1;
        }
    }
    let Some(open) = open else { return false };
    let end = body(f, open).map_or(f.t.len(), |(c, _)| c);
    let from = open.saturating_sub(30);
    (from..end).any(|k| {
        let tok = f.t[k];
        let text = match tok.kind {
            Kind::Ident | Kind::Str => tok.text.as_str(),
            _ => return false,
        };
        let w = words(text);
        w.iter().any(|x| {
            matches!(
                x.as_str(),
                "password" | "passwd" | "passphrase" | "pwd" | "credential" | "credentials"
            )
        })
    })
}

/// Идентификаторы аргумента вызова, которые выводят значение (не `.length`/`== null`/константы/`R.`).
fn sensitive_arg_idents(f: &File, from: usize, to: usize) -> Vec<String> {
    let mut found = Vec::new();
    let slice: Vec<&Token> = f.t[from..to].to_vec();
    for k in 0..slice.len() {
        let tok = slice[k];
        match tok.kind {
            Kind::Ident => {
                if logged_at(&slice, k) {
                    found.push(tok.text.clone());
                }
            }
            Kind::Str => {
                let inner = lex::template_idents(f.text, tok, f.lang);
                let inner: Vec<&Token> = inner.iter().filter(|t| t.kind != Kind::Newline).collect();
                for j in 0..inner.len() {
                    if inner[j].kind == Kind::Ident && logged_at(&inner, j) {
                        found.push(inner[j].text.clone());
                    }
                }
            }
            _ => {}
        }
    }
    found
}

fn is_constant(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Идентификатор `toks[k]` секретный по имени и выводится значением.
fn logged_at(toks: &[&Token], k: usize) -> bool {
    let tok = toks[k];
    if !is_sensitive_name(&tok.text) || is_constant(&tok.text) {
        return false;
    }
    // `R.string.password` — ресурс, не значение.
    let mut chain = k;
    while chain >= 2 && toks[chain - 1].is_punct(".") && toks[chain - 2].kind == Kind::Ident {
        chain -= 2;
    }
    if chain < k && toks[chain].is_ident("R") {
        return false;
    }
    // После: `.length`, `.size`, `.isEmpty()`, `== null`, `!= null` — выводит не значение.
    if let Some(next) = toks.get(k + 1) {
        if (next.is_punct(".") || next.is_punct("?."))
            && toks.get(k + 2).is_some_and(|m| {
                matches!(
                    m.text.as_str(),
                    "length"
                        | "size"
                        | "isEmpty"
                        | "isNotEmpty"
                        | "isBlank"
                        | "isNotBlank"
                        | "isNullOrEmpty"
                        | "isNullOrBlank"
                        | "hashCode"
                        | "count"
                )
            })
        {
            return false;
        }
        if next.is_punct("==") || next.is_punct("!=") {
            return false;
        }
    }
    true
}

const LOG_RECEIVERS: &[&str] = &["Log", "Timber"];
const LOG_METHODS: &[&str] = &["v", "d", "i", "w", "e", "wtf", "println"];

/// Условие `if (…)` перед индексом `close` (на `)`) содержит `BuildConfig.DEBUG` (или `DEBUG`) без `!`.
fn debug_condition(f: &File, close: usize) -> bool {
    if !f.tok(close).is_some_and(|t| t.is_punct(")")) {
        return false;
    }
    let mut depth = 0usize;
    for k in (0..=close).rev() {
        if f.t[k].is_punct(")") {
            depth += 1;
        } else if f.t[k].is_punct("(") {
            depth -= 1;
            if depth == 0 {
                let cond = &f.t[k + 1..close];
                return k > 0
                    && f.t[k - 1].is_ident("if")
                    && cond.iter().any(|t| t.is_ident("DEBUG"))
                    && !cond.iter().any(|t| t.is_punct("!") || t.is_punct("||"));
            }
        }
    }
    false
}

/// Вызов в `at` (первый токен выражения, `Log`) выполняется только при `BuildConfig.DEBUG`:
/// `if (BuildConfig.DEBUG) Log.d(…)` или внутри `if (BuildConfig.DEBUG) { … }`.
fn debug_guarded(f: &File, at: usize) -> bool {
    if at > 0 && debug_condition(f, at - 1) {
        return true;
    }
    let mut depth = 0usize;
    for k in (0..at).rev() {
        if f.t[k].is_punct("}") {
            depth += 1;
        } else if f.t[k].is_punct("{") {
            if depth == 0 {
                return k > 0 && debug_condition(f, k - 1);
            }
            depth -= 1;
        }
    }
    false
}

fn logging(f: &mut File, out: &mut RuleOutput) {
    let sites = f.sites(|i| {
        let tok = f.t[i];
        tok.kind == Kind::Ident
            && LOG_METHODS.contains(&tok.text.as_str())
            && f.is_call(i)
            && f.receiver(i).is_some_and(|r| LOG_RECEIVERS.contains(&r))
    });
    for i in sites {
        // `if (BuildConfig.DEBUG) Log.d(…)`: DEBUG — константа времени компиляции, в release-сборке
        // ветки нет вовсе (полевой тест, NewPipe).
        if debug_guarded(f, i.saturating_sub(2)) {
            continue;
        }
        let Some(args) = f.args(i) else { continue };
        let mut names = Vec::new();
        for &(a, b) in &args {
            names.extend(sensitive_arg_idents(f, a, b));
        }
        names.dedup();
        if names.is_empty() {
            continue;
        }
        let receiver = f.receiver(i).unwrap_or("Log").to_string();
        let method = f.t[i].text.clone();
        f.push(
            out,
            LOG_ID,
            "logging",
            i,
            format!("Possibly sensitive value logged ({})", crate::ui::sanitize_line(&names.join(", "))),
            Severity::Low,
            Confidence::NeedsReview,
            format!(
                "{receiver}.{method}(…) is passed {}, whose name says it is a secret. Logcat is readable over \
                 adb and in bug reports, and on old Android versions by other apps. Needs review: the \
                 name may not match the content, and debug logs may be stripped by R8 rules. Log a \
                 redacted form or nothing.",
                crate::ui::sanitize_line(&names.join(", "))
            ),
            "redact-logs",
            vec![REF_LOG, "https://cwe.mitre.org/data/definitions/532.html"],
            "CWE-532",
            "MASVS-STORAGE",
            None,
        );
    }
}

/// Получатель `putString` похож на редактор SharedPreferences: `….edit().putString`, цепочка
/// `.putString(…).putString`, переменная `editor`/`prefs…`, или вызов без получателя (`edit { putString }`).
/// `bundle.putString`, `intent.putString`, `result.putString` — нет (полевой тест, Nextcloud).
fn prefs_receiver(f: &File, i: usize) -> bool {
    let Some(dot) = f.prev(i) else { return true };
    if !(dot.is_punct(".") || dot.is_punct("?.")) {
        return true;
    }
    let Some(before) = i.checked_sub(2).and_then(|k| f.tok(k)) else {
        return false;
    };
    if before.is_punct(")") {
        // Парная `(` и функция перед ней.
        let mut depth = 0usize;
        for k in (0..=i - 2).rev() {
            if f.t[k].is_punct(")") {
                depth += 1;
            } else if f.t[k].is_punct("(") {
                depth -= 1;
                if depth == 0 {
                    return k.checked_sub(1).and_then(|p| f.tok(p)).is_some_and(|func| {
                        matches!(
                            func.text.as_str(),
                            "edit" | "putString" | "putBoolean" | "putInt" | "putLong" | "remove"
                        )
                    });
                }
            }
        }
        return false;
    }
    before.kind == Kind::Ident && {
        let lower = before.text.to_ascii_lowercase();
        lower.contains("edit") || lower.contains("pref")
    }
}

fn storage(f: &mut File, out: &mut RuleOutput) {
    let prefs = [
        "SharedPreferences",
        "getSharedPreferences",
        "getDefaultSharedPreferences",
        "PreferenceManager",
    ]
    .iter()
    .any(|w| f.has(w));
    let encrypted = ["EncryptedSharedPreferences", "MasterKey", "MasterKeys"]
        .iter()
        .any(|w| f.has(w));
    if !prefs || encrypted {
        return;
    }
    let sites = f.sites(|i| f.t[i].is_ident("putString") && f.is_call(i));
    for i in sites {
        if !prefs_receiver(f, i) {
            continue;
        }
        let Some(args) = f.args(i) else { continue };
        if args.len() != 2 {
            continue;
        }
        let (ka, kb) = args[0];
        let key_sensitive = (ka..kb).any(|k| {
            let tok = f.t[k];
            match tok.kind {
                Kind::Str => tok.templates.is_empty() && is_sensitive_name(&tok.text),
                Kind::Ident => is_sensitive_name(&tok.text),
                _ => false,
            }
        });
        let (va, vb) = args[1];
        let value_sensitive = (va..vb).any(|k| {
            let tok = f.t[k];
            tok.kind == Kind::Ident && is_sensitive_name(&tok.text) && !is_constant(&tok.text)
        });
        let value_literal = vb - va == 1 && matches!(f.t[va].kind, Kind::Str | Kind::Num);
        if !(key_sensitive || value_sensitive) || value_literal {
            continue;
        }
        f.push(
            out,
            STORAGE_ID,
            "data_storage",
            i,
            "Token-like value stored in plain SharedPreferences".to_string(),
            Severity::Info,
            Confidence::NeedsReview,
            "A value whose key or variable name looks like a token/password is written with putString to \
             SharedPreferences, which is a plain XML file in the app's data directory (readable with \
             root, from backups when allowed, and on debuggable builds). Consider the Android Keystore \
             (e.g. encrypt with a Keystore key) for long-lived credentials. Needs review: short-lived or \
             non-secret values are fine here."
                .to_string(),
            "protect-stored-credentials",
            vec![REF_PREFS, "https://cwe.mitre.org/data/definitions/312.html"],
            "CWE-312",
            "MASVS-STORAGE",
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(path: &str, text: &str, lang: Lang) -> Vec<(String, String, Severity, u32)> {
        let mut out = RuleOutput::default();
        let mut stats = CodeStats::default();
        check(path, text, lang, Some(23), &mut out, &mut stats);
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

    const KT: &str = "app/src/main/java/a/A.kt";
    const JAVA: &str = "app/src/main/java/a/A.java";

    #[test]
    fn webview_bridge_with_javascript() {
        let text = "import android.webkit.WebView\nfun f(w: WebView) {\n  w.settings.javaScriptEnabled = true\n  w.addJavascriptInterface(Bridge(), \"app\")\n}";
        let got = run(KT, text, Lang::Kotlin);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, WEBVIEW_ID);
        assert_eq!(got[0].2, Severity::Medium);
        assert_eq!(got[0].3, 4);
        // Без JavaScript в файле — low.
        let text = "import android.webkit.WebView\nfun f(w: WebView) { w.addJavascriptInterface(Bridge(), \"app\") }";
        assert_eq!(run(KT, text, Lang::Kotlin)[0].2, Severity::Low);
    }

    #[test]
    fn webview_negatives() {
        for text in [
            // Комментарий и строка.
            "import android.webkit.WebView\n// w.addJavascriptInterface(x, \"a\")\nval s = \"addJavascriptInterface(x)\"",
            // Объявление одноимённого метода.
            "import android.webkit.WebView\nclass Fake { fun addJavascriptInterface(o: Any, n: String) {} }",
            // Файл не про WebView.
            "class Settings { fun setJavaScriptEnabled(b: Boolean) {}\n fun g() { setJavaScriptEnabled(true); x.addJavascriptInterface(a, b) } }",
            // false
            "import android.webkit.WebSettings\nfun f(s: WebSettings) { s.setAllowUniversalAccessFromFileURLs(false) }",
        ] {
            assert!(run(KT, text, Lang::Kotlin).is_empty(), "{text}");
        }
    }

    #[test]
    fn webview_file_access_java() {
        let text = "import android.webkit.WebSettings;\nclass A { void f(WebSettings s) {\n s.setJavaScriptEnabled(true);\n s.setAllowUniversalAccessFromFileURLs(true);\n s.setAllowFileAccessFromFileURLs(true);\n s.setAllowFileAccess(true);\n} }";
        let got = run(JAVA, text, Lang::Java);
        let lines: Vec<u32> = got.iter().map(|g| g.3).collect();
        assert_eq!(lines, vec![4, 5, 6]);
        assert_eq!(got[2].2, Severity::Low);
    }

    #[test]
    fn trust_all_and_hostname() {
        let kotlin = "import javax.net.ssl.*\nobject TrustAll : X509TrustManager {\n  override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}\n  override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}\n  override fun getAcceptedIssuers() = arrayOf<X509Certificate>()\n}\nval v = HostnameVerifier { _, _ -> true }\nfun b(o: OkHttpClient.Builder) = o.hostnameVerifier { hostname, session -> true }";
        let got = run(KT, kotlin, Lang::Kotlin);
        let lines: Vec<(u32, &str)> = got.iter().map(|g| (g.3, g.1.as_str())).collect();
        assert_eq!(
            lines,
            vec![
                (4, "TrustManager accepts every server certificate"),
                (7, "HostnameVerifier accepts every host name"),
                (8, "HostnameVerifier accepts every host name"),
            ]
        );
        let java = "import javax.net.ssl.*;\nclass T implements X509TrustManager, HostnameVerifier {\n public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { }\n public boolean verify(String h, SSLSession s) { return true; }\n void x() { conn.setHostnameVerifier((h, s) -> true); HttpsURLConnection.setDefaultHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER); }\n}";
        let got = run(JAVA, java, Lang::Java);
        let lines: Vec<u32> = got.iter().map(|g| g.3).collect();
        assert_eq!(lines, vec![3, 4, 5, 5]);
    }

    #[test]
    fn tls_negatives() {
        for text in [
            // Делегирует проверку.
            "import javax.net.ssl.*\nclass P(val d: X509TrustManager) : X509TrustManager {\n override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { d.checkServerTrusted(c, a); pin(c) }\n}",
            // Бросает.
            "import javax.net.ssl.*\nclass P : X509TrustManager { override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { throw CertificateException() } }",
            // verify с проверкой.
            "import javax.net.ssl.*\nval v = HostnameVerifier { h, s -> h == \"api.example.com\" }",
            // Не про TLS: verify без SSLSession.
            "class Sig { fun verify(data: ByteArray): Boolean = true }",
            // Комментарий.
            "// HostnameVerifier { _, _ -> true }\n/* ALLOW_ALL_HOSTNAME_VERIFIER */",
            // Только импорт.
            "import org.apache.http.conn.ssl.NoopHostnameVerifier",
        ] {
            assert!(run(KT, text, Lang::Kotlin).is_empty(), "{text}");
        }
    }

    #[test]
    fn crypto_patterns() {
        let text = "import javax.crypto.Cipher\nfun f() {\n val a = Cipher.getInstance(\"AES\")\n val b = Cipher.getInstance(\"AES/ECB/PKCS5Padding\")\n val c = Cipher.getInstance(\"AES/GCM/NoPadding\")\n val d = Cipher.getInstance(\"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\")\n val e = Cipher.getInstance(\"DES/CBC/PKCS5Padding\")\n val g = Cipher.getInstance(TRANSFORMATION)\n val h = Cipher.getInstance(\"RSA/ECB/NoPadding\")\n}";
        let got = run(KT, text, Lang::Kotlin);
        let lines: Vec<u32> = got.iter().map(|g| g.3).collect();
        assert_eq!(lines, vec![3, 4, 7, 9]);
        assert!(got.iter().all(|g| g.0 == CRYPTO_ID));
    }

    #[test]
    fn digest_only_near_passwords() {
        let yes = "fun hashPassword(pw: String): ByteArray {\n  return MessageDigest.getInstance(\"MD5\").digest(pw.toByteArray())\n}";
        let got = run(KT, yes, Lang::Kotlin);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2, Severity::Low);
        let no = "fun cacheKey(url: String): ByteArray {\n  return MessageDigest.getInstance(\"MD5\").digest(url.toByteArray())\n}\nfun sha(p: String) = MessageDigest.getInstance(\"SHA-256\")";
        assert!(run(KT, no, Lang::Kotlin).is_empty());
    }

    #[test]
    fn world_readable() {
        let text = "class A : Activity() { fun f() { openFileOutput(\"x\", Context.MODE_WORLD_READABLE) } }";
        assert_eq!(run(KT, text, Lang::Kotlin).len(), 1);
        assert!(run(KT, "// MODE_WORLD_READABLE", Lang::Kotlin).is_empty());
    }

    #[test]
    fn logging_of_secrets() {
        let text = "fun f(password: String, token: String?, tokens: List<String>) {\n Log.d(TAG, \"login $password\")\n Log.i(TAG, \"t=\" + token)\n Log.d(TAG, \"has token: ${token != null}\")\n Log.d(TAG, \"n=\" + tokens.size)\n Log.d(TAG, \"password reset requested\")\n Timber.w(\"refresh %s\", user.refreshToken)\n Log.d(TAG, getString(R.string.password_hint))\n Log.d(TAG, \"len \" + password.length)\n}";
        let got = run(KT, text, Lang::Kotlin);
        let lines: Vec<u32> = got.iter().map(|g| g.3).collect();
        assert_eq!(lines, vec![2, 3, 7]);
        assert!(got.iter().all(|g| g.0 == LOG_ID && g.2 == Severity::Low));
    }

    #[test]
    fn field_test_false_positive_patterns() {
        // NewPipe: лог за `if (BuildConfig.DEBUG)` в release-сборку не попадает.
        let text = "fun f(password: String) {\n if (BuildConfig.DEBUG) Log.d(TAG, \"p=$password\")\n if (BuildConfig.DEBUG) {\n  Log.d(TAG, password)\n }\n if (!BuildConfig.DEBUG) { Log.d(TAG, password) }\n}";
        let got = run(KT, text, Lang::Kotlin);
        let lines: Vec<u32> = got.iter().map(|g| g.3).collect();
        assert_eq!(lines, vec![6]);
        // Thunderbird: переменная-ответ/ошибка с «token» в имени — не секрет.
        let text = "fun f(negativeResponseFromOldToken: Exception) { Log.v(TAG, negativeResponseFromOldToken, \"x\") }";
        assert!(run(KT, text, Lang::Kotlin).is_empty());
        // Nextcloud: `putString` в Bundle/Intent — не SharedPreferences.
        let text = "import android.content.SharedPreferences\nfun f(result: Bundle, editor: SharedPreferences.Editor, token: String) {\n result.putString(Constants.SSO_TOKEN, token)\n intent.putString(\"token\", token)\n editor.putString(KEY_TOKEN, token)\n}";
        let got = run(KT, text, Lang::Kotlin);
        let lines: Vec<u32> = got.iter().map(|g| g.3).collect();
        assert_eq!(lines, vec![5]);
    }

    #[test]
    fn shared_preferences_tokens() {
        let text = "fun save(p: SharedPreferences, accessToken: String) {\n p.edit().putString(\"access_token\", accessToken).apply()\n p.edit().putString(KEY_THEME, theme).apply()\n p.edit().putString(\"token\", \"\").apply()\n}";
        let got = run(KT, text, Lang::Kotlin);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2, Severity::Info);
        let encrypted =
            format!("import androidx.security.crypto.EncryptedSharedPreferences\n{text}");
        assert!(run(KT, &encrypted, Lang::Kotlin).is_empty());
    }

    #[test]
    fn test_sources_are_skipped_and_debug_is_downgraded() {
        let text = "import javax.net.ssl.*\nobject T : X509TrustManager { override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {} }";
        assert!(run("app/src/test/java/T.kt", text, Lang::Kotlin).is_empty());
        assert!(run("app/src/androidTest/java/T.kt", text, Lang::Kotlin).is_empty());
        let got = run("app/src/debug/java/T.kt", text, Lang::Kotlin);
        assert_eq!(got[0].2, Severity::Low);
    }

    #[test]
    fn ids_do_not_depend_on_lines() {
        let text = "import javax.crypto.Cipher\nval a = Cipher.getInstance(\"AES\")";
        let shifted = format!("\n\n// moved\n{text}");
        let id = |t: &str| {
            let mut out = RuleOutput::default();
            check(
                KT,
                t,
                Lang::Kotlin,
                None,
                &mut out,
                &mut CodeStats::default(),
            );
            out.findings[0].id.clone()
        };
        assert_eq!(id(text), id(&shifted));
    }
}
