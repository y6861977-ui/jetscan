//! WEB-FIREBASE-010: правила безопасности Firebase из репозитория — `firestore.rules`,
//! `storage.rules` (язык правил) и `database.rules.json` (Realtime Database).
//!
//! Firebase-конфиг веб-приложения (`apiKey: "AIza…"`) публичен по замыслу и находкой не является:
//! доступ к данным решают только правила. Проверяем их по файлам, к проекту не подключаемся:
//! - `allow …: if true;` / `allow …;` (без условия), `.read`/`.write: true` → по операции и пути;
//! - тестовый режим `request.time < timestamp.date(…)` / `"now < 1700000000000"` → high/potential;
//! - только `request.auth != null` (или `"auth != null"`) на всю базу/все файлы → medium/needs_review.
//!
//! Файл `*.rules` без `service cloud.firestore` / `service firebase.storage` — не Firebase (udev и
//! прочие DSL): молча пропускаем. Никогда не `confirmed`: развёрнутые правила могут отличаться.

use super::rls::{is_plain_name, is_private_name, is_public_name};
use crate::ui;
use crate::web_audit::location::{EXCERPT_MAX_CHARS, LineIndex};
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};
use std::collections::BTreeMap;

pub const RULE_ID: &str = "WEB-FIREBASE-010";

pub const REFERENCES: &[&str] = &[
    "https://firebase.google.com/docs/rules/insecure-rules",
    "https://firebase.google.com/docs/firestore/security/get-started",
    "https://firebase.google.com/docs/database/security",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cond {
    /// `true` или правило без условия.
    Open,
    /// Тестовый режим: открыто до даты.
    Until(i64),
    /// Только «пользователь вошёл».
    SignedIn,
    Other,
}

#[derive(Default)]
pub struct FirebaseOutcome {
    pub findings: Vec<WebFinding>,
    /// Разобранные файлы правил.
    pub files: usize,
    /// Файлы, которые не удалось разобрать целиком (незакрытая скобка/строка, битый JSON).
    pub broken: Vec<String>,
    /// Файлы правил из `firebase.json`, которых нет среди разобранных.
    pub missing: Vec<String>,
    pub ignored_inline: usize,
}

#[derive(Default)]
pub struct FirebaseCollector {
    out: FirebaseOutcome,
    seen: Vec<String>,
    referenced: Vec<String>,
}

impl FirebaseCollector {
    /// `*.rules`: Firestore или Cloud Storage.
    pub fn rules_file(&mut self, path: &str, text: &str) {
        let stripped = strip_comments(text);
        let service = if stripped.contains("cloud.firestore") {
            Service::Firestore
        } else if stripped.contains("firebase.storage") {
            Service::Storage
        } else {
            return;
        };
        self.seen.push(path.to_string());
        self.out.files += 1;
        let mut p = RulesParser {
            text: &stripped,
            b: stripped.as_bytes(),
            i: 0,
            functions: BTreeMap::new(),
            allows: Vec::new(),
            broken: false,
        };
        p.top();
        // Функции объявляются где угодно в файле — классифицируем после разбора.
        let index = LineIndex::new(text);
        let allows = std::mem::take(&mut p.allows);
        for a in allows {
            let cond = match &a.cond {
                None => Cond::Open,
                Some(expr) => p.classify(expr, 0),
            };
            if let Some(d) = rules_draft(service, &a, cond) {
                self.push(path, text, &index, a.at, &a.excerpt, d);
            }
        }
        if p.broken {
            self.out.broken.push(ui::sanitize_line(path));
        }
    }

    /// `*.rules.json`: Realtime Database.
    pub fn database_file(&mut self, path: &str, text: &str) {
        let mut j = JsonScan {
            b: text.as_bytes(),
            i: 0,
            hits: Vec::new(),
            broken: false,
        };
        j.skip();
        let mut path_keys = Vec::new();
        j.value(&mut path_keys);
        j.skip();
        if j.i < j.b.len() {
            j.broken = true;
        }
        let has_rules = j
            .hits
            .iter()
            .any(|h| h.path.first().is_some_and(|k| k == "rules"));
        if !has_rules && !j.broken {
            return; // другой JSON (`foo.rules.json` от чего-то ещё)
        }
        self.seen.push(path.to_string());
        self.out.files += 1;
        if j.broken {
            self.out.broken.push(ui::sanitize_line(path));
        }
        let index = LineIndex::new(text);
        for h in std::mem::take(&mut j.hits) {
            if h.path.first().map(String::as_str) != Some("rules") {
                continue;
            }
            let keys = &h.path[1..];
            let Some((access, parents)) = keys.split_last() else {
                continue;
            };
            if access != ".read" && access != ".write" {
                continue;
            }
            let cond = match &h.value {
                Rtdb::Bool(true) => Cond::Open,
                Rtdb::Bool(false) => Cond::Other,
                Rtdb::Str(s) => classify_rtdb(s),
            };
            if let Some(d) = rtdb_draft(access == ".write", parents, cond) {
                let excerpt = format!(
                    "\"{access}\": {}",
                    match &h.value {
                        Rtdb::Bool(b) => b.to_string(),
                        Rtdb::Str(s) => format!("\"{}\"", mask_strings(s)),
                    }
                );
                self.push(path, text, &index, h.at, &excerpt, d);
            }
        }
    }

    /// `firebase.json`: значения `"rules"` — пути к файлам правил (от каталога firebase.json).
    pub fn config_file(&mut self, path: &str, text: &str) {
        let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
        let Ok(json) = crate::json::parse(text) else {
            return;
        };
        let mut found = Vec::new();
        collect_rules_paths(&json, &mut found);
        for f in found {
            let f = f.trim_start_matches("./").replace('\\', "/");
            self.referenced.push(if dir.is_empty() {
                f
            } else {
                format!("{dir}/{f}")
            });
        }
    }

    fn push(
        &mut self,
        path: &str,
        text: &str,
        index: &LineIndex,
        at: usize,
        excerpt: &str,
        d: Draft,
    ) {
        let (line, col) = index.line_col(text, at).unwrap_or((1, 1));
        let ignored = index
            .line_range(text, line as usize)
            .is_some_and(|(s, e)| text[s..e].contains(crate::secrets::scan::INLINE_IGNORE));
        if ignored {
            self.out.ignored_inline += 1;
            return;
        }
        self.out.findings.push(WebFinding {
            id: finding_id(RULE_ID, path, &d.key),
            rule_id: RULE_ID,
            title: ui::sanitize_line(&d.title),
            category: "access_control",
            severity: d.severity,
            confidence: d.confidence,
            location: SourceLocation {
                relative_path: path.to_string(),
                line: Some(line),
                column: Some(col),
            },
            evidence: Evidence {
                redacted_excerpt: Some(clip(&ui::sanitize_line(excerpt))),
                fingerprint: None,
            },
            explanation: ui::sanitize_line(&format!(
                "{} Based on the rules file in this repository; rules deployed from the Firebase \
                 console may differ. The Firebase web config (apiKey) is public by design, so \
                 these rules are the only protection.",
                d.explanation
            )),
            remediation_id: Some(format!("{RULE_ID}:scope-security-rules")),
            references: REFERENCES.to_vec(),
            cwe_ids: vec![d.cwe],
            tags: vec![
                "web".to_string(),
                "firebase".to_string(),
                d.service.to_string(),
                d.tag.to_string(),
            ],
        });
    }

    pub fn finish(mut self) -> FirebaseOutcome {
        let seen: Vec<String> = self.seen.iter().map(|s| s.to_ascii_lowercase()).collect();
        self.referenced.sort();
        self.referenced.dedup();
        for r in self.referenced {
            if !seen.contains(&r.to_ascii_lowercase()) {
                self.out.missing.push(ui::sanitize_line(&r));
            }
        }
        self.out
    }
}

fn collect_rules_paths(json: &crate::json::Json, out: &mut Vec<String>) {
    use crate::json::Json;
    match json {
        Json::Obj(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                let v = &map[k];
                if k == "rules"
                    && let Some(s) = v.as_str()
                {
                    out.push(s.to_string());
                } else {
                    collect_rules_paths(v, out);
                }
            }
        }
        Json::Arr(items) => items.iter().for_each(|v| collect_rules_paths(v, out)),
        _ => {}
    }
}

fn clip(s: &str) -> String {
    if s.chars().count() > EXCERPT_MAX_CHARS {
        let cut: String = s.chars().take(EXCERPT_MAX_CHARS - 1).collect();
        format!("{cut}…")
    } else {
        s.to_string()
    }
}

/// Строки в кавычках, не похожие на короткие имена, — `'…'`.
fn mask_strings(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find(['\'', '"']) {
        let q = rest.as_bytes()[start] as char;
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find(q) else {
            out.push_str(&rest[start..]);
            return out;
        };
        let inner = &after[..end];
        if is_plain_name(inner) {
            out.push(q);
            out.push_str(inner);
            out.push(q);
        } else {
            out.push(q);
            out.push('…');
            out.push(q);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Комментарии `//` и `/* */` вне строк → пробелы (смещения сохраняются).
fn strip_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            q @ (b'\'' | b'"') => {
                i += 1;
                while i < b.len() && b[i] != q && b[i] != b'\n' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                    if b[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
                let close = (i + 2).min(b.len());
                out[i..close].fill(b' ');
                i += 2;
            }
            _ => i += 1,
        }
    }
    // Заменяли только ASCII-байты комментариев целиком (многобайтные символы внутри — тоже
    // целиком), так что UTF-8 сохраняется; на всякий случай — с потерями.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Service {
    Firestore,
    Storage,
}

impl Service {
    fn label(self) -> &'static str {
        match self {
            Service::Firestore => "Firestore",
            Service::Storage => "Cloud Storage",
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Service::Firestore => "firestore",
            Service::Storage => "storage",
        }
    }

    /// Префикс корня: `/databases/{database}/documents` или `/b/{bucket}/o`.
    fn root_len(self, path: &[String]) -> usize {
        let root = match self {
            Service::Firestore => ["databases", "", "documents"],
            Service::Storage => ["b", "", "o"],
        };
        let matches =
            path.len() >= 3 && path[0] == root[0] && path[1].starts_with('{') && path[2] == root[2];
        if matches { 3 } else { 0 }
    }
}

struct Allow {
    ops: Vec<String>,
    cond: Option<String>,
    path: Vec<String>,
    at: usize,
    excerpt: String,
}

struct RulesParser<'a> {
    text: &'a str,
    b: &'a [u8],
    i: usize,
    /// Функции без параметров: имя → выражение `return`.
    functions: BTreeMap<String, String>,
    allows: Vec<Allow>,
    broken: bool,
}

impl RulesParser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn word(&mut self) -> Option<String> {
        self.ws();
        let start = self.i;
        while self.i < self.b.len()
            && (self.b[self.i].is_ascii_alphanumeric() || matches!(self.b[self.i], b'_' | b'.'))
        {
            self.i += 1;
        }
        (self.i > start).then(|| self.text[start..self.i].to_string())
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.i).copied()
    }

    /// До `;` (или `}`) верхнего уровня; возвращает текст и ставит курсор за `;`.
    fn until_semicolon(&mut self) -> String {
        let start = self.i;
        let mut depth = 0i32;
        while self.i < self.b.len() {
            match self.b[self.i] {
                q @ (b'\'' | b'"') => {
                    self.i += 1;
                    while self.i < self.b.len() && self.b[self.i] != q {
                        if self.b[self.i] == b'\\' {
                            self.i += 1;
                        }
                        self.i += 1;
                    }
                }
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' => depth -= 1,
                b'}' if depth == 0 => return self.text[start..self.i].to_string(),
                b'}' => depth -= 1,
                b';' if depth == 0 => {
                    let s = self.text[start..self.i].to_string();
                    self.i += 1;
                    return s;
                }
                _ => {}
            }
            self.i += 1;
        }
        self.broken = true;
        self.text[start.min(self.b.len())..].to_string()
    }

    fn top(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_alphabetic() {
                match self.word().as_deref() {
                    Some("service") => {
                        while self.peek().is_some_and(|c| c != b'{') {
                            self.i += 1;
                        }
                        if self.peek() == Some(b'{') {
                            self.i += 1;
                            self.block(&[]);
                        }
                    }
                    Some("function") => self.function(),
                    _ => {
                        self.until_semicolon();
                    }
                }
            } else {
                self.i += 1;
            }
        }
    }

    /// Тело блока после `{` до парной `}`.
    fn block(&mut self, path: &[String]) {
        loop {
            let Some(c) = self.peek() else {
                self.broken = true;
                return;
            };
            if c == b'}' {
                self.i += 1;
                return;
            }
            if !c.is_ascii_alphabetic() {
                self.i += 1;
                continue;
            }
            let at = self.i;
            match self.word().as_deref() {
                Some("match") => {
                    self.ws();
                    let segments = self.match_path();
                    if self.peek() != Some(b'{') {
                        self.broken = true;
                        return;
                    }
                    self.i += 1;
                    let mut full = path.to_vec();
                    full.extend(segments);
                    self.block(&full);
                }
                Some("allow") => {
                    let body = self.until_semicolon();
                    let (ops, cond) = match body.split_once(':') {
                        Some((ops, cond)) => {
                            let cond = cond.trim();
                            let cond = cond.strip_prefix("if").map_or(cond, str::trim);
                            (ops, Some(cond.to_string()))
                        }
                        None => (body.as_str(), None),
                    };
                    let ops = ops
                        .split(',')
                        .map(|o| o.trim().to_string())
                        .filter(|o| !o.is_empty())
                        .collect();
                    let excerpt = mask_strings(
                        &format!("allow {};", body.trim())
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                    self.allows.push(Allow {
                        ops,
                        cond,
                        path: path.to_vec(),
                        at,
                        excerpt,
                    });
                }
                Some("function") => self.function(),
                _ => {
                    self.until_semicolon();
                }
            }
        }
    }

    /// `/a/{b}/{c=**}` → сегменты.
    fn match_path(&mut self) -> Vec<String> {
        let mut segments = Vec::new();
        let mut current = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if c == b'/' {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
                self.i += 1;
            } else if c == b'{' && current.is_empty() {
                let start = self.i;
                while self.i < self.b.len() && self.b[self.i] != b'}' {
                    self.i += 1;
                }
                self.i = (self.i + 1).min(self.b.len());
                segments.push(self.text[start..self.i].to_string());
            } else if c.is_ascii_whitespace() || c == b'{' {
                break;
            } else {
                let start = self.i;
                while self.i < self.b.len()
                    && !matches!(self.b[self.i], b'/' | b'{')
                    && !self.b[self.i].is_ascii_whitespace()
                {
                    self.i += 1;
                }
                current.push_str(&self.text[start..self.i]);
            }
        }
        if !current.is_empty() {
            segments.push(current);
        }
        segments
    }

    /// `function name(params) { …; return expr; }` — запоминаем только функции без параметров.
    fn function(&mut self) {
        let name = self.word().unwrap_or_default();
        if self.peek() != Some(b'(') {
            self.until_semicolon();
            return;
        }
        let params_start = self.i + 1;
        while self.i < self.b.len() && self.b[self.i] != b')' {
            self.i += 1;
        }
        let params = self.text[params_start.min(self.b.len())..self.i.min(self.b.len())]
            .trim()
            .to_string();
        self.i += 1;
        if self.peek() != Some(b'{') {
            self.broken = true;
            return;
        }
        self.i += 1;
        let mut ret = None;
        loop {
            let Some(c) = self.peek() else {
                self.broken = true;
                return;
            };
            if c == b'}' {
                self.i += 1;
                break;
            }
            let stmt = self.until_semicolon();
            if let Some(expr) = stmt.trim().strip_prefix("return") {
                ret = Some(expr.trim().to_string());
            }
            if self.i < self.b.len() && self.b[self.i] == b'}' {
                self.i += 1;
                break;
            }
        }
        if params.is_empty()
            && let Some(expr) = ret
        {
            self.functions.insert(name, expr);
        }
    }

    fn classify(&self, expr: &str, depth: usize) -> Cond {
        let mut n: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
        while n.starts_with('(') && n.ends_with(')') && balanced(&n[1..n.len() - 1]) {
            n = n[1..n.len() - 1].to_string();
        }
        if n == "true" {
            return Cond::Open;
        }
        if let Some(days) = test_mode_date(&n) {
            return Cond::Until(days);
        }
        if matches!(
            n.as_str(),
            "request.auth!=null"
                | "null!=request.auth"
                | "request.auth.uid!=null"
                | "request.auth!=null&&request.auth.uid!=null"
        ) {
            return Cond::SignedIn;
        }
        if depth < 4
            && let Some(name) = n.strip_suffix("()")
            && let Some(body) = self.functions.get(name)
        {
            return self.classify(body, depth + 1);
        }
        Cond::Other
    }
}

fn balanced(s: &str) -> bool {
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

/// `request.time<timestamp.date(2024,1,1)` → дни от 1970-01-01.
fn test_mode_date(n: &str) -> Option<i64> {
    let rest = n
        .strip_prefix("request.time<=timestamp.date(")
        .or_else(|| n.strip_prefix("request.time<timestamp.date("))?;
    let args = rest.strip_suffix(')')?;
    let parts: Vec<i64> = args
        .split(',')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let [y, m, d] = parts[..] else {
        return None;
    };
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| days_from_civil(y, m, d))
}

/// Дни от эпохи для даты григорианского календаря (алгоритм Хиннанта).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn date_label(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn classify_rtdb(s: &str) -> Cond {
    let n: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if n == "true" {
        return Cond::Open;
    }
    if let Some(ms) = n.strip_prefix("now<").and_then(|v| v.parse::<i64>().ok()) {
        return Cond::Until(ms.div_euclid(86_400_000));
    }
    if matches!(
        n.as_str(),
        "auth!=null" | "auth!==null" | "auth.uid!=null" | "auth.uid!==null" | "null!=auth"
    ) {
        return Cond::SignedIn;
    }
    Cond::Other
}

struct Draft {
    key: String,
    severity: Severity,
    confidence: Confidence,
    title: String,
    explanation: String,
    cwe: &'static str,
    service: &'static str,
    tag: &'static str,
}

const STORAGE_PUBLIC: &[&str] = &[
    "public", "avatars", "avatar", "images", "img", "assets", "static",
];

fn rules_draft(service: Service, a: &Allow, cond: Cond) -> Option<Draft> {
    let rest = &a.path[service.root_len(&a.path)..];
    if rest.is_empty() {
        return None; // правило на сам корень (`/databases/{db}/documents`) не совпадает ни с одним документом
    }
    let all = rest.len() == 1 && rest[0].starts_with('{') && rest[0].contains("=**");
    let ops: Vec<&str> = a.ops.iter().map(String::as_str).collect();
    let writes = ops
        .iter()
        .any(|o| matches!(*o, "write" | "create" | "update" | "delete"));
    let reads = ops.iter().any(|o| matches!(*o, "read" | "get" | "list"));
    if !writes && !reads {
        return None;
    }
    let verb = match (reads, writes) {
        (true, true) => "read and write",
        (false, true) => "write",
        _ => "read",
    };
    let thing = match service {
        Service::Firestore => "document",
        Service::Storage => "file",
    };
    let shown_path = format!("/{}", rest.join("/"));
    let scope = if all {
        format!("every {thing}")
    } else {
        format!("{thing}s under {}", ui::sanitize_line(&shown_path))
    };
    let first = rest
        .iter()
        .find(|s| !s.starts_with('{'))
        .cloned()
        .unwrap_or_default();
    let public_name = match service {
        Service::Firestore => is_public_name(&first),
        Service::Storage => STORAGE_PUBLIC.contains(&first.to_ascii_lowercase().as_str()),
    };
    let label = service.label();
    let ops_text = ops.join(", ");
    let (severity, confidence, title, explanation, tag) = match cond {
        Cond::Open => {
            let (sev, conf) = if writes || all || is_private_name(&first) {
                (Severity::High, Confidence::Potential)
            } else if public_name {
                (Severity::Low, Confidence::NeedsReview)
            } else {
                (Severity::Medium, Confidence::NeedsReview)
            };
            let note = if !writes && !all && public_name {
                " The path suggests public content, so this may be intended."
            } else {
                ""
            };
            (
                sev,
                conf,
                format!("{label} rules let anyone {verb} {scope}"),
                format!(
                    "`allow {ops_text}` on {shown} has no condition (or `if true`), so anyone, \
                     signed in or not, can {verb} {scope}.{note}",
                    shown = ui::sanitize_line(&shown_path)
                ),
                "rules:open",
            )
        }
        Cond::Until(days) => {
            let date = date_label(days);
            (
                Severity::High,
                Confidence::Potential,
                format!("{label} rules are in test mode: anyone can {verb} {scope} until {date}"),
                format!(
                    "`allow {ops_text}` is limited only by `request.time < timestamp.date(…)`, the \
                     test-mode default: until {date} anyone can {verb} {scope}; after it, all \
                     access is denied and the app stops working, which usually ends in the rule \
                     being extended rather than fixed. Write real per-user rules."
                ),
                "rules:test-mode",
            )
        }
        Cond::SignedIn if all => (
            Severity::Medium,
            Confidence::NeedsReview,
            format!("{label} rules let any signed-in user {verb} {scope}"),
            format!(
                "`allow {ops_text}` on {shown} only checks `request.auth != null`. Anyone can \
                 create an account (sign-up is open unless disabled), so any user can {verb} \
                 {scope}, including other users' data. Match the owner, for example \
                 `request.auth.uid == userId`.",
                shown = ui::sanitize_line(&shown_path)
            ),
            "rules:any-signed-in",
        ),
        _ => return None,
    };
    Some(Draft {
        key: format!("{}|{}|{}|{tag}", service.tag(), shown_path, ops_text),
        severity,
        confidence,
        title,
        explanation,
        cwe: "CWE-862",
        service: service.tag(),
        tag,
    })
}

fn rtdb_draft(write: bool, parents: &[String], cond: Cond) -> Option<Draft> {
    let root = parents.is_empty();
    let shown = if root {
        "the database root".to_string()
    } else {
        ui::sanitize_line(&format!("/{}", parents.join("/")))
    };
    let scope = if root {
        "the entire database".to_string()
    } else {
        format!("everything under {shown}")
    };
    let last = parents
        .iter()
        .rev()
        .find(|k| !k.starts_with('$'))
        .cloned()
        .unwrap_or_default();
    let verb = if write { "write" } else { "read" };
    let access = if write { ".write" } else { ".read" };
    let (severity, confidence, title, explanation, tag) = match cond {
        Cond::Open => {
            let (sev, conf) = if write || root || is_private_name(&last) {
                (Severity::High, Confidence::Potential)
            } else if is_public_name(&last) {
                (Severity::Low, Confidence::NeedsReview)
            } else {
                (Severity::Medium, Confidence::NeedsReview)
            };
            (
                sev,
                conf,
                format!("Realtime Database rules let anyone {verb} {scope}"),
                format!(
                    "`{access}: true` at {shown}: anyone, signed in or not, can {verb} {scope}. \
                     Rules cascade, so deeper rules cannot take this back."
                ),
                "rules:open",
            )
        }
        Cond::Until(days) => {
            let date = date_label(days);
            (
                Severity::High,
                Confidence::Potential,
                format!(
                    "Realtime Database rules are in test mode: anyone can {verb} {scope} until {date}"
                ),
                format!(
                    "`{access}` at {shown} is limited only by `now < …`, the test-mode default: \
                     until {date} anyone can {verb} {scope}. Write real per-user rules."
                ),
                "rules:test-mode",
            )
        }
        Cond::SignedIn if root => (
            Severity::Medium,
            Confidence::NeedsReview,
            format!("Realtime Database rules let any signed-in user {verb} {scope}"),
            format!(
                "`{access}` at the root only checks `auth != null`. Anyone can create an account, \
                 so any user can {verb} {scope}, including other users' data. Scope rules to \
                 `$uid === auth.uid`."
            ),
            "rules:any-signed-in",
        ),
        _ => return None,
    };
    Some(Draft {
        key: format!("rtdb|{shown}|{access}|{tag}"),
        severity,
        confidence,
        title,
        explanation,
        cwe: "CWE-862",
        service: "realtime-database",
        tag,
    })
}

// ---------- JSON с позициями (только то, что нужно для правил RTDB) ----------

enum Rtdb {
    Bool(bool),
    Str(String),
}

struct Hit {
    path: Vec<String>,
    value: Rtdb,
    at: usize,
}

struct JsonScan<'a> {
    b: &'a [u8],
    i: usize,
    hits: Vec<Hit>,
    broken: bool,
}

impl JsonScan<'_> {
    /// Пробелы и комментарии (Firebase CLI принимает их в rules.json).
    fn skip(&mut self) {
        loop {
            while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
            if self.b.get(self.i) == Some(&b'/') && self.b.get(self.i + 1) == Some(&b'/') {
                while self.i < self.b.len() && self.b[self.i] != b'\n' {
                    self.i += 1;
                }
            } else if self.b.get(self.i) == Some(&b'/') && self.b.get(self.i + 1) == Some(&b'*') {
                self.i += 2;
                while self.i < self.b.len()
                    && !(self.b[self.i] == b'*' && self.b.get(self.i + 1) == Some(&b'/'))
                {
                    self.i += 1;
                }
                self.i = (self.i + 2).min(self.b.len());
            } else {
                return;
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.b.get(self.i) != Some(&b'"') {
            return None;
        }
        self.i += 1;
        let mut out = Vec::new();
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'"' => {
                    self.i += 1;
                    return Some(String::from_utf8_lossy(&out).into_owned());
                }
                b'\\' => {
                    let e = self.b.get(self.i + 1).copied().unwrap_or(b'\\');
                    out.push(match e {
                        b'n' => b'\n',
                        b't' => b'\t',
                        other => other,
                    });
                    self.i += 2;
                }
                c => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        self.broken = true;
        None
    }

    fn value(&mut self, path: &mut Vec<String>) -> Option<Rtdb> {
        self.skip();
        match self.b.get(self.i)? {
            b'{' => {
                self.i += 1;
                loop {
                    self.skip();
                    match self.b.get(self.i) {
                        Some(b'}') => {
                            self.i += 1;
                            return None;
                        }
                        Some(b',') => {
                            self.i += 1;
                            continue;
                        }
                        Some(b'"') => {}
                        _ => {
                            self.broken = true;
                            self.i = self.b.len();
                            return None;
                        }
                    }
                    let at = self.i;
                    let key = self.string()?;
                    self.skip();
                    if self.b.get(self.i) != Some(&b':') {
                        self.broken = true;
                        self.i = self.b.len();
                        return None;
                    }
                    self.i += 1;
                    path.push(key);
                    if let Some(v) = self.value(path) {
                        self.hits.push(Hit {
                            path: path.clone(),
                            value: v,
                            at,
                        });
                    }
                    path.pop();
                }
            }
            b'[' => {
                self.i += 1;
                loop {
                    self.skip();
                    match self.b.get(self.i) {
                        Some(b']') => {
                            self.i += 1;
                            return None;
                        }
                        Some(b',') => self.i += 1,
                        None => {
                            self.broken = true;
                            return None;
                        }
                        _ => {
                            self.value(path);
                        }
                    }
                }
            }
            b'"' => self.string().map(Rtdb::Str),
            _ => {
                let start = self.i;
                while self.i < self.b.len()
                    && (self.b[self.i].is_ascii_alphanumeric()
                        || matches!(self.b[self.i], b'.' | b'-' | b'+'))
                {
                    self.i += 1;
                }
                match &self.b[start..self.i] {
                    b"true" => Some(Rtdb::Bool(true)),
                    b"false" => Some(Rtdb::Bool(false)),
                    [] => {
                        self.broken = true;
                        self.i = self.b.len();
                        None
                    }
                    _ => None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> FirebaseOutcome {
        let mut c = FirebaseCollector::default();
        c.rules_file("firestore.rules", text);
        c.finish()
    }

    fn rtdb(text: &str) -> FirebaseOutcome {
        let mut c = FirebaseCollector::default();
        c.database_file("database.rules.json", text);
        c.finish()
    }

    fn summary(out: &FirebaseOutcome) -> Vec<(String, u32, Severity, Confidence)> {
        out.findings
            .iter()
            .map(|f| {
                (
                    f.title.clone(),
                    f.location.line.unwrap(),
                    f.severity,
                    f.confidence,
                )
            })
            .collect()
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(date_label(days_from_civil(2024, 2, 29)), "2024-02-29");
        assert_eq!(
            date_label(1_700_000_000_000i64.div_euclid(86_400_000)),
            "2023-11-14"
        );
    }

    #[test]
    fn firestore_open_test_mode_and_signed_in() {
        let out = rules(
            "rules_version = '2';\n\
             service cloud.firestore {\n\
               match /databases/{database}/documents {\n\
                 // allow read, write: if true;   (commented out: not a finding)\n\
                 match /{document=**} {\n\
                   allow read, write: if request.time < timestamp.date(2024, 1, 1);\n\
                 }\n\
                 match /posts/{id} {\n\
                   allow read: if true;\n\
                   allow write: if request.auth != null && request.auth.uid == resource.data.author;\n\
                 }\n\
                 match /users/{uid} { allow read; }\n\
                 match /{path=**} { allow read: if isSignedIn(); }\n\
                 match /orgs/{org} { allow write: if request.auth != null; }\n\
               }\n\
               function isSignedIn() { return request.auth != null; }\n\
             }\n",
        );
        assert_eq!(
            summary(&out),
            vec![
                (
                    "Firestore rules are in test mode: anyone can read and write every document until 2024-01-01"
                        .to_string(),
                    6,
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Firestore rules let anyone read documents under /posts/{id}".to_string(),
                    9,
                    Severity::Low,
                    Confidence::NeedsReview
                ),
                (
                    "Firestore rules let anyone read documents under /users/{uid}".to_string(),
                    12,
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Firestore rules let any signed-in user read every document".to_string(),
                    13,
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
            ]
        );
        assert!(out.broken.is_empty());
        assert_eq!(out.files, 1);
    }

    #[test]
    fn firestore_root_open_is_high_and_owner_rules_are_quiet() {
        let out = rules(
            "service cloud.firestore { match /databases/{db}/documents {\n\
               match /{document=**} { allow read, write: if true; }\n\
               match /notes/{uid} { allow read, write: if request.auth.uid == uid; }\n\
             } }",
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, Severity::High);
        assert_eq!(
            out.findings[0].title,
            "Firestore rules let anyone read and write every document"
        );
        assert_eq!(
            out.findings[0].evidence.redacted_excerpt.as_deref(),
            Some("allow read, write: if true;")
        );
    }

    #[test]
    fn storage_default_rule_and_non_firebase_rules() {
        let mut c = FirebaseCollector::default();
        c.rules_file(
            "storage.rules",
            "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if request.auth != null; // jetscan:ignore\n    }\n    match /public/{f} { allow read: if true; }\n  }\n}\n",
        );
        c.rules_file("udev/99-usb.rules", "SUBSYSTEM==\"usb\", MODE=\"0666\"\n");
        let out = c.finish();
        assert_eq!(out.files, 1);
        assert_eq!(out.ignored_inline, 1);
        assert_eq!(
            summary(&out),
            vec![(
                "Cloud Storage rules let anyone read files under /public/{f}".to_string(),
                7,
                Severity::Low,
                Confidence::NeedsReview
            )]
        );
    }

    #[test]
    fn broken_rules_are_reported() {
        let out = rules(
            "service cloud.firestore { match /databases/{db}/documents { match /{d=**} { allow read: if true;",
        );
        assert_eq!(out.broken, vec!["firestore.rules".to_string()]);
        assert_eq!(out.findings.len(), 1);
    }

    #[test]
    fn rtdb_root_open_test_mode_nested_and_signed_in() {
        let out = rtdb(
            "{\n  \"rules\": {\n    \".read\": \"now < 1700000000000\",\n    \".write\": true,\n    \"posts\": { \".read\": true },\n    \"users\": { \"$uid\": { \".read\": \"$uid === auth.uid\" } }\n  }\n}\n",
        );
        assert_eq!(
            summary(&out),
            vec![
                (
                    "Realtime Database rules are in test mode: anyone can read the entire database until 2023-11-14"
                        .to_string(),
                    3,
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Realtime Database rules let anyone write the entire database".to_string(),
                    4,
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Realtime Database rules let anyone read everything under /posts".to_string(),
                    5,
                    Severity::Low,
                    Confidence::NeedsReview
                ),
            ]
        );
        let out =
            rtdb("// comment\n{ \"rules\": { \".read\": \"auth != null\", \".write\": false } }");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, Severity::Medium);
        let other = rtdb("{ \"name\": \"x\" }");
        assert_eq!(other.files, 0);
        let broken = rtdb("{ \"rules\": { \".read\": true ");
        assert_eq!(broken.broken.len(), 1);
    }

    #[test]
    fn firebase_json_references_missing_rules() {
        let mut c = FirebaseCollector::default();
        c.config_file(
            "firebase.json",
            "{\"firestore\": {\"rules\": \"config/fs.txt\"}, \"storage\": [{\"bucket\": \"b\", \"rules\": \"storage.rules\"}]}",
        );
        c.rules_file(
            "storage.rules",
            "service firebase.storage { match /b/{bucket}/o { } }",
        );
        let out = c.finish();
        assert_eq!(out.missing, vec!["config/fs.txt".to_string()]);
    }

    #[test]
    fn ids_do_not_depend_on_lines() {
        let a = rules(
            "service cloud.firestore { match /databases/{d}/documents { match /{x=**} { allow read: if true; } } }",
        );
        let b = rules(
            "\n\nservice cloud.firestore { match /databases/{d}/documents { match /{x=**} { allow read: if true; } } }",
        );
        assert_eq!(a.findings[0].id, b.findings[0].id);
        assert_ne!(a.findings[0].location.line, b.findings[0].location.line);
    }
}
