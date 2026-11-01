//! Клиент OSV.dev — порт `seed/audit.rs` (jet audit) с обобщением на экосистемы.
//!
//! Что изменилось против seed (ревью при порте):
//! - Экосистема — из пакета, а не захардкоженный `"npm"`.
//! - curl без временных файлов: тело запроса — через stdin, ответ и код — через stdout,
//!   `Retry-After` — через `%header{}`. В seed имена файлов в общем temp были
//!   предсказуемы (`jet-osv-body-<pid>`). `-q` — не читать чужой `~/.curlrc`,
//!   `--proto =https` — никаких редиректов на другие схемы.
//! - id уязвимости из ответа OSV проверяется по алфавиту, прежде чем попасть в URL.
//! - Кэш: имя файла — хэш (экосистема, имя, версия); в seed `a/b` и `a_b` давали один файл.
//!   Внутри файла имя и версия сверяются.
//! - Пакет, у которого не удалось получить детали уязвимости, не кэшируется
//!   (иначе «(details unavailable)» жил бы в кэше сутки).
//! - Детали тянутся параллельно (django 3.2 — 66 уязвимостей = 66 запросов).
//! - Пагинация querybatch (`next_page_token`) — иначе часть дыр молча терялась бы.
//!
//! Что НЕ меняли: ретраи 1/3/9 с, Retry-After, офлайн-фолбэк на старый кэш с возрастом,
//! CVSS 3.1 по формуле, TTL 24 ч.

use super::{Ecosystem, Package, Severity, Vuln};
use crate::json::{self, Json};
use crate::{hash, ui};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const OSV_BATCH: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN: &str = "https://api.osv.dev/v1/vulns";
const BATCH_LIMIT: usize = 1000;
const MAX_PAGES: usize = 20;
const DETAIL_WORKERS: usize = 8;

const CACHE_TTL_SECS: u64 = 24 * 60 * 60;
/// 2: версии исправлений Go с префиксом `v`; уровень из GHSA-алиаса. 3: `malicious`.
const CACHE_VERSION: f64 = 3.0;

const CONNECT_TIMEOUT: &str = "10";
const MAX_TIME: &str = "60";
const MAX_RETRIES: u32 = 3;
const BACKOFF: [u64; 3] = [1, 3, 9];
const RETRY_AFTER_DEFAULT: u64 = 60;
/// Больше не ждём, даже если сервер просит: лучше честно «OSV недоступен».
const RETRY_AFTER_MAX: u64 = 120;

// ---------------------------------------------------------------------------
// Транспорт
// ---------------------------------------------------------------------------

/// Итог одной HTTP-попытки.
#[derive(Clone, Debug, PartialEq)]
pub enum Attempt {
    Ok(String),
    /// Можно повторить (сеть, таймаут, 5xx, 429). `Some(сек)` — из Retry-After.
    Retry(Option<u64>),
    /// Повторять бессмысленно (4xx кроме 429, нет curl).
    Fatal(String),
}

/// HTTP-транспорт. Подменяется в тестах — логика проверяется без сети.
pub trait Http: Sync {
    /// GET, если `body` — `None`, иначе POST JSON.
    fn request(&self, url: &str, body: Option<&str>) -> Attempt;
}

/// Системный `curl`.
pub struct Curl;

impl Http for Curl {
    fn request(&self, url: &str, body: Option<&str>) -> Attempt {
        let mut cmd = Command::new("curl");
        cmd.arg("-q") // первым: не читать ~/.curlrc
            .args(["-sS", "--proto", "=https", "--retry", "0"])
            .args(["--connect-timeout", CONNECT_TIMEOUT, "--max-time", MAX_TIME])
            .args(["-H", "Accept: application/json"])
            .args(["-A", concat!("jetscan/", env!("CARGO_PKG_VERSION"))])
            .args(["-o", "-", "-w", "\n%{http_code} %header{retry-after}"]);
        if body.is_some() {
            cmd.args(["-X", "POST", "-H", "Content-Type: application/json"])
                .args(["--data-binary", "@-"]);
        }
        cmd.arg(url)
            .stdin(if body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let Ok(mut child) = cmd.spawn() else {
            return Attempt::Fatal("cannot run curl (is it on PATH?)".to_string());
        };
        let writer = match (body, child.stdin.take()) {
            (Some(b), Some(mut pipe)) => {
                let data = b.as_bytes().to_vec();
                Some(std::thread::spawn(move || {
                    let _ = pipe.write_all(&data);
                }))
            }
            _ => None,
        };
        let out = child.wait_with_output();
        if let Some(w) = writer {
            let _ = w.join();
        }
        let Ok(out) = out else {
            return Attempt::Retry(None);
        };
        if !out.status.success() {
            return Attempt::Retry(None); // сеть / DNS / таймаут
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        parse_curl_output(text)
    }
}

/// stdout curl: `<тело>\n<код> <retry-after>`.
fn parse_curl_output(mut text: String) -> Attempt {
    let Some(nl) = text.rfind('\n') else {
        return Attempt::Retry(None);
    };
    let meta = text.split_off(nl);
    let mut parts = meta.trim().splitn(2, ' ');
    let code: u16 = parts.next().and_then(|c| c.parse().ok()).unwrap_or(0);
    let retry_after = parts.next().and_then(|s| s.trim().parse::<u64>().ok());
    classify(code, text, retry_after)
}

fn classify(code: u16, body: String, retry_after: Option<u64>) -> Attempt {
    match code {
        200..=299 => Attempt::Ok(body),
        429 => Attempt::Retry(Some(retry_after.unwrap_or(RETRY_AFTER_DEFAULT))),
        500..=599 => Attempt::Retry(None),
        400..=499 => Attempt::Fatal(format!("OSV rejected the request (HTTP {code})")),
        _ => Attempt::Retry(None),
    }
}

/// Повторы с бэкоффом. `fetch` и `sleep` подставляются — тесты без сети и без пауз.
fn with_retry(mut fetch: impl FnMut() -> Attempt, sleep: &dyn Fn(u64)) -> Result<String, String> {
    for attempt in 0..MAX_RETRIES {
        match fetch() {
            Attempt::Ok(body) => return Ok(body),
            Attempt::Fatal(msg) => return Err(msg),
            Attempt::Retry(delay) => {
                if attempt + 1 >= MAX_RETRIES {
                    break;
                }
                let d = delay.unwrap_or(BACKOFF[attempt as usize]);
                if d > RETRY_AFTER_MAX {
                    break;
                }
                sleep(d);
            }
        }
    }
    Err("OSV is unavailable (retries exhausted)".to_string())
}

pub fn real_sleep(secs: u64) {
    std::thread::sleep(std::time::Duration::from_secs(secs));
}

// ---------------------------------------------------------------------------
// Запросы и разбор ответов (чистые функции)
// ---------------------------------------------------------------------------

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn query_json(p: &Package, page_token: Option<&str>) -> Json {
    let mut q = vec![
        (
            "package",
            obj(vec![
                ("name", Json::Str(p.name.clone())),
                ("ecosystem", Json::Str(p.ecosystem.osv_name().to_string())),
            ]),
        ),
        ("version", Json::Str(p.version.clone())),
    ];
    if let Some(t) = page_token {
        q.push(("page_token", Json::Str(t.to_string())));
    }
    obj(q)
}

/// Тело querybatch.
fn batch_body(queries: Vec<Json>) -> String {
    json::stringify(&obj(vec![("queries", Json::Arr(queries))]))
}

/// Ответ querybatch: по индексу запроса — id уязвимостей и токен следующей страницы.
/// id уязвимостей одного запроса и токен его следующей страницы.
pub type BatchResult = (Vec<String>, Option<String>);

pub fn parse_batch(body: &str, n: usize) -> Result<Vec<BatchResult>, String> {
    let doc = json::parse(body).map_err(|e| format!("OSV sent invalid JSON: {e}"))?;
    let results = doc
        .get("results")
        .and_then(Json::as_array)
        .ok_or("OSV response has no results")?;
    if results.len() != n {
        // Ответ не выровнен с запросом — нельзя понять, чья дыра чья.
        return Err(format!(
            "OSV answered {} results for {n} queries",
            results.len()
        ));
    }
    Ok(results
        .iter()
        .map(|r| {
            let ids = r
                .get("vulns")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|v| v.get("id").and_then(Json::as_str))
                .map(str::to_string)
                .collect();
            let next = r
                .get("next_page_token")
                .and_then(Json::as_str)
                .filter(|t| !t.is_empty())
                .map(str::to_string);
            (ids, next)
        })
        .collect())
}

/// id идёт в URL — только `[A-Za-z0-9._:-]`, разумной длины.
pub fn valid_id(id: &str) -> bool {
    (3..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        && !id.contains("..")
}

/// Ответ `vulns/{id}` → уязвимость применительно к пакету (`eco`, `name`).
pub fn parse_vuln(body: &str, eco: Ecosystem, name: &str) -> Result<Vuln, String> {
    let doc = json::parse(body).map_err(|e| format!("OSV sent invalid JSON: {e}"))?;
    let id = doc.get("id").and_then(Json::as_str).unwrap_or("");
    if !valid_id(id) {
        return Err("OSV vulnerability without a valid id".to_string());
    }

    let raw_summary = doc
        .get("summary")
        .and_then(Json::as_str)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| doc.get("details").and_then(Json::as_str))
        .unwrap_or("");
    let first_line = raw_summary
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let summary = truncate_chars(&ui::sanitize_line(first_line.trim()), 200);

    let aliases = doc
        .get("aliases")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .filter(|a| valid_id(a))
        .map(str::to_string)
        .collect();

    // Опасность: максимум по CVSS 3.x-векторам, иначе текст из database_specific.
    let cvss = doc
        .get("severity")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|s| s.get("score").and_then(Json::as_str))
        .filter_map(cvss31_base_score)
        .fold(None, |best: Option<f64>, v| {
            Some(best.map_or(v, |b| b.max(v)))
        });
    let severity = match cvss {
        Some(v) => Severity::from_score(v),
        None => doc
            .get("database_specific")
            .and_then(|d| d.get("severity"))
            .and_then(Json::as_str)
            .and_then(Severity::from_label)
            .unwrap_or(Severity::Unknown),
    };

    // Исправления — только для нашего пакета в нашей экосистеме (в affected бывают
    // соседи: lodash-es, lodash-rails из RubyGems...).
    let mut fixed: Vec<String> = Vec::new();
    for a in doc.get("affected").and_then(Json::as_array).unwrap_or(&[]) {
        let pkg = a.get("package");
        let a_eco = pkg.and_then(|p| p.get("ecosystem")).and_then(Json::as_str);
        let a_name = pkg.and_then(|p| p.get("name")).and_then(Json::as_str);
        // `ecosystem` бывает с суффиксом: `Debian:11`, `npm` — без; сравниваем основу.
        let same_eco = a_eco.is_some_and(|e| e.split(':').next() == Some(eco.osv_name()));
        if !same_eco || !a_name.is_some_and(|n| eco.same_name(n, name)) {
            continue;
        }
        for r in a.get("ranges").and_then(Json::as_array).unwrap_or(&[]) {
            for e in r.get("events").and_then(Json::as_array).unwrap_or(&[]) {
                if let Some(f) = e.get("fixed").and_then(Json::as_str) {
                    let f = ui::sanitize_line(f);
                    // OSV отрезает `v` у Go-версий, а в go.mod он есть: `v0.30.0`.
                    let f = if eco == Ecosystem::Go && f.starts_with(|c: char| c.is_ascii_digit()) {
                        format!("v{f}")
                    } else {
                        f
                    };
                    if !f.is_empty() && f.len() <= 64 && !fixed.contains(&f) {
                        fixed.push(f);
                    }
                }
            }
        }
    }

    let cwe_506 = doc
        .get("database_specific")
        .and_then(|d| d.get("cwe_ids"))
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .any(|c| c.as_str() == Some("CWE-506"));
    let malicious = is_malicious_id(id) || cwe_506;
    // У MAL-записей нет оценки: вредоносный код — всегда critical.
    let severity = if malicious && severity < Severity::Critical {
        Severity::Critical
    } else {
        severity
    };

    Ok(Vuln {
        id: id.to_string(),
        aliases,
        summary,
        severity,
        cvss,
        fixed,
        malicious,
    })
}

/// `MAL-…` — запись базы вредоносных пакетов OpenSSF (через OSV).
pub fn is_malicious_id(id: &str) -> bool {
    id.starts_with("MAL-")
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max - 1).collect();
    t.push('…');
    t
}

// ---------------------------------------------------------------------------
// CVSS 3.1 base score — по официальной формуле (порт из seed, без изменений)
// ---------------------------------------------------------------------------

/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8. `None` — не вектор 3.x.
pub fn cvss31_base_score(vector: &str) -> Option<f64> {
    if !(vector.starts_with("CVSS:3.0/") || vector.starts_with("CVSS:3.1/")) {
        return None;
    }
    let mut m: HashMap<&str, &str> = HashMap::new();
    for part in vector.split('/') {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k, v);
        }
    }
    let scope_changed = match *m.get("S")? {
        "C" => true,
        "U" => false,
        _ => return None,
    };
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*m.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |v: &str| -> Option<f64> {
        match v {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let c = cia(m.get("C")?)?;
    let i = cia(m.get("I")?)?;
    let a = cia(m.get("A")?)?;

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup(raw))
}

/// Округление вверх до 0.1 по спецификации CVSS 3.1 (через целые, без ошибок float).
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100000.0).round() as i64;
    if int_input % 10000 == 0 {
        int_input as f64 / 100000.0
    } else {
        ((int_input / 10000) + 1) as f64 / 10.0
    }
}

// ---------------------------------------------------------------------------
// Дисковый кэш: <cache>/<экосистема>/<хэш>.json
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Каталог кэша по умолчанию: `JETSCAN_HOME` или `~/.jetscan`, внутри `osv-cache`.
pub fn default_cache_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("JETSCAN_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h).join("osv-cache"));
    }
    crate::secrets::machine::home_dir().map(|h| h.join(".jetscan").join("osv-cache"))
}

fn cache_file(dir: &Path, p: &Package) -> PathBuf {
    let key = format!("{}\n{}\n{}", p.ecosystem.osv_name(), p.name, p.version);
    let digest = hash::sha256(key.as_bytes());
    let eco_dir: String = p
        .ecosystem
        .osv_name()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    dir.join(eco_dir)
        .join(format!("{}.json", hash::hex(&digest[..16])))
}

fn vuln_to_json(v: &Vuln) -> Json {
    obj(vec![
        ("id", Json::Str(v.id.clone())),
        (
            "aliases",
            Json::Arr(v.aliases.iter().cloned().map(Json::Str).collect()),
        ),
        ("summary", Json::Str(v.summary.clone())),
        ("severity", Json::Str(v.severity.label().to_string())),
        ("cvss", v.cvss.map(Json::Num).unwrap_or(Json::Null)),
        ("malicious", Json::Bool(v.malicious)),
        (
            "fixed",
            Json::Arr(v.fixed.iter().cloned().map(Json::Str).collect()),
        ),
    ])
}

fn strs(v: Option<&Json>) -> Vec<String> {
    v.and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_string)
        .collect()
}

/// Кэш — тоже недоверенный ввод (его мог подменить кто угодно с доступом к диску):
/// при чтении те же проверки, что и для ответа OSV.
fn vuln_from_json(v: &Json) -> Option<Vuln> {
    let id = v.get("id").and_then(Json::as_str).filter(|i| valid_id(i))?;
    Some(Vuln {
        id: id.to_string(),
        aliases: strs(v.get("aliases"))
            .into_iter()
            .filter(|a| valid_id(a))
            .collect(),
        summary: ui::sanitize_line(v.get("summary").and_then(Json::as_str).unwrap_or("")),
        severity: v
            .get("severity")
            .and_then(Json::as_str)
            .and_then(Severity::from_label)
            .unwrap_or_default(),
        cvss: v.get("cvss").and_then(Json::as_f64),
        fixed: strs(v.get("fixed"))
            .iter()
            .map(|f| ui::sanitize_line(f))
            .collect(),
        malicious: v.get("malicious").and_then(Json::as_bool) == Some(true) || is_malicious_id(id),
    })
}

/// `(уязвимости, время запроса)`; `None` — нет файла, битый, или чужой пакет.
fn cache_read(dir: &Path, p: &Package) -> Option<(Vec<Vuln>, u64)> {
    let text = fs::read_to_string(cache_file(dir, p)).ok()?;
    let doc = json::parse(&text).ok()?;
    if doc.get("v").and_then(Json::as_f64) != Some(CACHE_VERSION)
        || doc.get("ecosystem").and_then(Json::as_str) != Some(p.ecosystem.osv_name())
        || doc.get("name").and_then(Json::as_str) != Some(p.name.as_str())
        || doc.get("version").and_then(Json::as_str) != Some(p.version.as_str())
    {
        return None;
    }
    let ts = doc.get("queried_at").and_then(Json::as_f64)? as u64;
    let vulns = doc
        .get("vulns")
        .and_then(Json::as_array)?
        .iter()
        .map(vuln_from_json)
        .collect::<Option<Vec<_>>>()?;
    Some((vulns, ts))
}

/// Атомарно (temp + rename). Ошибка не фатальна — станет предупреждением.
fn cache_write(dir: &Path, p: &Package, vulns: &[Vuln], now: u64) -> Result<(), String> {
    let path = cache_file(dir, p);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let doc = obj(vec![
        ("v", Json::Num(CACHE_VERSION)),
        ("ecosystem", Json::Str(p.ecosystem.osv_name().to_string())),
        ("name", Json::Str(p.name.clone())),
        ("version", Json::Str(p.version.clone())),
        ("queried_at", Json::Num(now as f64)),
        ("vulns", Json::Arr(vulns.iter().map(vuln_to_json).collect())),
    ]);
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, json::stringify(&doc)).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

// ---------------------------------------------------------------------------
// Оркестрация
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OsvOptions {
    /// `None` — без кэша вовсе (ни читать, ни писать).
    pub cache_dir: Option<PathBuf>,
    /// Не читать свежий кэш (ответ всё равно сохраняется).
    pub no_cache: bool,
    /// Без сети: только кэш, любой давности.
    pub offline: bool,
}

/// Итог проверки списка пакетов.
#[derive(Clone, Debug, Default)]
pub struct OsvResult {
    /// По индексу пакета: `Some(уязвимости)` — проверен, `None` — проверить не удалось.
    pub vulns: Vec<Option<Vec<Vuln>>>,
    pub from_cache: usize,
    pub fresh: usize,
    /// Сеть не ответила (или `offline`) и часть данных — из старого кэша.
    pub stale_cache_age: Option<u64>,
    pub osv_unavailable: bool,
    pub warnings: Vec<String>,
}

pub fn check(
    pkgs: &[Package],
    opts: &OsvOptions,
    http: &dyn Http,
    sleep: &(dyn Fn(u64) + Sync),
) -> OsvResult {
    let now = now_secs();
    let mut res = OsvResult {
        vulns: vec![None; pkgs.len()],
        ..OsvResult::default()
    };

    // 1. Свежий кэш.
    let mut to_query = Vec::new();
    for (i, p) in pkgs.iter().enumerate() {
        let cached = opts.cache_dir.as_deref().and_then(|d| cache_read(d, p));
        match cached {
            Some((v, ts)) if !opts.no_cache && now.saturating_sub(ts) <= CACHE_TTL_SECS => {
                res.vulns[i] = Some(v);
                res.from_cache += 1;
            }
            _ => to_query.push(i),
        }
    }

    // 2. Сеть (или её отсутствие) для остальных.
    let ids_per_pkg = if opts.offline {
        None
    } else {
        query_ids(pkgs, &to_query, http, sleep, &mut res.warnings)
    };
    let Some(ids_per_pkg) = ids_per_pkg else {
        res.osv_unavailable = !opts.offline;
        for &i in &to_query {
            if let Some((v, ts)) = opts
                .cache_dir
                .as_deref()
                .and_then(|d| cache_read(d, &pkgs[i]))
            {
                let age = now.saturating_sub(ts);
                res.stale_cache_age = Some(res.stale_cache_age.map_or(age, |a| a.max(age)));
                res.vulns[i] = Some(v);
                res.from_cache += 1;
            }
        }
        return res;
    };

    // 3. Детали уязвимостей — параллельно, по одному запросу на уникальный id.
    let mut unique: Vec<&str> = ids_per_pkg
        .iter()
        .flat_map(|(_, ids)| ids.iter().map(String::as_str))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unique.sort_unstable();
    let bodies = fetch_details(&unique, http, sleep);

    // Нет оценки (так у всей базы Go: GO-…) — берём из GHSA-алиаса той же дыры.
    let mut alias_ids: Vec<String> = bodies
        .values()
        .filter_map(|b| b.as_ref().ok())
        .filter_map(|b| parse_vuln(b, Ecosystem::Npm, "").ok())
        .filter(|v| v.severity == Severity::Unknown && v.cvss.is_none())
        .flat_map(|v| v.aliases.into_iter().filter(|a| a.starts_with("GHSA-")))
        .filter(|a| !bodies.contains_key(a.as_str()))
        .collect();
    alias_ids.sort();
    alias_ids.dedup();
    let alias_refs: Vec<&str> = alias_ids.iter().map(String::as_str).collect();
    let alias_bodies = fetch_details(&alias_refs, http, sleep);
    let rate_from_alias = |v: &mut Vuln, eco: Ecosystem, name: &str| {
        for a in v.aliases.iter().filter(|a| a.starts_with("GHSA-")) {
            let body = bodies
                .get(a.as_str())
                .or_else(|| alias_bodies.get(a.as_str()));
            if let Some(Ok(b)) = body
                && let Ok(g) = parse_vuln(b, eco, name)
                && (g.severity != Severity::Unknown || g.cvss.is_some())
            {
                v.severity = g.severity;
                v.cvss = g.cvss;
                return;
            }
        }
    };

    for (i, ids) in &ids_per_pkg {
        let p = &pkgs[*i];
        let mut vulns = Vec::new();
        let mut complete = true;
        for id in ids {
            let parsed = bodies
                .get(id.as_str())
                .and_then(|b| b.as_ref().ok())
                .and_then(|b| parse_vuln(b, p.ecosystem, &p.name).ok());
            match parsed {
                Some(mut v) => {
                    if v.severity == Severity::Unknown && v.cvss.is_none() {
                        rate_from_alias(&mut v, p.ecosystem, &p.name);
                    }
                    vulns.push(v);
                }
                None => {
                    // id известен — находку не теряем, просто без деталей.
                    complete = false;
                    vulns.push(Vuln {
                        id: id.clone(),
                        aliases: Vec::new(),
                        summary: "(details unavailable)".to_string(),
                        // MAL-id вредоносен и без деталей.
                        severity: if is_malicious_id(id) {
                            Severity::Critical
                        } else {
                            Severity::Unknown
                        },
                        cvss: None,
                        fixed: Vec::new(),
                        malicious: is_malicious_id(id),
                    });
                }
            }
        }
        vulns.sort_by(|a, b| a.id.cmp(&b.id));
        if complete
            && let Some(dir) = opts.cache_dir.as_deref()
            && let Err(e) = cache_write(dir, p, &vulns, now)
        {
            res.warnings.push(format!("cache not written: {e}"));
        }
        res.vulns[*i] = Some(vulns);
        res.fresh += 1;
    }
    res.warnings.sort();
    res.warnings.dedup();
    res
}

/// querybatch для пакетов `idx` (с пагинацией). `None` — OSV недоступен совсем.
/// Частичный сбой не смешиваем с «чисто»: любой непрошедший батч = `None` для всех.
fn query_ids(
    pkgs: &[Package],
    idx: &[usize],
    http: &dyn Http,
    sleep: &dyn Fn(u64),
    warnings: &mut Vec<String>,
) -> Option<Vec<(usize, Vec<String>)>> {
    let mut out: Vec<(usize, Vec<String>)> = Vec::new();
    for chunk in idx.chunks(BATCH_LIMIT) {
        let body = batch_body(chunk.iter().map(|&i| query_json(&pkgs[i], None)).collect());
        let resp = with_retry(|| http.request(OSV_BATCH, Some(&body)), sleep).ok()?;
        let parsed = match parse_batch(&resp, chunk.len()) {
            Ok(p) => p,
            Err(e) => {
                warnings.push(e);
                return None;
            }
        };
        for (&i, (mut ids, mut next)) in chunk.iter().zip(parsed) {
            let mut pages = 0;
            while let Some(token) = next.take() {
                pages += 1;
                if pages > MAX_PAGES {
                    warnings.push(format!(
                        "{}: more than {MAX_PAGES} pages of vulnerabilities, list truncated",
                        pkgs[i].name
                    ));
                    break;
                }
                let body = batch_body(vec![query_json(&pkgs[i], Some(&token))]);
                let resp = with_retry(|| http.request(OSV_BATCH, Some(&body)), sleep).ok()?;
                let mut page = parse_batch(&resp, 1).ok()?;
                let (more, n) = page.pop()?;
                ids.extend(more);
                next = n;
            }
            ids.retain(|id| valid_id(id));
            ids.sort();
            ids.dedup();
            out.push((i, ids));
        }
    }
    Some(out)
}

fn fetch_details<'a>(
    ids: &[&'a str],
    http: &dyn Http,
    sleep: &(dyn Fn(u64) + Sync),
) -> HashMap<&'a str, Result<String, String>> {
    let queue = Mutex::new(ids.iter().copied());
    let results = Mutex::new(HashMap::new());
    std::thread::scope(|s| {
        for _ in 0..DETAIL_WORKERS.min(ids.len()) {
            s.spawn(|| {
                while let Some(id) = queue.lock().ok().and_then(|mut q| q.next()) {
                    let url = format!("{OSV_VULN}/{id}");
                    let r = with_retry(|| http.request(&url, None), sleep);
                    if let Ok(mut m) = results.lock() {
                        m.insert(id, r);
                    }
                }
            });
        }
    });
    results.into_inner().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss31_known_vectors() {
        // lodash CVE-2021-23337 — 7.2 HIGH (NVD).
        let v = cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((v - 7.2).abs() < 1e-9, "got {v}");
        assert_eq!(
            cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        // Scope changed: 10.0.
        assert_eq!(
            cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            Some(10.0)
        );
        assert_eq!(
            cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            Some(0.0)
        );
        assert!(cvss31_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
        assert!(cvss31_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H").is_none());
        assert!(cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H").is_none());
    }

    #[test]
    fn retry_backoff_retry_after_and_fatal() {
        let sleeps = Mutex::new(Vec::new());
        let sleep = |s: u64| sleeps.lock().unwrap().push(s);
        let mut n = 0;
        let r = with_retry(
            || {
                n += 1;
                if n < 3 {
                    Attempt::Retry(None)
                } else {
                    Attempt::Ok("ok".into())
                }
            },
            &sleep,
        );
        assert_eq!(r.unwrap(), "ok");
        assert_eq!(*sleeps.lock().unwrap(), vec![1, 3]);

        sleeps.lock().unwrap().clear();
        assert!(with_retry(|| Attempt::Fatal("400".into()), &sleep).is_err());
        assert!(sleeps.lock().unwrap().is_empty());

        let mut n = 0;
        let _ = with_retry(
            || {
                n += 1;
                if n < 2 {
                    Attempt::Retry(Some(7))
                } else {
                    Attempt::Ok("x".into())
                }
            },
            &sleep,
        );
        assert_eq!(*sleeps.lock().unwrap(), vec![7]);

        // Сервер просит ждать час — не ждём, честно сдаёмся.
        sleeps.lock().unwrap().clear();
        assert!(with_retry(|| Attempt::Retry(Some(3600)), &sleep).is_err());
        assert!(sleeps.lock().unwrap().is_empty());
    }

    #[test]
    fn curl_output_is_split_into_body_code_and_retry_after() {
        assert_eq!(
            parse_curl_output("{\"a\":1}\n200 ".into()),
            Attempt::Ok("{\"a\":1}".into())
        );
        assert_eq!(
            parse_curl_output("x\n429 12".into()),
            Attempt::Retry(Some(12))
        );
        assert_eq!(
            parse_curl_output("x\n429 ".into()),
            Attempt::Retry(Some(RETRY_AFTER_DEFAULT))
        );
        assert!(matches!(
            parse_curl_output("x\n404 ".into()),
            Attempt::Fatal(_)
        ));
        assert_eq!(parse_curl_output("\n503 ".into()), Attempt::Retry(None));
        assert_eq!(parse_curl_output("garbage".into()), Attempt::Retry(None));
        // Тело с переводами строк — режем по последнему.
        assert_eq!(
            parse_curl_output("a\nb\n200 ".into()),
            Attempt::Ok("a\nb".into())
        );
    }

    #[test]
    fn ids_from_osv_are_checked_before_going_into_a_url() {
        assert!(valid_id("GHSA-35jh-r3h4-6jhm"));
        assert!(valid_id("PYSEC-2021-9"));
        assert!(valid_id("RUSTSEC-2021-0001"));
        assert!(valid_id("GO-2022-0001"));
        assert!(!valid_id("../../v1/x"));
        assert!(!valid_id("a?b=c"));
        assert!(!valid_id("x y"));
        assert!(!valid_id("GHSA..x"));
        assert!(!valid_id(&"A".repeat(65)));
    }

    #[test]
    fn parse_batch_aligns_and_rejects_misaligned() {
        let body = r#"{"results":[{},{"vulns":[{"id":"GHSA-aaa"},{"id":"CVE-bbb"}],"next_page_token":"t1"},{}]}"#;
        let got = parse_batch(body, 3).unwrap();
        assert!(got[0].0.is_empty() && got[0].1.is_none());
        assert_eq!(got[1].0, vec!["GHSA-aaa", "CVE-bbb"]);
        assert_eq!(got[1].1.as_deref(), Some("t1"));
        assert!(parse_batch(body, 2).is_err());
        assert!(parse_batch("{}", 1).is_err());
    }

    const LODASH: &str = r#"{
        "id":"GHSA-35jh-r3h4-6jhm",
        "summary":"Command Injection in lodash",
        "aliases":["CVE-2021-23337"],
        "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific":{"severity":"HIGH"},
        "affected":[
          {"package":{"name":"lodash","ecosystem":"npm"},
           "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]},
          {"package":{"name":"lodash-es","ecosystem":"npm"},
           "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]},
          {"package":{"name":"lodash","ecosystem":"RubyGems"},
           "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.8.8"}]}]}
        ]}"#;

    #[test]
    fn parse_vuln_takes_fix_only_for_our_package() {
        let v = parse_vuln(LODASH, Ecosystem::Npm, "lodash").unwrap();
        assert_eq!(v.id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(v.aliases, vec!["CVE-2021-23337"]);
        assert_eq!(v.summary, "Command Injection in lodash");
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.cvss, Some(7.2));
        assert_eq!(v.fixed, vec!["4.17.21"]);
    }

    #[test]
    fn parse_vuln_text_severity_pypi_names_and_hostile_text() {
        let body = "{\"id\":\"PYSEC-1\",\"details\":\"\\n evil\\u001b[31mRED\\nsecond line\",\
            \"database_specific\":{\"severity\":\"MODERATE\"},\
            \"affected\":[{\"package\":{\"name\":\"Django\",\"ecosystem\":\"PyPI\"},\
            \"ranges\":[{\"events\":[{\"fixed\":\"3.2.1\"}]}]}]}";
        let v = parse_vuln(body, Ecosystem::PyPI, "django").unwrap();
        assert_eq!(v.severity, Severity::Medium);
        assert!(v.cvss.is_none());
        assert!(!v.summary.contains('\u{1b}') && v.summary.contains("RED"));
        assert!(!v.summary.contains("second"));
        assert_eq!(v.fixed, vec!["3.2.1"]);
        assert!(parse_vuln(r#"{"id":"../x"}"#, Ecosystem::Npm, "a").is_err());
    }

    /// Поддельный OSV: querybatch → lodash уязвим, остальные чисты; детали по id.
    struct FakeOsv {
        calls: Mutex<Vec<String>>,
        batch_fails: bool,
    }

    impl Http for FakeOsv {
        fn request(&self, url: &str, body: Option<&str>) -> Attempt {
            self.calls.lock().unwrap().push(url.to_string());
            if url == OSV_BATCH {
                if self.batch_fails {
                    return Attempt::Retry(None);
                }
                let doc = json::parse(body.unwrap()).unwrap();
                let results: Vec<String> = doc
                    .get("queries")
                    .and_then(Json::as_array)
                    .unwrap()
                    .iter()
                    .map(|q| {
                        let name = q.get("package").and_then(|p| p.get("name")).and_then(Json::as_str);
                        if name == Some("lodash") {
                            r#"{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm"},{"id":"GHSA-gone-0000-0000"}]}"#.to_string()
                        } else {
                            "{}".to_string()
                        }
                    })
                    .collect();
                return Attempt::Ok(format!("{{\"results\":[{}]}}", results.join(",")));
            }
            if url.ends_with("/GHSA-35jh-r3h4-6jhm") {
                return Attempt::Ok(LODASH.to_string());
            }
            Attempt::Fatal("HTTP 404".into())
        }
    }

    fn pkg(name: &str, version: &str) -> Package {
        Package {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            lockfiles: vec!["package-lock.json".into()],
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jetscan-osv-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn check_queries_caches_and_falls_back_offline() {
        let dir = tmp("check");
        let pkgs = vec![pkg("lodash", "4.17.20"), pkg("ms", "2.1.3")];
        let opts = OsvOptions {
            cache_dir: Some(dir.clone()),
            no_cache: false,
            offline: false,
        };
        let osv = FakeOsv {
            calls: Mutex::new(Vec::new()),
            batch_fails: false,
        };
        let r = check(&pkgs, &opts, &osv, &|_| {});
        assert_eq!((r.fresh, r.from_cache), (2, 0));
        let lodash = r.vulns[0].as_ref().unwrap();
        assert_eq!(lodash.len(), 2);
        assert_eq!(lodash[0].id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(lodash[1].summary, "(details unavailable)");
        assert_eq!(r.vulns[1].as_deref(), Some(&[][..]));

        // lodash с неполными деталями не закэширован, ms (чистый) — закэширован.
        let osv2 = FakeOsv {
            calls: Mutex::new(Vec::new()),
            batch_fails: true,
        };
        let r2 = check(&pkgs, &opts, &osv2, &|_| {});
        assert_eq!(r2.from_cache, 1);
        assert!(r2.vulns[0].is_none(), "unchecked, not clean");
        assert_eq!(r2.vulns[1].as_deref(), Some(&[][..]));
        assert!(r2.osv_unavailable);

        // offline — сеть не трогаем вовсе.
        let osv3 = FakeOsv {
            calls: Mutex::new(Vec::new()),
            batch_fails: false,
        };
        let off = OsvOptions {
            offline: true,
            ..opts.clone()
        };
        let r3 = check(&pkgs, &off, &osv3, &|_| {});
        assert!(osv3.calls.lock().unwrap().is_empty());
        assert!(r3.vulns[0].is_none() && r3.vulns[1].is_some());
        assert!(!r3.osv_unavailable);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malicious_packages_are_flagged_from_facts_not_text() {
        // OpenSSF malicious packages: id MAL-…, без оценки → critical.
        let mal = parse_vuln(
            r#"{"id":"MAL-2025-20690","summary":"Malicious code in flatmap-stream (npm)"}"#,
            Ecosystem::Npm,
            "flatmap-stream",
        )
        .unwrap();
        assert!(mal.malicious);
        assert_eq!(mal.severity, Severity::Critical);
        // GHSA с CWE-506 (Embedded Malicious Code).
        let ghsa = parse_vuln(
            r#"{"id":"GHSA-9x64-5r7x-2q53","summary":"x","database_specific":{"cwe_ids":["CWE-506"],"severity":"HIGH"}}"#,
            Ecosystem::Npm,
            "flatmap-stream",
        )
        .unwrap();
        assert!(ghsa.malicious);
        assert_eq!(ghsa.severity, Severity::Critical);
        // Слово «malicious» в описании — не факт; обычная дыра остаётся дырой.
        let text = parse_vuln(
            r#"{"id":"GHSA-aaaa-bbbb-cccc","summary":"Malicious input causes ReDoS","database_specific":{"severity":"MODERATE"}}"#,
            Ecosystem::Npm,
            "x",
        )
        .unwrap();
        assert!(!text.malicious);
        assert_eq!(text.severity, Severity::Medium);
        // Флаг переживает кэш.
        let back = vuln_from_json(&vuln_to_json(&ghsa)).unwrap();
        assert!(back.malicious);
    }

    /// База Go: у GO-… нет оценки, она у GHSA-алиаса; версии исправлений без `v`.
    struct FakeGo;

    impl Http for FakeGo {
        fn request(&self, url: &str, _body: Option<&str>) -> Attempt {
            if url == OSV_BATCH {
                return Attempt::Ok(r#"{"results":[{"vulns":[{"id":"GO-2026-6094"}]}]}"#.into());
            }
            if url.ends_with("/GO-2026-6094") {
                return Attempt::Ok(
                    r#"{"id":"GO-2026-6094","summary":"cel-go issue","aliases":["GHSA-gcjh-h69q-9w9g"],
                    "affected":[{"package":{"name":"github.com/google/cel-go","ecosystem":"Go"},
                    "ranges":[{"type":"SEMVER","events":[{"introduced":"0.22.0"},{"fixed":"0.30.0"}]}]}]}"#
                        .into(),
                );
            }
            if url.ends_with("/GHSA-gcjh-h69q-9w9g") {
                return Attempt::Ok(
                    r#"{"id":"GHSA-gcjh-h69q-9w9g","summary":"x",
                    "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}"#
                        .into(),
                );
            }
            Attempt::Fatal("HTTP 404".into())
        }
    }

    #[test]
    fn go_vulns_get_severity_from_ghsa_alias_and_v_prefixed_fix() {
        let p = Package {
            ecosystem: Ecosystem::Go,
            name: "github.com/google/cel-go".into(),
            version: "v0.29.2".into(),
            lockfiles: vec!["go.mod".into()],
        };
        let opts = OsvOptions {
            cache_dir: None,
            no_cache: false,
            offline: false,
        };
        let r = check(&[p], &opts, &FakeGo, &|_| {});
        let v = &r.vulns[0].as_ref().unwrap()[0];
        assert_eq!(v.id, "GO-2026-6094");
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.cvss, Some(9.8));
        assert_eq!(v.fixed, vec!["v0.30.0"]);
    }

    #[test]
    fn cache_rejects_foreign_and_tampered_entries() {
        let dir = tmp("cache");
        let p = pkg("a/b", "1.0.0");
        let v = parse_vuln(LODASH, Ecosystem::Npm, "lodash").unwrap();
        cache_write(&dir, &p, std::slice::from_ref(&v), 1000).unwrap();
        assert_eq!(cache_read(&dir, &p).unwrap().0, vec![v]);
        // Похожие имена — разные файлы.
        assert!(cache_read(&dir, &pkg("a_b", "1.0.0")).is_none());
        // Подмена: файл одного пакета положили под имя другого.
        let other = pkg("x", "1.0.0");
        fs::create_dir_all(cache_file(&dir, &other).parent().unwrap()).unwrap();
        fs::copy(cache_file(&dir, &p), cache_file(&dir, &other)).unwrap();
        assert!(cache_read(&dir, &other).is_none());
        // Битый id в кэше — весь файл не принимаем.
        fs::write(
            cache_file(&dir, &p),
            r#"{"v":1,"ecosystem":"npm","name":"a/b","version":"1.0.0","queried_at":1,"vulns":[{"id":"../../x"}]}"#,
        )
        .unwrap();
        assert!(cache_read(&dir, &p).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
