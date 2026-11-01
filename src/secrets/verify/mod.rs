//! Проверка, рабочий ли найденный ключ.
//!
//! Только по явному `--verify`. Каждый ключ уходит ТОЛЬКО своему провайдеру (GitHub-токен —
//! на api.github.com) одним безвредным запросом «кто я» — ничего не меняет у провайдера.
//!
//! Безопасность (не ослаблять):
//! - Ключ не попадает в командную строку curl (её видит любой процесс через список
//!   процессов): весь запрос передаётся конфигом через stdin (`curl -K -`).
//! - Только https, без редиректов (`--max-redirs 0`): ключ не уйдёт на чужой хост.
//! - Хост запроса обязан быть в `Provider::hosts` — проверяем ДО отправки.
//! - Ответ провайдера в отчёт не попадает: только итог `Liveness`.
//! - Сырые секреты живут только в памяти скана и только при `--verify`.

pub mod providers;

use super::Liveness;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// HTTP-запрос к провайдеру. Строит адаптер, отправляет движок.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `GET` или `POST`.
    pub method: &'static str,
    /// Полный https-URL; хост — из `Provider::hosts`.
    pub url: String,
    /// Заголовки, включая авторизацию с ключом.
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// Ответ провайдера: код и тело (тело только для классификации, наружу не уходит).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

/// Адаптер одного провайдера. Чистые функции — тестируются без сети.
pub struct Provider {
    /// Правила (`RuleInfo::id`), чьи находки этот адаптер проверяет.
    pub rule_ids: &'static [&'static str],
    /// Разрешённые хосты (точное совпадение). Запрос на другой хост не отправится.
    pub hosts: &'static [&'static str],
    /// Запрос «кто я» для ключа. `None` — этот ключ так не проверить (формат, нужна пара...).
    pub build: fn(secret: &str) -> Option<Request>,
    /// Итог по ответу. 200 → Live, 401/403 → Revoked, 429/5xx → Unknown и т.п.
    pub classify: fn(resp: &Response) -> Liveness,
}

/// Транспорт. В тестах — фейк, как `jest.mock(fetch)`.
pub trait Transport: Sync {
    fn send(&self, req: &Request) -> Result<Response, String>;
}

/// Хост https-URL или `None`, если URL не https / странный.
pub fn https_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    // Без userinfo (`user@host`) и порта: проверяем ровно то, куда пойдёт запрос.
    if host.is_empty() || host.contains(['@', ':', '\\']) {
        return None;
    }
    Some(host)
}

/// Значение для конфига curl в кавычках: экранируем `\` и `"`, переводы строк запрещены.
fn curl_quote(s: &str) -> Option<String> {
    if s.contains(['\n', '\r', '\0']) {
        return None;
    }
    Some(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// Конфиг curl для запроса (всё, что содержит ключ, — только тут, не в argv).
pub fn curl_config(req: &Request) -> Option<String> {
    let mut cfg = String::new();
    cfg.push_str(&format!("url = {}\n", curl_quote(&req.url)?));
    cfg.push_str(&format!("request = {}\n", curl_quote(req.method)?));
    for (k, v) in &req.headers {
        if k.contains([':', '\n', '\r']) {
            return None;
        }
        cfg.push_str(&format!("header = {}\n", curl_quote(&format!("{k}: {v}"))?));
    }
    if let Some(b) = &req.body {
        cfg.push_str(&format!("data-binary = {}\n", curl_quote(b)?));
    }
    Some(cfg)
}

/// Системный curl; запрос — конфигом через stdin.
pub struct Curl;

impl Transport for Curl {
    fn send(&self, req: &Request) -> Result<Response, String> {
        let cfg = curl_config(req).ok_or("request has characters curl config cannot carry")?;
        let mut child = Command::new("curl")
            .arg("-q") // первым: не читать ~/.curlrc
            // --globoff: curl раскрывает {} и [] в URL даже из конфига — ключ в пути
            // (Telegram) не должен превратиться в несколько запросов.
            .args(["-sS", "--globoff", "--proto", "=https", "--max-redirs", "0"])
            .args(["--connect-timeout", "10", "--max-time", "20"])
            .args(["-A", concat!("jetscan/", env!("CARGO_PKG_VERSION"))])
            .args(["-o", "-", "-w", "\n%{http_code}", "-K", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot run curl".to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(cfg.as_bytes())
                .map_err(|e| format!("cannot pass request to curl: {e}"))?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err("network error".to_string());
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (body, code) = text.rsplit_once('\n').unwrap_or(("", text.as_str()));
        let status = code
            .trim()
            .parse()
            .map_err(|_| "no HTTP status".to_string())?;
        Ok(Response {
            status,
            body: body.to_string(),
        })
    }
}

/// Адаптер для правила.
pub fn provider_for(rule_id: &str) -> Option<&'static Provider> {
    providers::PROVIDERS
        .iter()
        .find(|p| p.rule_ids.contains(&rule_id))
}

/// Проверяет ключи: `fingerprint → (rule_id, секрет)`. Каждый отпечаток — один запрос.
/// Не поддержанные правила в результат не попадают (в отчёте — «не проверялся»).
pub fn check(
    secrets: &BTreeMap<String, (&'static str, String)>,
    transport: &dyn Transport,
) -> HashMap<String, Liveness> {
    let jobs: Vec<(&String, &'static Provider, Request)> = secrets
        .iter()
        .filter_map(|(fp, (rule, secret))| {
            let p = provider_for(rule)?;
            let req = (p.build)(secret)?;
            Some((fp, p, req))
        })
        .collect();
    let out = Mutex::new(HashMap::new());
    let queue = Mutex::new(jobs.into_iter());
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                while let Some((fp, p, req)) = queue.lock().ok().and_then(|mut q| q.next()) {
                    let result = match https_host(&req.url) {
                        Some(h) if p.hosts.contains(&h) => match transport.send(&req) {
                            Ok(resp) => (p.classify)(&resp),
                            Err(e) => Liveness::Unknown(e),
                        },
                        // Адаптер построил запрос не туда — ключ не отправляем.
                        _ => Liveness::Unknown("refused: host not allowed".to_string()),
                    };
                    if let Ok(mut m) = out.lock() {
                        m.insert(fp.clone(), result);
                    }
                }
            });
        }
    });
    out.into_inner().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_check_rejects_tricks() {
        assert_eq!(
            https_host("https://api.github.com/user"),
            Some("api.github.com")
        );
        assert_eq!(https_host("http://api.github.com/user"), None);
        assert_eq!(https_host("https://evil.com@api.github.com/"), None);
        assert_eq!(https_host("https://api.github.com:8443/"), None);
        assert_eq!(https_host("https://api.github.com\\@evil.com/"), None);
        assert_eq!(https_host("https:///x"), None);
    }

    #[test]
    fn curl_config_escapes_and_refuses_newlines() {
        let req = Request {
            method: "GET",
            url: "https://api.github.com/user".into(),
            headers: vec![("Authorization".into(), "Bearer a\"b\\c".into())],
            body: None,
        };
        let cfg = curl_config(&req).unwrap();
        assert!(cfg.contains("header = \"Authorization: Bearer a\\\"b\\\\c\"\n"));
        let mut bad = req.clone();
        bad.headers[0].1 = "x\nurl = \"https://evil.com\"".into();
        assert!(
            curl_config(&bad).is_none(),
            "newline would inject a curl option"
        );
    }

    /// Адаптер, который «ошибся» хостом: ключ не должен уйти.
    struct Recorder(Mutex<Vec<String>>);
    impl Transport for Recorder {
        fn send(&self, req: &Request) -> Result<Response, String> {
            self.0.lock().unwrap().push(req.url.clone());
            Ok(Response {
                status: 200,
                body: String::new(),
            })
        }
    }

    #[test]
    fn unsupported_rules_are_skipped_and_nothing_leaves_for_them() {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "fp1".to_string(),
            ("no-such-rule", "s3cr3t-value".to_string()),
        );
        let t = Recorder(Mutex::new(Vec::new()));
        let r = check(&secrets, &t);
        assert!(r.is_empty());
        assert!(t.0.lock().unwrap().is_empty());
    }
}
