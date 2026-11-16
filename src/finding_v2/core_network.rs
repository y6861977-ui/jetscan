//! Request accounting at the existing transport boundary. Never retain URLs,
//! headers, bodies, responses, errors, package names or credential fingerprints.
use crate::{deps::osv, secrets::verify};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Clone, Debug, Default)]
pub struct NetworkSummary {
    pub(super) activities: Vec<String>,
    pub(super) failed_attempts: usize,
    pub(super) unavailable: bool,
}
/// (purpose, host, method) → (attempts, failed attempts).
type RequestCounts = BTreeMap<(&'static str, &'static str, &'static str), (usize, usize)>;

#[derive(Default)]
pub struct NetworkLog {
    counts: Mutex<RequestCounts>,
}
impl NetworkLog {
    fn record(
        &self,
        purpose: &'static str,
        host: &'static str,
        method: &'static str,
        failed: bool,
    ) {
        if let Ok(mut counts) = self.counts.lock() {
            let count = counts.entry((purpose, host, method)).or_default();
            count.0 = count.0.saturating_add(1);
            count.1 = count.1.saturating_add(usize::from(failed));
        }
    }
    /// Read only after scanner workers have joined. A successful transport return
    /// is not evidence of a complete detector check or credential revocation.
    pub fn snapshot(&self) -> NetworkSummary {
        let Ok(counts) = self.counts.lock() else {
            return NetworkSummary {
                unavailable: true,
                ..NetworkSummary::default()
            };
        };
        NetworkSummary {
            activities: counts.iter().map(|((purpose,host,method),(attempts,failed))|
                format!("{purpose}: {method} {host}; transport_attempts={attempts}; failed_or_retryable={failed}")) .collect(),
            failed_attempts: counts.values().fold(0usize, |n, (_,failed)| n.saturating_add(*failed)),
            unavailable: false,
        }
    }
}
pub struct ObservedHttp<'a> {
    pub inner: &'a dyn osv::Http,
    pub log: &'a NetworkLog,
}
impl osv::Http for ObservedHttp<'_> {
    fn request(&self, url: &str, body: Option<&str>) -> osv::Attempt {
        let (purpose, host) = if url == "https://api.osv.dev/v1/querybatch" {
            ("dependency query", "api.osv.dev")
        } else if url.starts_with("https://api.osv.dev/v1/vulns/") {
            ("dependency advisory details", "api.osv.dev")
        } else {
            ("dependency request", "unrecognized destination omitted")
        };
        let result = self.inner.request(url, body);
        self.log.record(
            purpose,
            host,
            if body.is_some() { "POST" } else { "GET" },
            !matches!(result, osv::Attempt::Ok(_)),
        );
        result
    }
}
pub struct ObservedVerification<'a> {
    pub inner: &'a dyn verify::Transport,
    pub log: &'a NetworkLog,
}
impl verify::Transport for ObservedVerification<'_> {
    fn send(&self, request: &verify::Request) -> Result<verify::Response, String> {
        let host = verify::https_host(&request.url)
            .and_then(|host| {
                verify::providers::PROVIDERS
                    .iter()
                    .flat_map(|p| p.hosts.iter())
                    .copied()
                    .find(|known| *known == host)
            })
            .unwrap_or("unrecognized destination omitted");
        let result = self.inner.send(request);
        let failed = result
            .as_ref()
            .map_or(true, |r| r.status == 429 || r.status >= 500);
        self.log.record(
            "credential verification",
            host,
            match request.method {
                "GET" => "GET",
                "POST" => "POST",
                _ => "OTHER",
            },
            failed,
        );
        result
    }
}
