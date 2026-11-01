//! CycloneDX 1.6 JSON. Идентичность — из содержимого без serialNumber;
//! абсолютные пути, состояние кэша и текущее время не экспортируются.

use super::purl::purl;
use crate::deps::scan::DepsReport;
use crate::deps::{Ecosystem, Package, VulnFinding};
use crate::hash;
use crate::json::{self, Json};

pub fn render(r: &DepsReport) -> Result<String, String> {
    render_with_timestamp(r, source_date_epoch()?)
}

fn render_with_timestamp(r: &DepsReport, timestamp: Option<String>) -> Result<String, String> {
    let mut metadata = vec![(
        "tools",
        obj(vec![(
            "components",
            Json::Arr(vec![obj(vec![
                ("type", Json::Str("application".into())),
                ("name", Json::Str("jetscan".into())),
                ("version", Json::Str(env!("CARGO_PKG_VERSION").into())),
            ])]),
        )]),
    )];
    if let Some(timestamp) = timestamp {
        metadata.push(("timestamp", Json::Str(timestamp)));
    }
    let vulnerabilities = r
        .findings
        .iter()
        .map(vulnerability)
        .collect::<Result<_, _>>()?;
    let mut document = obj(vec![
        ("bomFormat", Json::Str("CycloneDX".into())),
        ("specVersion", Json::Str("1.6".into())),
        ("version", Json::Num(1.0)),
        ("metadata", obj(metadata)),
        (
            "components",
            Json::Arr(r.packages.iter().map(component).collect()),
        ),
        ("vulnerabilities", Json::Arr(vulnerabilities)),
    ]);
    // Hash the pretty JSON before inserting the identifier: no circular input.
    let serial = serial_number(json::stringify_pretty(&document).as_bytes());
    if let Json::Obj(fields) = &mut document {
        fields.insert("serialNumber".into(), Json::Str(serial));
    }
    Ok(json::stringify_pretty(&document))
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn component(p: &Package) -> Json {
    let (group, name) = match p.ecosystem {
        Ecosystem::Npm if p.name.starts_with('@') => match p.name.split_once('/') {
            Some((scope, name)) => (Some(scope), name),
            None => (None, p.name.as_str()),
        },
        _ => (None, p.name.as_str()),
    };
    let url = purl(p);
    let mut fields = vec![
        ("type", Json::Str("library".into())),
        ("bom-ref", Json::Str(url.clone())),
        ("name", Json::Str(name.into())),
        ("version", Json::Str(p.version.clone())),
        ("purl", Json::Str(url)),
    ];
    if let Some(group) = group {
        fields.push(("group", Json::Str(group.into())));
    }
    obj(fields)
}

fn vulnerability(f: &VulnFinding) -> Result<Json, String> {
    let v = &f.vuln;
    let mut rating = vec![("severity", Json::Str(v.severity.label().into()))];
    // Ревью Claude: `method: CVSSv31` — только вместе с баллом. Уровень из текста GHSA
    // (без вектора) — не CVSS, и утверждать обратное в документе для аудитора нельзя.
    if let Some(score) = v.cvss {
        if !score.is_finite() || !(0.0..=10.0).contains(&score) {
            return Err("CycloneDX: CVSS score must be finite and between 0 and 10".into());
        }
        rating.push(("score", Json::Num(score)));
        rating.push(("method", Json::Str("CVSSv31".into())));
    }
    let mut fields = vec![
        ("id", Json::Str(v.id.clone())),
        (
            "source",
            source("OSV", format!("https://osv.dev/vulnerability/{}", v.id)),
        ),
        ("ratings", Json::Arr(vec![obj(rating)])),
        ("description", Json::Str(v.summary.clone())),
        (
            "affects",
            Json::Arr(vec![obj(vec![("ref", Json::Str(purl(&f.package)))])]),
        ),
    ];
    if v.malicious {
        fields.push((
            "recommendation",
            Json::Str("Malicious package: remove it".into()),
        ));
    } else if let Some(fix) = &f.fix {
        fields.push(("recommendation", Json::Str(format!("Upgrade to {fix}"))));
    }
    let references: Vec<_> = v
        .aliases
        .iter()
        .filter(|id| id.starts_with("CVE-"))
        .map(|id| {
            obj(vec![
                ("id", Json::Str(id.clone())),
                (
                    "source",
                    source("NVD", format!("https://nvd.nist.gov/vuln/detail/{id}")),
                ),
            ])
        })
        .collect();
    if !references.is_empty() {
        fields.push(("references", Json::Arr(references)));
    }
    Ok(obj(fields))
}

fn source(name: &str, url: String) -> Json {
    obj(vec![
        ("name", Json::Str(name.into())),
        ("url", Json::Str(url)),
    ])
}

/// First 128 SHA-256 bits, with version nibble 5 and RFC 4122 variant bits 10.
/// This is a deterministic v5-shaped identifier, NOT RFC UUIDv5 (SHA-1 with a
/// namespace). The requested SHA-256 construction deliberately uses no UUID crate.
fn serial_number(content: &[u8]) -> String {
    let mut digest = hash::sha256(content);
    digest[6] = (digest[6] & 0x0f) | 0x50;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    let hex = hash::hex(&digest[..16]);
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Shared with SPDX, kept here to leave the SBOM module contract unchanged.
pub(super) fn source_date_epoch() -> Result<Option<String>, String> {
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => epoch_timestamp(&value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("SOURCE_DATE_EPOCH must contain non-negative integer seconds".into())
        }
    }
}

fn epoch_timestamp(value: &str) -> Result<String, String> {
    const ERROR: &str =
        "SOURCE_DATE_EPOCH must be integer seconds in 0..=253402300799 (years 1970..=9999)";
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ERROR.into());
    }
    let seconds: u64 = value.parse().map_err(|_| ERROR.to_string())?;
    if seconds > 253_402_300_799 {
        return Err(ERROR.into());
    }
    // Gregorian calendar: move Jan/Feb to the end of the previous year, split
    // into 400-year eras, then recover year/month/day. Epoch offset is 1970-01-01.
    let days = seconds / 86_400 + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    if month <= 2 {
        year += 1;
    }
    let time = seconds % 86_400;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time / 60 % 60,
        time % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{Severity, Vuln};

    fn report() -> DepsReport {
        let package = Package {
            ecosystem: Ecosystem::Npm,
            name: "@scope/name".into(),
            version: "1.0.0".into(),
            lockfiles: vec!["/private/do-not-export/package-lock.json".into()],
        };
        DepsReport {
            root: "/private/do-not-export/project".into(),
            lockfiles: vec![],
            packages: vec![package.clone()],
            findings: vec![VulnFinding {
                package,
                vuln: Vuln {
                    id: "GHSA-test-test-test".into(),
                    aliases: vec!["CVE-2026-12345".into(), "OTHER-123".into()],
                    summary: "A \"quoted\" summary\nwith a newline".into(),
                    severity: Severity::High,
                    cvss: Some(7.5),
                    fixed: vec!["1.0.1".into()],
                    malicious: false,
                },
                fix: Some("1.0.1".into()),
            }],
            unchecked: vec![],
            from_cache: 0,
            fresh: 1,
            stale_cache_age: None,
            osv_unavailable: false,
            offline: false,
            warnings: vec!["/private/do-not-export/warning".into()],
            install_scripts: vec![],
            typosquats: vec![],
        }
    }

    fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
        value.get(key).unwrap().as_array().unwrap()
    }

    #[test]
    fn document_components_vulnerabilities_and_determinism() {
        let mut r = report();
        let second = Package {
            ecosystem: Ecosystem::PyPI,
            name: "Zope.Interface".into(),
            version: "6.0".into(),
            lockfiles: vec![],
        };
        r.packages.push(second);
        let output = render_with_timestamp(&r, None).unwrap();
        assert_eq!(output, render_with_timestamp(&r, None).unwrap());
        assert!(!output.contains("do-not-export"));
        let doc = json::parse(&output).unwrap();
        assert_eq!(
            doc.get("bomFormat").and_then(Json::as_str),
            Some("CycloneDX")
        );
        assert_eq!(doc.get("specVersion").and_then(Json::as_str), Some("1.6"));
        assert_eq!(doc.get("version").and_then(Json::as_f64), Some(1.0));
        let metadata = doc.get("metadata").unwrap();
        assert!(metadata.get("timestamp").is_none());
        let tool = &array(metadata.get("tools").unwrap(), "components")[0];
        assert_eq!(tool.get("name").and_then(Json::as_str), Some("jetscan"));
        assert_eq!(
            tool.get("version").and_then(Json::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        let components = array(&doc, "components");
        assert_eq!(components.len(), 2);
        let first = &components[0];
        assert_eq!(first.get("type").and_then(Json::as_str), Some("library"));
        assert_eq!(first.get("group").and_then(Json::as_str), Some("@scope"));
        assert_eq!(first.get("name").and_then(Json::as_str), Some("name"));
        assert_eq!(first.get("version").and_then(Json::as_str), Some("1.0.0"));
        assert_eq!(
            first.get("purl").and_then(Json::as_str),
            Some("pkg:npm/%40scope/name@1.0.0")
        );
        assert_eq!(first.get("bom-ref"), first.get("purl"));
        assert_eq!(
            components[1].get("purl").and_then(Json::as_str),
            Some("pkg:pypi/zope-interface@6.0")
        );
        assert!(components[1].get("group").is_none());
        let vuln = &array(&doc, "vulnerabilities")[0];
        assert_eq!(
            vuln.get("id").and_then(Json::as_str),
            Some("GHSA-test-test-test")
        );
        assert_eq!(
            vuln.get("description").and_then(Json::as_str),
            Some(r.findings[0].vuln.summary.as_str())
        );
        let osv = vuln.get("source").unwrap();
        assert_eq!(osv.get("name").and_then(Json::as_str), Some("OSV"));
        assert_eq!(
            osv.get("url").and_then(Json::as_str),
            Some("https://osv.dev/vulnerability/GHSA-test-test-test")
        );
        assert_eq!(array(vuln, "affects")[0].get("ref"), first.get("purl"));
        let rating = &array(vuln, "ratings")[0];
        assert_eq!(rating.get("severity").and_then(Json::as_str), Some("high"));
        assert_eq!(rating.get("score").and_then(Json::as_f64), Some(7.5));
        assert_eq!(rating.get("method").and_then(Json::as_str), Some("CVSSv31"));
        assert_eq!(
            vuln.get("recommendation").and_then(Json::as_str),
            Some("Upgrade to 1.0.1")
        );
        let references = array(vuln, "references");
        assert_eq!(references.len(), 1);
        assert_eq!(
            references[0].get("id").and_then(Json::as_str),
            Some("CVE-2026-12345")
        );
        assert_eq!(
            references[0]
                .get("source")
                .unwrap()
                .get("url")
                .and_then(Json::as_str),
            Some("https://nvd.nist.gov/vuln/detail/CVE-2026-12345")
        );
    }

    #[test]
    fn malicious_overrides_upgrade_and_optional_fields_are_omitted() {
        let mut r = report();
        r.findings[0].vuln.malicious = true;
        r.findings[0].vuln.cvss = None;
        r.findings[0].vuln.severity = Severity::Unknown;
        r.findings[0].vuln.aliases.clear();
        let doc = json::parse(&render_with_timestamp(&r, None).unwrap()).unwrap();
        let vuln = &array(&doc, "vulnerabilities")[0];
        assert_eq!(
            vuln.get("recommendation").and_then(Json::as_str),
            Some("Malicious package: remove it")
        );
        assert!(vuln.get("references").is_none());
        let rating = &array(vuln, "ratings")[0];
        assert!(rating.get("score").is_none());
        assert_eq!(
            rating.get("severity").and_then(Json::as_str),
            Some("unknown")
        );
        r.findings[0].vuln.malicious = false;
        r.findings[0].fix = None;
        assert!(
            vulnerability(&r.findings[0])
                .unwrap()
                .get("recommendation")
                .is_none()
        );
        for score in [f64::NAN, f64::INFINITY, -1.0, 10.1] {
            r.findings[0].vuln.cvss = Some(score);
            assert!(render_with_timestamp(&r, None).is_err());
        }
    }

    #[test]
    fn serial_hashes_content_not_paths_and_empty_report_is_valid() {
        let mut r = report();
        let output = render_with_timestamp(&r, None).unwrap();
        r.root = "/another/location/project".into();
        r.packages[0].lockfiles.clear();
        assert_eq!(output, render_with_timestamp(&r, None).unwrap());
        let mut doc = json::parse(&output).unwrap();
        let serial = if let Json::Obj(fields) = &mut doc {
            fields.remove("serialNumber").unwrap()
        } else {
            panic!("document must be an object");
        };
        let serial = serial.as_str().unwrap();
        assert_eq!(
            serial,
            serial_number(json::stringify_pretty(&doc).as_bytes())
        );
        assert_eq!(serial.len(), 45);
        let uuid = serial.strip_prefix("urn:uuid:").unwrap();
        assert_eq!(uuid.as_bytes()[14], b'5');
        assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_eq!(
            uuid.split('-').map(str::len).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        r.findings[0].vuln.summary.push('!');
        let changed = json::parse(&render_with_timestamp(&r, None).unwrap()).unwrap();
        assert_ne!(
            changed.get("serialNumber").and_then(Json::as_str),
            Some(serial)
        );
        r.findings.clear();
        r.packages.clear();
        let empty = json::parse(&render_with_timestamp(&r, None).unwrap()).unwrap();
        assert!(array(&empty, "components").is_empty());
        assert!(array(&empty, "vulnerabilities").is_empty());
    }

    #[test]
    fn epoch_conversion_validates_and_handles_calendar_boundaries() {
        for (epoch, expected) in [
            ("0", "1970-01-01T00:00:00Z"),
            ("86399", "1970-01-01T23:59:59Z"),
            ("86400", "1970-01-02T00:00:00Z"),
            ("951782400", "2000-02-29T00:00:00Z"),
            ("1709210096", "2024-02-29T12:34:56Z"),
            ("4107542400", "2100-03-01T00:00:00Z"),
            ("253402300799", "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(epoch_timestamp(epoch).unwrap(), expected);
        }
        for invalid in [
            "",
            "-1",
            "+1",
            " 0",
            "1.5",
            "no",
            "253402300800",
            "18446744073709551616",
        ] {
            assert!(epoch_timestamp(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn source_date_epoch_in_isolated_processes() {
        // Never mutate this test process's environment: Rust tests run in parallel.
        const CASE: &str = "JETSCAN_SBOM_EPOCH_TEST_CASE";
        if let Ok(case) = std::env::var(CASE) {
            let r = report();
            let cdx = render(&r);
            let spdx = super::super::spdx::render(&r);
            if case == "invalid" {
                assert!(cdx.is_err());
                assert!(spdx.is_err());
                return;
            }
            let cdx = cdx.unwrap();
            let spdx = spdx.unwrap();
            assert_eq!(cdx, render(&r).unwrap());
            assert_eq!(spdx, super::super::spdx::render(&r).unwrap());
            let cdx = json::parse(&cdx).unwrap();
            let spdx = json::parse(&spdx).unwrap();
            let timestamp = cdx
                .get("metadata")
                .unwrap()
                .get("timestamp")
                .and_then(Json::as_str);
            let created = spdx
                .get("creationInfo")
                .unwrap()
                .get("created")
                .and_then(Json::as_str);
            if case == "absent" {
                assert_eq!(timestamp, None);
                assert_eq!(created, Some("1970-01-01T00:00:00Z"));
            } else {
                assert_eq!(timestamp, Some("2024-02-29T12:34:56Z"));
                assert_eq!(created, timestamp);
            }
            return;
        }
        for (case, value) in [
            ("absent", None),
            ("set", Some("1709210096")),
            ("invalid", Some("invalid")),
        ] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "sbom::cyclonedx::tests::source_date_epoch_in_isolated_processes",
                "--nocapture",
            ]);
            command.env(CASE, case).env_remove("SOURCE_DATE_EPOCH");
            if let Some(value) = value {
                command.env("SOURCE_DATE_EPOCH", value);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "case {case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
