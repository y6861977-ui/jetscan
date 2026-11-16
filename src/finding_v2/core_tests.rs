//! Synthetic full-report regression tests; no real network or credential material.
use super::{core_capture::scan_project_observed, core_network::*, core_reports::*, *};
use crate::{
    baseline::{Baseline, Hidden},
    combined::{self, ProjectReport},
    deps::{
        self, osv,
        scan::{DepsReport, LockfileReport},
        scripts::InstallScript,
        typosquat::Suspect,
    },
    secrets::{
        self,
        history::{HistoryError, HistoryStats},
        scan::{HistoryOutcome, ScanOptions, ScanReport},
        verify,
        walk::WalkStats,
    },
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

fn secret() -> secrets::Finding {
    let raw = ["fixture", "credential"].join("-");
    secrets::Finding {
        rule: secrets::RuleInfo {
            id: "fixture-secret",
            name: "Fixture",
            confidence: secrets::Confidence::High,
        },
        location: secrets::Location::File {
            path: "src/config.ts".into(),
        },
        line: 3,
        col: 2,
        masked: "****".into(),
        fingerprint: secrets::fingerprint(&raw),
        tracking: secrets::Tracking::Tracked,
        verified: None,
    }
}
fn secrets_report_fixture() -> ScanReport {
    ScanReport {
        root: "unused-root".into(),
        findings: vec![secret()],
        history_findings: vec![],
        walk: WalkStats {
            files_scanned: 1,
            ..WalkStats::default()
        },
        history: HistoryOutcome::Scanned(HistoryStats {
            commits: 2,
            lines: 5,
        }),
        ignored: 0,
    }
}
fn package() -> deps::Package {
    deps::Package {
        ecosystem: deps::Ecosystem::Npm,
        name: "fixture-package".into(),
        version: "1.0.0".into(),
        lockfiles: vec!["package-lock.json".into()],
    }
}
fn vulnerability() -> deps::VulnFinding {
    deps::VulnFinding {
        package: package(),
        vuln: deps::Vuln {
            id: "FIXTURE-ADVISORY".into(),
            aliases: vec!["CVE-fixture".into()],
            summary: "Fixture".into(),
            severity: deps::Severity::High,
            cvss: None,
            fixed: vec!["2.0.0".into()],
            malicious: false,
        },
        fix: Some("2.0.0".into()),
    }
}
fn dependencies_fixture() -> DepsReport {
    DepsReport {
        root: "unused-root".into(),
        lockfiles: vec![LockfileReport {
            rel: "package-lock.json".into(),
            label: "package-lock.json",
            ecosystem: deps::Ecosystem::Npm,
            packages: 1,
            error: None,
        }],
        packages: vec![package()],
        findings: vec![vulnerability()],
        unchecked: vec![],
        from_cache: 1,
        fresh: 0,
        stale_cache_age: None,
        osv_unavailable: false,
        offline: true,
        warnings: vec![],
        install_scripts: vec![],
        typosquats: vec![],
    }
}
fn report() -> ProjectReport {
    ProjectReport {
        secrets: secrets_report_fixture(),
        deps: Some(dependencies_fixture()),
        workflows: Some(vec![]),
    }
}
fn context() -> CoreContext {
    CoreContext {
        target: TargetKind::Directory,
        verification_requested: Some(false),
        network: Some(NetworkLog::default().snapshot()),
        baseline_hidden: Some(Hidden::default()),
    }
}
fn status(result: &ScanResultV2, id: &str) -> CheckStatus {
    result
        .checks
        .iter()
        .find(|c| c.id == id)
        .expect("expected coverage check")
        .status
}
fn export(report: &ProjectReport, c: &CoreContext) -> RedactedScan {
    project_report(report, c)
        .unwrap()
        .redacted(&RedactionPolicy::default())
        .unwrap()
}

#[test]
fn complete_projection_retains_fingerprints_ids_and_explicit_legacy_gaps() {
    let mut r = report();
    let before = export(&r, &context());
    let f = before
        .as_scan()
        .findings
        .iter()
        .find(|f| f.category == "secret_exposure")
        .unwrap();
    assert_eq!(
        f.evidence.fingerprint.as_deref(),
        Some(r.secrets.findings[0].fingerprint.as_str())
    );
    assert!(f.id.starts_with("secrets/fixture-secret/"));
    let id = f.id.clone();
    r.secrets.findings[0].line += 20;
    r.secrets.findings[0].col += 2;
    let after = export(&r, &context());
    assert!(after.as_scan().findings.iter().any(|f| f.id == id));
    assert_eq!(
        status(after.as_scan(), "core.secrets.walk"),
        CheckStatus::Completed
    );
    assert_eq!(
        status(after.as_scan(), "legacy.workflows"),
        CheckStatus::Partial
    );
    assert_eq!(
        status(after.as_scan(), "core.deps.discovery"),
        CheckStatus::Partial
    );
    assert!(!after.as_scan().completed());
    assert_eq!(
        wire::parse(&after.render_json(), &RedactionPolicy::default()).unwrap(),
        after
    );
    assert!(
        before
            .as_scan()
            .findings
            .iter()
            .any(|f| f.tags.contains(&"recommended-version:2.0.0".into()))
    );
    assert!(
        before
            .as_scan()
            .limitations
            .contains(&output::FINGERPRINT_LIMITATION.into())
    );
}
#[test]
fn all_walk_skips_and_policy_exclusions_are_partial_with_reasons() {
    for select in 0..4 {
        let mut r = report();
        let w = &mut r.secrets.walk;
        match select {
            0 => w.skipped_binary = 1,
            1 => w.skipped_large = 2,
            2 => w.skipped_unreadable = 3,
            _ => w.dirs_skipped = 4,
        }
        r.secrets.ignored = 7;
        let result = project_report(&r, &context()).unwrap();
        assert_eq!(status(&result, "core.secrets.walk"), CheckStatus::Partial);
        assert_eq!(
            status(&result, "core.secrets.suppressions"),
            CheckStatus::Partial
        );
        assert!(
            result
                .checks
                .iter()
                .filter(|c| c.status != CheckStatus::Completed)
                .all(|c| c.reason.as_ref().is_some_and(|r| !r.is_empty()))
        );
        assert!(
            result
                .limitations
                .iter()
                .any(|s| s.contains("reported counter): 7"))
        );
    }
}
#[test]
fn history_failures_are_partial_and_never_copy_stderr() {
    let raw = ["weak", "private-value"].join("-");
    for error in [
        HistoryError::GitNotFound,
        HistoryError::NotARepo,
        HistoryError::Git(raw.clone()),
    ] {
        let mut r = report();
        r.secrets.history = HistoryOutcome::Failed(error);
        let safe = export(&r, &context());
        assert_eq!(
            status(safe.as_scan(), "core.secrets.history"),
            CheckStatus::Partial
        );
        assert!(!safe.render_json().contains(&raw));
        assert!(!safe.render_text().contains(&raw));
        assert!(!safe.render_html().contains(&raw));
    }
    let mut r = report();
    r.secrets.history = HistoryOutcome::Disabled;
    r.deps = None;
    r.workflows = None;
    let mut c = context();
    c.target = TargetKind::File;
    let safe = export(&r, &c);
    assert_eq!(
        status(safe.as_scan(), "core.secrets.history"),
        CheckStatus::Skipped
    );
    assert_eq!(
        status(safe.as_scan(), "core.deps.applicability"),
        CheckStatus::Skipped
    );
    c.target = TargetKind::Directory;
    assert_eq!(
        status(export(&r, &c).as_scan(), "core.secrets.history"),
        CheckStatus::Partial
    );
}
#[test]
fn unchecked_lockfile_cache_warning_and_missing_metadata_are_visible() {
    let mut r = report();
    let d = r.deps.as_mut().unwrap();
    let raw = ["unsafe", "parser-data"].join("-");
    d.lockfiles[0].error = Some(raw.clone());
    d.unchecked.push(package());
    d.warnings.push(raw.clone());
    d.osv_unavailable = true;
    d.stale_cache_age = Some(12345);
    let safe = export(&r, &context());
    for id in [
        "core.deps.lockfiles",
        "core.deps.unchecked",
        "core.deps.advisory_data",
    ] {
        assert_eq!(status(safe.as_scan(), id), CheckStatus::Partial);
    }
    assert!(safe.render_json().contains("12345"));
    assert!(
        safe.render_json()
            .contains("Unchecked package npm:fixture-package@1.0.0")
    );
    assert!(!safe.render_json().contains(&raw));
}
#[test]
fn invalid_and_unknown_items_do_not_discard_other_findings() {
    let mut r = report();
    let mut invalid = secret();
    invalid.location = secrets::Location::File {
        path: "../outside".into(),
    };
    r.secrets.findings.push(invalid);
    let d = r.deps.as_mut().unwrap();
    d.findings[0].package.lockfiles.push("../outside".into());
    let mut unknown = vulnerability();
    unknown.vuln.id = "FIXTURE-UNKNOWN".into();
    unknown.vuln.severity = deps::Severity::Unknown;
    d.findings.push(unknown);
    let safe = export(&r, &context());
    assert_eq!(safe.as_scan().findings.len(), 2);
    assert_eq!(
        status(safe.as_scan(), "core.secrets.mapping"),
        CheckStatus::Partial
    );
    assert_eq!(
        status(safe.as_scan(), "core.deps.mapping"),
        CheckStatus::Partial
    );
    assert!(safe.render_json().contains("FIXTURE-UNKNOWN"));
    assert!(safe.render_json().contains("legacy severity=unknown"));
}
#[test]
fn scripts_and_typosquats_survive_without_executable_or_secret_bodies() {
    let mut r = report();
    let raw = ["hidden", "script-value"].join("-");
    let d = r.deps.as_mut().unwrap();
    d.install_scripts.push(InstallScript {
        lockfile: "package-lock.json".into(),
        name: "script-package".into(),
        version: "1.0.0".into(),
        dev: true,
        commands: vec![("postinstall".into(), raw.clone())],
        flags: vec!["network"],
    });
    d.install_scripts.push(InstallScript {
        lockfile: "yarn.lock".into(),
        name: "unknown-script".into(),
        version: "1.0.0".into(),
        dev: false,
        commands: vec![],
        flags: vec![],
    });
    d.typosquats.push((
        package(),
        Suspect {
            looks_like: "popular-package".into(),
            reason: "two letters swapped",
        },
    ));
    let safe = export(&r, &context());
    assert_eq!(safe.as_scan().findings.len(), 5);
    assert!(
        safe.as_scan().findings.iter().any(
            |f| f.rule_id == "core-install-script" && f.tags.contains(&"dev-dependency".into())
        )
    );
    assert!(
        safe.as_scan()
            .findings
            .iter()
            .any(|f| f.rule_id == "core-typosquat" && f.confidence == Confidence::NeedsReview)
    );
    assert!(!safe.render_json().contains(&raw));
    assert_eq!(
        status(safe.as_scan(), "core.deps.script_details"),
        CheckStatus::Partial
    );
}
#[test]
fn real_baseline_filtering_counts_are_carried_separately_from_ignores() {
    let mut r = report();
    let before = ReportCounts::capture(&r);
    let baseline =
        Baseline::from_reports(Some(&r.secrets), r.deps.as_ref(), r.workflows.as_deref());
    baseline.apply_secrets(&mut r.secrets);
    baseline.apply_deps(r.deps.as_mut().unwrap());
    let mut c = context();
    c.baseline_hidden = Some(before.hidden_since(&r).unwrap());
    let safe = export(&r, &c);
    assert!(safe.as_scan().findings.is_empty());
    assert_eq!(
        status(safe.as_scan(), "core.policy.baseline"),
        CheckStatus::Partial
    );
    assert!(safe.render_json().contains("secrets=1, vulnerabilities=1"));
    let none = ReportCounts::capture(&r);
    r.secrets.findings.push(secret());
    assert!(none.hidden_since(&r).is_err());
}
#[test]
fn no_network_journal_does_not_invent_requests_from_fresh_or_liveness() {
    let mut r = report();
    r.deps.as_mut().unwrap().fresh = 5;
    r.secrets.findings[0].verified = Some(secrets::Liveness::Live);
    let safe = export(&r, &CoreContext::default());
    assert!(safe.as_scan().network_activities.is_empty());
    assert_eq!(status(safe.as_scan(), "core.network"), CheckStatus::Partial);
    let mut c = context();
    c.verification_requested = Some(true);
    r.secrets.findings[0].verified = Some(secrets::Liveness::Unknown("sensitive error".into()));
    assert_eq!(
        status(export(&r, &c).as_scan(), "core.secrets.verification"),
        CheckStatus::Partial
    );
}

struct MockHttp {
    calls: AtomicUsize,
    fail: bool,
}
impl osv::Http for MockHttp {
    fn request(&self, _: &str, _: Option<&str>) -> osv::Attempt {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            osv::Attempt::Retry(None)
        } else {
            osv::Attempt::Ok(r#"{"results":[{"vulns":[]}]}"#.into())
        }
    }
}
struct MockVerify {
    calls: AtomicUsize,
}
impl verify::Transport for MockVerify {
    fn send(&self, _: &verify::Request) -> Result<verify::Response, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(verify::Response {
            status: 200,
            body: r#"{"login":"fixture"}"#.into(),
        })
    }
}
#[test]
fn network_observers_count_actual_calls_and_never_store_request_data() {
    use osv::Http;
    use verify::Transport;
    let log = NetworkLog::default();
    let http = MockHttp {
        calls: AtomicUsize::new(0),
        fail: true,
    };
    let provider = MockVerify {
        calls: AtomicUsize::new(0),
    };
    let raw = ["private", "request-data"].join("-");
    let observed = ObservedHttp {
        inner: &http,
        log: &log,
    };
    for _ in 0..3 {
        observed.request("https://api.osv.dev/v1/querybatch", Some(&raw));
    }
    observed.request(&format!("https://api.osv.dev/v1/vulns/{raw}?q={raw}"), None);
    ObservedVerification {
        inner: &provider,
        log: &log,
    }
    .send(&verify::Request {
        method: "GET",
        url: format!("https://api.github.com/{raw}?q={raw}"),
        headers: vec![("Authorization".into(), raw.clone())],
        body: Some(raw.clone()),
    })
    .unwrap();
    let mut c = context();
    c.network = Some(log.snapshot());
    let safe = export(&report(), &c);
    let out = safe.render_json();
    assert!(out.contains("transport_attempts=3"));
    assert!(out.contains("credential verification: GET api.github.com"));
    assert!(!out.contains(&raw));
    assert_eq!(status(safe.as_scan(), "core.network"), CheckStatus::Partial);
    assert_eq!(http.calls.load(Ordering::SeqCst), 4);
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        loop {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/finding_v2")
                .join(format!(
                    ".test-fnd05-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::SeqCst)
                ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("cannot create isolated fixture"),
            }
        }
    }
    fn write(&self, name: &str, body: &str) {
        fs::write(self.0.join(name), body).unwrap();
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/finding_v2")
            .canonicalize()
            .unwrap();
        if self
            .0
            .canonicalize()
            .is_ok_and(|p| p.starts_with(&parent) && p.parent() == Some(parent.as_path()))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn options() -> ScanOptions {
    ScanOptions {
        history: false,
        verify: false,
        ..ScanOptions::default()
    }
}
fn osv_options(offline: bool) -> osv::OsvOptions {
    osv::OsvOptions {
        cache_dir: None,
        no_cache: true,
        offline,
    }
}
fn lockfile(p: &Project) {
    p.write(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/fixture-package":{"version":"1.0.0"}}}"#,
    );
}
#[test]
fn observed_capture_preserves_legacy_report_and_counts_retries_offline_and_online() {
    for (offline, fail, expected) in [(true, false, 0), (false, false, 1), (false, true, 3)] {
        let p = Project::new();
        lockfile(&p);
        let http = MockHttp {
            calls: AtomicUsize::new(0),
            fail,
        };
        let provider = MockVerify {
            calls: AtomicUsize::new(0),
        };
        let (r, c) = scan_project_observed(
            &p.0,
            &options(),
            &osv_options(offline),
            &http,
            &provider,
            &|_| {},
        )
        .unwrap();
        assert_eq!(http.calls.load(Ordering::SeqCst), expected);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        let safe = export(&r, &c);
        assert_eq!(safe.as_scan().network_activities.is_empty(), offline);
        if fail {
            assert!(safe.render_json().contains("transport_attempts=3"));
            assert_eq!(
                status(safe.as_scan(), "core.deps.unchecked"),
                CheckStatus::Partial
            );
        }
        let legacy = combined::scan_project(
            &p.0,
            &options(),
            &osv_options(offline),
            &MockHttp {
                calls: AtomicUsize::new(0),
                fail,
            },
            &|_| {},
        )
        .unwrap();
        assert_eq!(combined::render_json(&legacy), combined::render_json(&r));
    }
}
#[test]
fn dependency_offline_does_not_hide_explicit_provider_verification() {
    let p = Project::new();
    lockfile(&p);
    let token = format!("{}{}", "ghp_", "aB9cD8eF7gH6iJ5kL4mN3oP2qR1sT0uV9wX8");
    p.write("config.js", &format!("const token = '{token}';\n"));
    let http = MockHttp {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    let provider = MockVerify {
        calls: AtomicUsize::new(0),
    };
    let (r, c) = scan_project_observed(
        &p.0,
        &ScanOptions {
            verify: true,
            ..options()
        },
        &osv_options(true),
        &http,
        &provider,
        &|_| {},
    )
    .unwrap();
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let safe = export(&r, &c);
    assert!(safe.render_json().contains("credential verification"));
    assert!(!safe.render_json().contains(&token));
    assert_eq!(
        safe.as_scan()
            .findings
            .iter()
            .filter(|f| f.evidence.fingerprint.is_some())
            .count(),
        1
    );
}

#[test]
fn cached_results_do_not_create_fictional_network_activity() {
    let p = Project::new();
    lockfile(&p);
    let opts = osv::OsvOptions {
        cache_dir: Some(p.0.join("cache")),
        no_cache: false,
        offline: false,
    };
    let http = MockHttp {
        calls: AtomicUsize::new(0),
        fail: false,
    };
    let provider = MockVerify {
        calls: AtomicUsize::new(0),
    };
    let (first, first_context) =
        scan_project_observed(&p.0, &options(), &opts, &http, &provider, &|_| {}).unwrap();
    assert_eq!(first.deps.as_ref().unwrap().fresh, 1);
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        export(&first, &first_context)
            .as_scan()
            .network_activities
            .len(),
        1
    );
    let (cached, cached_context) =
        scan_project_observed(&p.0, &options(), &opts, &http, &provider, &|_| {}).unwrap();
    assert_eq!(cached.deps.as_ref().unwrap().from_cache, 1);
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    assert!(
        export(&cached, &cached_context)
            .as_scan()
            .network_activities
            .is_empty()
    );
}
#[test]
fn hostile_metadata_is_redacted_on_all_output_paths_and_roundtrips() {
    let raw = ["weak", "metadata-secret"].join("-");
    let mut r = report();
    let mut p = package();
    p.name = raw.clone();
    r.deps.as_mut().unwrap().unchecked.push(p);
    let mut s = secret();
    s.line = 40;
    r.secrets.findings.push(s);
    let safe = project_report(&r, &context())
        .unwrap()
        .redacted(&RedactionPolicy::new([raw.as_str()]))
        .unwrap();
    assert!(
        safe.as_scan()
            .findings
            .iter()
            .any(|f| f.tags.contains(&"occurrences:2".into()))
    );
    for rendered in [
        safe.render_json(),
        safe.render_text(),
        safe.render_html(),
        format!("{safe:?}"),
    ] {
        assert!(!rendered.contains(&raw));
    }
    assert_eq!(
        wire::parse(&safe.render_json(), &RedactionPolicy::default()).unwrap(),
        safe
    );
}
