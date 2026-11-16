//! Conservative adapters for already-merged Core types. No scanner invocation,
//! filesystem access, network, licensing decision, or command execution.
use super::output::pending_id;
use super::*;
use crate::{deps, hygiene, secrets};

/// Existing Core paths are already root-relative; reject absolute/traversal paths.
/// The core fingerprint (16 lowercase hex, `secrets::fingerprint`) is carried
/// so V1 `.jetscanignore`/baselines keep matching; the legacy mask is not
/// copied (it shows the first/last characters of weak secrets). The id is
/// computed by `redacted()` in area `secrets` from rule, path, commit and
/// fingerprint, so it survives line moves.
pub fn secret(f: &secrets::Finding) -> Result<FindingV2, ModelError> {
    let (path, component, history) = match &f.location {
        secrets::Location::File { path } => (
            path.to_str()
                .ok_or(ModelError("non_utf8_path"))?
                .replace('\\', "/"),
            None,
            false,
        ),
        secrets::Location::Git { path, commit } => {
            (path.clone(), Some(format!("git:{commit}")), true)
        }
    };
    let location = SourceLocation {
        relative_path: path,
        line: one_based(f.line)?,
        column: one_based(f.col)?,
        archive_entry: None,
        component,
    };
    location.validate()?;
    let mut tags = vec![
        "legacy-core".into(),
        format!("tracking:{}", f.tracking.label()),
    ];
    if history {
        tags.push("git-history".into());
    }
    if let Some(live) = &f.verified {
        tags.push(format!("provider:{}", live.label()));
    }
    Ok(FindingV2 {
        id:pending_id("secrets"),rule_id:f.rule.id.into(),title:"Possible credential in source or history".into(),category:"secret_exposure".into(),
        severity:Severity::High,
        confidence:match f.rule.confidence { secrets::Confidence::Low=>Confidence::NeedsReview,_=>Confidence::Potential },
        location,evidence:Evidence { redacted_excerpt:None, fingerprint:Some(f.fingerprint.clone()).filter(|fp| output::is_core_fingerprint(fp)) },
        explanation:"A static detector matched. Provider liveness, if recorded, does not prove exposure or exploitation. Review tracking and revoke/rotate exposed credentials outside JetScan.".into(),
        remediation_id:Some("core-secret:rotate-and-review".into()),references:vec![],cwe_ids:vec!["CWE-200".into()],tags,
    })
}

/// Coverage is always Partial: legacy workflows::check cannot distinguish an
/// empty successful check from unsupported/unreadable input. Not a verifier.
pub fn workflows(issues: &[hygiene::Issue]) -> Result<ScanResultV2, ModelError> {
    let mut result = ScanResultV2::default();
    result.checks.push(RuleCheck {
        id: "legacy.workflows".into(),
        status: CheckStatus::Partial,
        reason: Some("Legacy workflow scanner does not report parsing/read completeness.".into()),
    });
    for issue in issues {
        if !(issue.path.starts_with(".github/workflows/")
            || matches!(issue.path.as_str(), "action.yml" | "action.yaml"))
        {
            return Err(ModelError("not_workflow_location"));
        }
        let location = SourceLocation {
            relative_path: issue.path.clone(),
            line: if issue.line == 0 {
                None
            } else {
                one_based(issue.line)?
            },
            column: None,
            archive_entry: None,
            // Multiple contexts may share a rule and source line. This metadata
            // passes through redaction before being used for structural identity.
            component: Some(issue.message.clone()),
        };
        location.validate()?;
        result.findings.push(FindingV2 {
            id: pending_id("workflows"),
            rule_id: issue.id.into(),
            title: "Potential unsafe workflow configuration".into(),
            category: "workflow".into(),
            severity: match issue.level {
                hygiene::Level::High => Severity::High,
                hygiene::Level::Medium => Severity::Medium,
            },
            confidence: Confidence::Potential,
            location,
            evidence: Evidence::default(),
            explanation: issue.message.clone(),
            remediation_id: Some(format!("{}:review", issue.id)),
            references: vec![],
            cwe_ids: vec![],
            tags: vec!["legacy-core".into(), "guidance-only".into()],
        });
    }
    Ok(result)
}

/// One finding per affected lockfile. Unknown severity is an explicit adapter
/// error: caller MUST record Partial and retain the V1 report, not claim clean.
pub fn dependency(f: &deps::VulnFinding) -> Result<Vec<FindingV2>, ModelError> {
    let severity = if f.vuln.malicious {
        Severity::Critical
    } else {
        match f.vuln.severity {
            deps::Severity::Critical => Severity::Critical,
            deps::Severity::High => Severity::High,
            deps::Severity::Medium => Severity::Medium,
            deps::Severity::Low => Severity::Low,
            deps::Severity::Unknown => {
                return Err(ModelError("legacy_unknown_severity_requires_review"));
            }
        }
    };
    if f.package.lockfiles.is_empty() {
        return Err(ModelError("missing_dependency_location"));
    }
    f.package.lockfiles.iter().map(|path| {
        let location=SourceLocation { relative_path:path.clone(),line:None,column:None,archive_entry:None,
            component:Some(format!("{}:{}@{}",f.package.ecosystem.osv_name(),f.package.name,f.package.version)) };
        location.validate()?;
        Ok(FindingV2 { id:pending_id("deps"),rule_id:f.vuln.id.clone(),
            title:if f.vuln.malicious {"Package listed as malicious"} else {"Dependency matches a known advisory"}.into(),
            category:"dependency".into(),severity,confidence:Confidence::Potential,location,evidence:Evidence::default(),
            explanation:"Advisory matches a locked package version; application reachability and exploitability were not checked. Review existing dependency advice manually; no package manager is run.".into(),
            remediation_id:Some("core-dependency:manual-review".into()),references:vec![],cwe_ids:vec![],
            tags:vec!["legacy-core".into(),if f.vuln.malicious {"malicious-package"} else {"advisory-match"}.into()],
        })
    }).collect()
}
fn one_based(n: usize) -> Result<Option<u32>, ModelError> {
    let n = u32::try_from(n).map_err(|_| ModelError("coordinate_overflow"))?;
    if n == 0 {
        return Err(ModelError("invalid_coordinates"));
    }
    Ok(Some(n))
}

// Web and APK share these types (`apk_audit::types` re-exports them).
use crate::web_audit::types as scanner;

fn severity(s: scanner::Severity) -> Severity {
    match s {
        scanner::Severity::Critical => Severity::Critical,
        scanner::Severity::High => Severity::High,
        scanner::Severity::Medium => Severity::Medium,
        scanner::Severity::Low => Severity::Low,
        scanner::Severity::Info => Severity::Info,
    }
}
fn confidence(c: scanner::Confidence) -> Confidence {
    match c {
        scanner::Confidence::Confirmed => Confidence::Confirmed,
        scanner::Confidence::Potential => Confidence::Potential,
        scanner::Confidence::NeedsReview => Confidence::NeedsReview,
    }
}
fn check(c: &scanner::RuleCheck) -> RuleCheck {
    RuleCheck {
        id: c.id.clone(),
        status: match c.status {
            scanner::CheckStatus::Completed => CheckStatus::Completed,
            scanner::CheckStatus::Partial => CheckStatus::Partial,
            scanner::CheckStatus::Skipped => CheckStatus::Skipped,
            scanner::CheckStatus::Error => CheckStatus::Error,
        },
        reason: c.reason.clone(),
    }
}
fn evidence(e: &scanner::Evidence) -> Evidence {
    // The fingerprint is the core one (`secrets::fingerprint`); `redacted()`
    // still drops anything that is not in that format.
    Evidence {
        redacted_excerpt: e.redacted_excerpt.clone(),
        fingerprint: e.fingerprint.clone(),
    }
}
fn owned(list: &[&'static str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}
fn scanner_scan(
    schema_version: u32,
    findings: Vec<FindingV2>,
    checks: &[scanner::RuleCheck],
    limitations: &[String],
    network_activities: &[String],
) -> Result<ScanResultV2, ModelError> {
    if schema_version != SCHEMA_VERSION {
        return Err(ModelError("unsupported_schema_version"));
    }
    let result = ScanResultV2 {
        schema_version: SCHEMA_VERSION,
        findings,
        checks: checks.iter().map(check).collect(),
        limitations: limitations.to_vec(),
        network_activities: network_activities.to_vec(),
    };
    result.validate()?;
    Ok(result)
}

/// Web Source Audit -> V2, 1:1 per `web_audit/HANDOFF_WEB.md` §3. Scanner ids
/// (`web/<rule>/<16 hex>`, line-independent) and core fingerprints are kept;
/// checks (incl. skipped with reasons), limitations and network activities are
/// carried. Framework and walk statistics have no V2 field and are not carried.
/// Output still goes through `redacted()`; no scanner is run here.
pub fn web(r: &crate::web_audit::WebScanResult) -> Result<ScanResultV2, ModelError> {
    let findings = r
        .findings
        .iter()
        .map(|f| FindingV2 {
            id: f.id.clone(),
            rule_id: f.rule_id.into(),
            title: f.title.clone(),
            category: f.category.into(),
            severity: severity(f.severity),
            confidence: confidence(f.confidence),
            location: SourceLocation {
                relative_path: f.location.relative_path.clone(),
                line: f.location.line,
                column: f.location.column,
                archive_entry: None,
                component: None,
            },
            evidence: evidence(&f.evidence),
            explanation: f.explanation.clone(),
            remediation_id: f.remediation_id.clone(),
            references: owned(&f.references),
            cwe_ids: owned(&f.cwe_ids),
            tags: f.tags.clone(),
        })
        .collect();
    scanner_scan(
        r.schema_version,
        findings,
        &r.checks,
        &r.limitations,
        &r.network_activities,
    )
}

/// APK Static Audit -> V2 per `apk_audit/HANDOFF_APK.md`: `relative_path` and
/// `archive_entry` are both the archive entry (the APK path itself is a CLI
/// argument, possibly absolute, and is not a project-relative path); column is
/// always None. A finding without an archive entry is an adapter error, never a
/// guessed location. Ids (`apk/<rule>/<16 hex>`) and fingerprints are kept;
/// APK metadata (package, SDKs, entry count) has no V2 field.
pub fn apk(r: &crate::apk_audit::ApkScanResult) -> Result<ScanResultV2, ModelError> {
    let findings = r
        .findings
        .iter()
        .map(|f| {
            let entry = f
                .location
                .archive_entry
                .clone()
                .ok_or(ModelError("missing_archive_entry"))?;
            Ok(FindingV2 {
                id: f.id.clone(),
                rule_id: f.rule_id.into(),
                title: f.title.clone(),
                category: f.category.into(),
                severity: severity(f.severity),
                confidence: confidence(f.confidence),
                location: SourceLocation {
                    relative_path: entry.clone(),
                    line: f.location.line,
                    column: None,
                    archive_entry: Some(entry),
                    component: f.location.component.clone(),
                },
                evidence: evidence(&f.evidence),
                explanation: f.explanation.clone(),
                remediation_id: f.remediation_id.clone(),
                references: owned(&f.references),
                cwe_ids: owned(&f.cwe_ids),
                tags: f.tags.clone(),
            })
        })
        .collect::<Result<_, ModelError>>()?;
    scanner_scan(
        r.schema_version,
        findings,
        &r.checks,
        &r.limitations,
        &r.network_activities,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_adapter_omits_even_corrupt_legacy_masks_and_hashes() {
        let raw = ["weak", "credential"].join("-");
        let legacy = secrets::Finding {
            rule: secrets::RuleInfo {
                id: "fixture-secret",
                name: "Fixture",
                confidence: secrets::Confidence::High,
            },
            location: secrets::Location::File {
                path: "config.ts".into(),
            },
            line: 1,
            col: 2,
            masked: raw.clone(),
            fingerprint: raw.clone(),
            tracking: secrets::Tracking::Ignored,
            verified: Some(secrets::Liveness::Live),
        };
        let f = secret(&legacy).unwrap();
        assert_eq!(f.confidence, Confidence::Potential);
        assert!(f.tags.contains(&"tracking:ignored".into()));
        assert_eq!(f.evidence, Evidence::default());
        let scan = ScanResultV2 {
            findings: vec![f],
            ..ScanResultV2::default()
        };
        assert!(
            !scan
                .redacted(&RedactionPolicy::default())
                .unwrap()
                .render_json()
                .contains(&raw)
        );
        let mut invalid = legacy.clone();
        invalid.col = 0;
        assert!(secret(&invalid).is_err());
        invalid.col = 2;
        invalid.location = secrets::Location::File {
            path: "../outside".into(),
        };
        assert!(secret(&invalid).is_err());
        let mut history = legacy;
        history.location = secrets::Location::Git {
            path: "config.ts".into(),
            commit: "abc123".into(),
        };
        assert_eq!(
            secret(&history).unwrap().location.component.as_deref(),
            Some("git:abc123")
        );
    }
    #[test]
    fn secret_adapter_carries_core_fingerprint_and_line_independent_id() {
        let token = format!("{}{}", "ghp_", "aB9cD8eF7gH6iJ5kL4mN3oP2qR1sT0uV9wX8");
        let hits = secrets::scan_text(secrets::rules::all(), &format!("t = \"{token}\""));
        assert_eq!(hits.len(), 1, "core must detect the synthetic token");
        let legacy = secrets::Finding {
            rule: hits[0].rule,
            location: secrets::Location::File {
                path: "src\\config.ts".into(),
            },
            line: 3,
            col: 6,
            masked: secrets::mask(&token),
            fingerprint: secrets::fingerprint(&token),
            tracking: secrets::Tracking::Tracked,
            verified: None,
        };
        let export = |findings: Vec<secrets::Finding>| {
            ScanResultV2 {
                findings: findings.iter().map(|f| secret(f).unwrap()).collect(),
                ..ScanResultV2::default()
            }
            .redacted(&RedactionPolicy::default())
            .unwrap()
        };
        let safe = export(vec![legacy.clone()]);
        let f = &safe.as_scan().findings[0];
        assert_eq!(f.location.relative_path, "src/config.ts");
        assert_eq!(
            f.evidence.fingerprint.as_deref(),
            Some(legacy.fingerprint.as_str())
        );
        assert!(f.id.starts_with(&format!("secrets/{}/", hits[0].rule.id)));
        assert!(output::is_canonical_id(&f.id, hits[0].rule.id));
        assert!(
            safe.as_scan()
                .limitations
                .contains(&output::FINGERPRINT_LIMITATION.to_string())
        );
        let json = safe.render_json();
        assert!(!json.contains(&token));
        assert!(!json.contains(&legacy.masked), "mask is not exported");
        assert_eq!(
            wire::parse(&json, &RedactionPolicy::default()).unwrap(),
            safe
        );
        // Same secret, code moved down: same id. Twice in the file: one finding.
        let mut moved = legacy.clone();
        moved.line = 30;
        moved.col = 1;
        assert_eq!(export(vec![moved.clone()]).as_scan().findings[0].id, f.id);
        let both = export(vec![moved, legacy.clone()]);
        assert_eq!(both.as_scan().findings.len(), 1);
        assert_eq!(both.as_scan().findings[0].location.line, Some(3));
        assert!(
            both.as_scan().findings[0]
                .tags
                .contains(&"occurrences:2".into())
        );
        // Another commit or another secret is another finding.
        let mut history = legacy.clone();
        history.location = secrets::Location::Git {
            path: "src/config.ts".into(),
            commit: "abc123".into(),
        };
        assert_ne!(export(vec![history]).as_scan().findings[0].id, f.id);
        let mut other = legacy;
        other.fingerprint = secrets::fingerprint("another-value");
        assert_ne!(export(vec![other]).as_scan().findings[0].id, f.id);
    }
    #[test]
    fn empty_workflow_result_is_incomplete_and_same_line_contexts_survive() {
        assert!(!workflows(&[]).unwrap().completed());
        let issue = hygiene::Issue {
            id: "gha-script-injection",
            level: hygiene::Level::High,
            path: ".github/workflows/ci.yml".into(),
            line: 6,
            message: "Untrusted title expression".into(),
            fix: "Advice only".into(),
        };
        let mut second = issue.clone();
        second.message = "Untrusted body expression".into();
        let scan = workflows(&[issue, second])
            .unwrap()
            .redacted(&RedactionPolicy::default())
            .unwrap();
        assert_eq!(scan.as_scan().findings.len(), 2);
        assert!(!scan.as_scan().completed());
        assert_eq!(
            wire::parse(&scan.render_json(), &RedactionPolicy::default()).unwrap(),
            scan
        );
    }
    #[test]
    fn unknown_severity_is_explicit_not_an_info_or_clean_result() {
        let mut legacy = deps::VulnFinding {
            package: deps::Package {
                ecosystem: deps::Ecosystem::Npm,
                name: "fixture-package".into(),
                version: "1.0.0".into(),
                lockfiles: vec!["package-lock.json".into()],
            },
            vuln: deps::Vuln {
                id: "FIXTURE-ADVISORY".into(),
                aliases: vec![],
                summary: "Fixture only".into(),
                severity: deps::Severity::Unknown,
                cvss: None,
                fixed: vec![],
                malicious: false,
            },
            fix: None,
        };
        assert_eq!(
            dependency(&legacy),
            Err(ModelError("legacy_unknown_severity_requires_review"))
        );
        legacy.vuln.severity = deps::Severity::High;
        assert_eq!(dependency(&legacy).unwrap()[0].severity, Severity::High);
        legacy.vuln.malicious = true;
        assert_eq!(dependency(&legacy).unwrap()[0].severity, Severity::Critical);
        legacy.package.lockfiles.clear();
        assert_eq!(
            dependency(&legacy),
            Err(ModelError("missing_dependency_location"))
        );
    }
}
