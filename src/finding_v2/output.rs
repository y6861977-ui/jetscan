//! All output flows through this immutable, sanitized view.
use super::*;
use crate::{
    hash,
    json::{self, Json},
    secrets, ui,
};
use std::path::Path;

/// Sensitive values live only for this operation. Debug never displays them.
#[derive(Default)]
pub struct RedactionPolicy<'a> {
    sensitive: Vec<&'a str>,
}
impl fmt::Debug for RedactionPolicy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedactionPolicy { <omitted> }")
    }
}
impl<'a> RedactionPolicy<'a> {
    /// Supply ALL known sensitive fragments, including weak/unrecognized passwords.
    /// Built-in detection is defense in depth, not proof that arbitrary text is safe.
    pub fn new(sensitive: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            sensitive: sensitive.into_iter().filter(|s| !s.is_empty()).collect(),
        }
    }
    pub fn text(&self, input: &str) -> String {
        // Bound detection and avoid truncation leaving a partial credential visible.
        if input.len() > 16 * 1024 {
            return "[omitted: oversized field]".into();
        }
        let clean = ui::sanitize_line(input);
        // Drop entire contaminated fields: no overlapping replacements or visible tails.
        if self.sensitive.iter().any(|s| {
            input.contains(s) || {
                let s = ui::sanitize_line(s);
                !s.is_empty() && clean.contains(&s)
            }
        }) || contains_secret(input)
            || contains_secret(&clean)
        {
            return "[redacted]".into();
        }
        clean
    }
}
fn contains_secret(text: &str) -> bool {
    !secrets::scan_text(secrets::rules::all(), text).is_empty()
        || !secrets::special::scan(Path::new(".env"), text).is_empty()
        || text.contains("-----BEGIN ")
        // Detection may intentionally ignore example hosts/placeholders. Output
        // must still hide URL userinfo, even for an unrecognized weak password.
        || text.split("://").skip(1).any(|tail| {
            tail.split(['/', '?', '#', ' ', '\n', '\r', '\t'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedScan {
    pub(super) scan: ScanResultV2,
}
impl RedactedScan {
    /// Read-only safe data for a reviewed adapter; no mutable escape hatch.
    pub fn as_scan(&self) -> &ScanResultV2 {
        &self.scan
    }
    pub fn render_json(&self) -> String {
        json::stringify_pretty(&self.to_json())
    }
    /// A readable complete representation, identical on stdout and stderr.
    pub fn render_text(&self) -> String {
        self.render_json()
    }
    /// An inert fragment, never interpreted source/Markdown/links.
    pub fn render_html(&self) -> String {
        format!("<pre>{}</pre>", escape_html(&self.render_json()))
    }
    pub fn to_json(&self) -> Json {
        scan_json(&self.scan)
    }
}

/// Added to `limitations` whenever an exported finding carries a fingerprint.
pub const FINGERPRINT_LIMITATION: &str = "evidence.fingerprint is the core secrets fingerprint \
(first 64 bits of SHA-256 over a fixed public prefix and the secret; the same value as JSON v1, \
.jetscanignore and baselines). It is not secret-salted: a short or dictionary password can be \
recovered from it by offline brute force. Treat reports that contain fingerprints as sensitive.";

/// Area for an id that is empty or has no usable `<area>/` prefix.
pub const FALLBACK_AREA: &str = "f2";

impl ScanResultV2 {
    pub fn redacted(&self, policy: &RedactionPolicy<'_>) -> Result<RedactedScan, ModelError> {
        self.validate()?;
        let mut scan = self.clone();
        for f in &mut scan.findings {
            for s in [
                &mut f.rule_id,
                &mut f.title,
                &mut f.category,
                &mut f.explanation,
                &mut f.location.relative_path,
            ] {
                *s = policy.text(s);
            }
            for s in [
                &mut f.remediation_id,
                &mut f.location.archive_entry,
                &mut f.location.component,
                &mut f.evidence.redacted_excerpt,
            ]
            .into_iter()
            .flatten()
            {
                *s = policy.text(s);
            }
            // Only the core secrets fingerprint survives: anything else may be a
            // raw value or a weaker hash supplied by an adapter.
            f.evidence.fingerprint = f
                .evidence
                .fingerprint
                .take()
                .filter(|fp| is_core_fingerprint(fp) && policy.text(fp) == *fp);
            for list in [&mut f.references, &mut f.cwe_ids, &mut f.tags] {
                clean_list(list, policy);
            }
            normalize_occurrences(f);
            // Keep a well-formed scanner id byte for byte; compute only when it is
            // empty, malformed, or its text would itself be redacted.
            let id = policy.text(&f.id);
            if !(id == f.id && is_canonical_id(&f.id, &f.rule_id)) {
                let area = id
                    .split_once('/')
                    .map(|(area, _)| area)
                    .filter(|area| is_area(area))
                    .unwrap_or(FALLBACK_AREA);
                f.id = compute_id(area, &f.rule_id, &f.location, &f.evidence)?;
            }
        }
        for c in &mut scan.checks {
            c.id = policy.text(&c.id);
            if let Some(s) = &mut c.reason {
                *s = policy.text(s);
            }
        }
        if scan
            .findings
            .iter()
            .any(|f| f.evidence.fingerprint.is_some())
        {
            scan.limitations.push(FINGERPRINT_LIMITATION.into());
        }
        clean_list(&mut scan.limitations, policy);
        clean_list(&mut scan.network_activities, policy);
        scan.findings.sort();
        scan.findings.dedup();
        scan.findings = merge_same_id(std::mem::take(&mut scan.findings))?;
        scan.checks.sort();
        scan.checks.dedup();
        // Keep conflicting coverage visible by refusing it, never pick Completed.
        if scan.checks.windows(2).any(|w| w[0].id == w[1].id) {
            return Err(ModelError("conflicting_check_id"));
        }
        scan.validate()?;
        if json::stringify_pretty(&scan_json(&scan)).len() > super::wire::MAX_BYTES {
            return Err(ModelError("v2_output_limit"));
        }
        Ok(RedactedScan { scan })
    }
}
fn clean_list(list: &mut Vec<String>, policy: &RedactionPolicy<'_>) {
    for s in list.iter_mut() {
        *s = policy.text(s);
    }
    list.sort();
    list.dedup();
}

const OCCURRENCES: &str = "occurrences:";

/// `occurrences:<n>` with canonical decimal n >= 2.
fn occurrence_tag(tag: &str) -> Option<u32> {
    let digits = tag.strip_prefix(OCCURRENCES)?;
    let n: u32 = digits.parse().ok()?;
    (n >= 2 && digits == n.to_string()).then_some(n)
}
fn occurrences(f: &FindingV2) -> u32 {
    f.tags
        .iter()
        .filter_map(|t| occurrence_tag(t))
        .max()
        .unwrap_or(1)
}
fn set_occurrences(f: &mut FindingV2, n: u32) {
    f.tags.retain(|t| occurrence_tag(t).is_none());
    if n > 1 {
        f.tags.push(format!("{OCCURRENCES}{n}"));
        f.tags.sort();
    }
}
/// At most one canonical occurrence tag per finding, so re-import is idempotent.
fn normalize_occurrences(f: &mut FindingV2) {
    let n = occurrences(f);
    set_occurrences(f, n);
}
/// Everything except the position inside the file/entry (line, column,
/// component) and the excerpt around it. Computed ids hash the component, so
/// it can only differ under one id when the scanner chose to leave it out of
/// its key (APK-SECRET-006: one key in two XML elements of one entry).
fn logical(f: &FindingV2) -> FindingV2 {
    let mut f = f.clone();
    f.location.line = None;
    f.location.column = None;
    f.location.component = None;
    f.evidence.redacted_excerpt = None;
    set_occurrences(&mut f, 1);
    f
}
/// Ids do not depend on line/column, so one id may arrive several times (the
/// same secret twice in one file). Same id = same logical finding: keep the
/// first location (input is sorted, so the lowest line/column/component) and
/// count as `occurrences:<n>`. Any other difference (severity, confidence,
/// title, ...) is a conflict and is refused rather than silently resolved.
fn merge_same_id(sorted: Vec<FindingV2>) -> Result<Vec<FindingV2>, ModelError> {
    let mut out: Vec<FindingV2> = Vec::with_capacity(sorted.len());
    for f in sorted {
        match out.last_mut() {
            Some(first) if first.id == f.id => {
                if logical(first) != logical(&f) {
                    return Err(ModelError("conflicting_finding_id"));
                }
                let n = occurrences(first).saturating_add(occurrences(&f));
                set_occurrences(first, n);
            }
            _ => out.push(f),
        }
    }
    Ok(out)
}

/// `secrets::fingerprint` format: exactly 16 lowercase hex characters.
pub fn is_core_fingerprint(fp: &str) -> bool {
    fp.len() == 16 && fp.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn is_area(area: &str) -> bool {
    (1..=32).contains(&area.len())
        && area.as_bytes()[0].is_ascii_alphanumeric()
        && area
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
/// The rule segment of an id: ASCII-lowercased rule id, characters outside
/// `[a-z0-9._-]` replaced by `_`, at most 128 characters.
pub fn rule_segment(rule_id: &str) -> String {
    let segment: String = rule_id
        .chars()
        .take(128)
        .map(|c| match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9' | '.' | '_' | '-') => c,
            _ => '_',
        })
        .collect();
    if segment.is_empty() {
        "_".into()
    } else {
        segment
    }
}
/// `<area>/<rule_segment(rule_id)>/<16 lowercase hex>`, area `[a-z0-9-]{1,32}`.
pub fn is_canonical_id(id: &str, rule_id: &str) -> bool {
    let mut parts = id.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(area), Some(rule), Some(hex), None) => {
            is_area(area) && rule == rule_segment(rule_id) && is_core_fingerprint(hex)
        }
        _ => false,
    }
}
/// Placeholder for adapters: `redacted()` replaces it with an id computed in
/// this area over already-redacted fields.
pub fn pending_id(area: &str) -> String {
    format!("{area}/pending")
}

/// Line/column-independent identity: first 8 bytes of SHA-256 over a
/// domain-separated canonical JSON array of (area, rule, path, archive entry,
/// component, key), key = core fingerprint if present, else the
/// whitespace-normalized redacted excerpt, else null. Call with redacted fields
/// (`redacted()` does); no raw source or credential belongs in the input.
pub fn compute_id(
    area: &str,
    rule_id: &str,
    location: &SourceLocation,
    evidence: &Evidence,
) -> Result<String, ModelError> {
    location.validate()?;
    if !is_area(area) {
        return Err(ModelError("invalid_id_area"));
    }
    let key = match (&evidence.fingerprint, &evidence.redacted_excerpt) {
        (Some(fp), _) if is_core_fingerprint(fp) => Json::Arr(vec![s("fingerprint"), s(fp)]),
        (_, Some(excerpt)) => Json::Arr(vec![
            s("excerpt"),
            s(&excerpt.split_whitespace().collect::<Vec<_>>().join(" ")),
        ]),
        _ => Json::Null,
    };
    let canonical = json::stringify(&Json::Arr(vec![
        s("jetscan:finding-id:v2"),
        s(area),
        s(rule_id),
        s(&location.relative_path),
        opt(&location.archive_entry),
        opt(&location.component),
        key,
    ]));
    let digest = hash::sha256(canonical.as_bytes());
    Ok(format!(
        "{area}/{}/{}",
        rule_segment(rule_id),
        hash::hex(&digest[..8])
    ))
}
fn escape_html(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}
fn obj<const N: usize>(pairs: [(&str, Json); N]) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
fn s(v: &str) -> Json {
    Json::Str(v.into())
}
fn opt(v: &Option<String>) -> Json {
    v.as_deref().map(s).unwrap_or(Json::Null)
}
fn strings(v: &[String]) -> Json {
    Json::Arr(v.iter().map(|v| s(v)).collect())
}
fn coordinate(v: Option<u32>) -> Json {
    v.map(|v| Json::Num(v as f64)).unwrap_or(Json::Null)
}
fn location_json(l: &SourceLocation) -> Json {
    obj([
        ("relative_path", s(&l.relative_path)),
        ("line", coordinate(l.line)),
        ("column", coordinate(l.column)),
        ("archive_entry", opt(&l.archive_entry)),
        ("component", opt(&l.component)),
    ])
}
pub(super) fn scan_json(scan: &ScanResultV2) -> Json {
    obj([
        ("schema_version", Json::Num(scan.schema_version as f64)),
        (
            "findings",
            Json::Arr(
                scan.findings
                    .iter()
                    .map(|f| {
                        obj([
                            ("id", s(&f.id)),
                            ("rule_id", s(&f.rule_id)),
                            ("title", s(&f.title)),
                            ("category", s(&f.category)),
                            (
                                "severity",
                                s(match f.severity {
                                    Severity::Critical => "critical",
                                    Severity::High => "high",
                                    Severity::Medium => "medium",
                                    Severity::Low => "low",
                                    Severity::Info => "info",
                                }),
                            ),
                            (
                                "confidence",
                                s(match f.confidence {
                                    Confidence::Confirmed => "confirmed",
                                    Confidence::Potential => "potential",
                                    Confidence::NeedsReview => "needs_review",
                                }),
                            ),
                            ("location", location_json(&f.location)),
                            (
                                "evidence",
                                obj([
                                    ("redacted_excerpt", opt(&f.evidence.redacted_excerpt)),
                                    ("fingerprint", opt(&f.evidence.fingerprint)),
                                ]),
                            ),
                            ("explanation", s(&f.explanation)),
                            ("remediation_id", opt(&f.remediation_id)),
                            ("references", strings(&f.references)),
                            ("cwe_ids", strings(&f.cwe_ids)),
                            ("tags", strings(&f.tags)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "checks",
            Json::Arr(
                scan.checks
                    .iter()
                    .map(|c| {
                        obj([
                            ("id", s(&c.id)),
                            (
                                "status",
                                s(match c.status {
                                    CheckStatus::Completed => "completed",
                                    CheckStatus::Partial => "partial",
                                    CheckStatus::Skipped => "skipped",
                                    CheckStatus::Error => "error",
                                }),
                            ),
                            ("reason", opt(&c.reason)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("limitations", strings(&scan.limitations)),
        ("network_activities", strings(&scan.network_activities)),
    ])
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub fn fixture() -> ScanResultV2 {
        ScanResultV2 {
            findings: vec![FindingV2 {
                id: "adapter-id".into(),
                rule_id: "FIXTURE-001".into(),
                title: "Possible issue".into(),
                category: "test".into(),
                severity: Severity::High,
                confidence: Confidence::Potential,
                location: SourceLocation {
                    relative_path: "src/пример.ts".into(),
                    line: Some(3),
                    column: Some(2),
                    archive_entry: None,
                    component: None,
                },
                evidence: Evidence::default(),
                explanation: "Static match only".into(),
                remediation_id: None,
                references: vec![],
                cwe_ids: vec![],
                tags: vec!["z".into(), "a".into()],
            }],
            checks: vec![RuleCheck {
                id: "FIXTURE-001".into(),
                status: CheckStatus::Completed,
                reason: None,
            }],
            ..ScanResultV2::default()
        }
    }
    #[test]
    fn output_and_debug_do_not_leak_known_or_detected_credentials() {
        let tokens = [
            format!("{}{}", "ghp_", "aB9cD8eF7gH6iJ5kL4mN3oP2qR1sT0uV9wX8"),
            format!("{}{}", "AKIA", "ZYXWVUTSRQPONMLK"),
            format!("{}{}", "sk_live_", "aB9cD8eF7gH6iJ5kL4mN3oP2"),
            ["unusual", "password"].join("-"),
            ["данные", "секрет"].join("-"),
        ];
        let policy = RedactionPolicy::new(tokens.iter().map(String::as_str));
        for token in &tokens {
            let mut scan = fixture();
            let f = &mut scan.findings[0];
            f.title = token.clone();
            f.explanation = token.clone();
            f.id = token.clone();
            f.evidence.redacted_excerpt = Some(token.clone());
            f.evidence.fingerprint = Some(token.clone());
            f.references = vec![token.clone()];
            f.tags = vec![token.clone()];
            f.cwe_ids = vec![token.clone()];
            f.remediation_id = Some(token.clone());
            f.location.component = Some(token.clone());
            f.location.archive_entry = Some(token.clone());
            f.location.relative_path = token.clone();
            f.rule_id = token.clone();
            scan.checks[0].id = token.clone();
            scan.checks[0].reason = Some(token.clone());
            scan.limitations.push(token.clone());
            scan.network_activities.push(token.clone());
            let safe = scan.redacted(&policy).unwrap();
            for output in [
                safe.render_json(),
                safe.render_text(),
                safe.render_html(),
                format!("{scan:?} {safe:?} {policy:?}"),
            ] {
                assert!(!output.contains(token), "sensitive field escaped redaction");
            }
        }
        for token in &tokens[..3] {
            assert_eq!(RedactionPolicy::default().text(token), "[redacted]");
        }
        let db = format!(
            "DATABASE_URL=postgres://user:{}@example.invalid/db",
            tokens[3]
        );
        assert_eq!(RedactionPolicy::default().text(&db), "[redacted]");
    }
    #[test]
    fn ordering_identity_and_escaping_are_stable() {
        let mut scan = fixture();
        scan.findings[0].title = "<script>\"&'\u{001b}\u{202e}".into();
        let policy = RedactionPolicy::default();
        let safe = scan.redacted(&policy).unwrap();
        assert!(!safe.render_html().contains("<script>"));
        assert!(safe.render_html().contains("&lt;script&gt;"));
        assert!(!safe.render_json().contains('\u{001b}'));
        assert!(json::parse(&safe.render_json()).is_ok());
        scan.findings.push(scan.findings[0].clone());
        scan.findings[0].tags.reverse();
        // Exact duplicates (same position too) are one occurrence, not two.
        assert_eq!(safe, scan.redacted(&policy).unwrap());
        let id = safe.as_scan().findings[0].id.clone();
        // "adapter-id" is malformed, so the id was computed in the fallback area.
        assert!(is_canonical_id(&id, "FIXTURE-001"));
        assert!(id.starts_with("f2/fixture-001/"));
        scan.findings.truncate(1);
        let id_of = |scan: &ScanResultV2| {
            scan.redacted(&policy).unwrap().as_scan().findings[0]
                .id
                .clone()
        };
        // Line/column-independent: survives code moving down/right.
        scan.findings[0].location.line = Some(40);
        scan.findings[0].location.column = Some(9);
        assert_eq!(id, id_of(&scan));
        scan.findings[0].location.line = None;
        scan.findings[0].location.column = None;
        assert_eq!(id, id_of(&scan));
        // Excerpt is the key when there is no fingerprint; whitespace is normalized.
        scan.findings[0].evidence.redacted_excerpt = Some("const  a =\t…".into());
        let with_excerpt = id_of(&scan);
        assert_ne!(id, with_excerpt);
        scan.findings[0].evidence.redacted_excerpt = Some(" const a = … ".into());
        assert_eq!(with_excerpt, id_of(&scan));
        // A core fingerprint replaces the excerpt as the key.
        scan.findings[0].evidence.fingerprint = Some("0123456789abcdef".into());
        let with_fp = id_of(&scan);
        scan.findings[0].evidence.redacted_excerpt = Some("other context".into());
        assert_eq!(with_fp, id_of(&scan));
        scan.findings[0].evidence.fingerprint = Some("fedcba9876543210".into());
        assert_ne!(with_fp, id_of(&scan));
        // Path, rule, archive entry and component each separate identities.
        let base = id_of(&scan);
        let mut other = scan.clone();
        other.findings[0].location.relative_path = "src/other.ts".into();
        assert_ne!(base, id_of(&other));
        let mut other = scan.clone();
        other.findings[0].location.component = Some("service .A".into());
        let a = id_of(&other);
        other.findings[0].location.component = Some("service .B".into());
        assert_ne!(a, id_of(&other));
        assert_ne!(base, a);
        let mut other = scan.clone();
        other.findings[0].location.archive_entry = Some("assets/a.json".into());
        assert_ne!(base, id_of(&other));
        let mut other = scan.clone();
        other.findings[0].rule_id = "FIXTURE-002".into();
        assert_ne!(base, id_of(&other));
    }
    #[test]
    fn scanner_ids_are_kept_and_only_malformed_ones_are_computed() {
        let policy = RedactionPolicy::new(["hunter2"]);
        let id_for = |id: &str| {
            let mut scan = fixture();
            scan.findings[0].id = id.into();
            scan.redacted(&policy).unwrap().as_scan().findings[0]
                .id
                .clone()
        };
        for kept in [
            "web/fixture-001/0123456789abcdef",
            "apk/fixture-001/ffffffffffffffff",
            "secrets-2/fixture-001/0000000000000000",
        ] {
            assert_eq!(id_for(kept), kept);
        }
        for (malformed, area) in [
            ("", "f2"),
            ("web/fixture-001/0123456789ABCDEF", "web"),
            ("web/FIXTURE-001/0123456789abcdef", "web"),
            ("web/fixture-002/0123456789abcdef", "web"),
            ("web/fixture-001/0123456789abcde", "web"),
            ("web/fixture-001/0123456789abcdef/x", "web"),
            ("Web/fixture-001/0123456789abcdef", "f2"),
            ("-web/fixture-001/0123456789abcdef", "f2"),
            ("web/pending", "web"),
            // A well-formed id whose text is sensitive is recomputed, not echoed.
            ("hunter2/fixture-001/0123456789abcdef", "f2"),
        ] {
            let id = id_for(malformed);
            assert_ne!(id, malformed);
            assert!(is_canonical_id(&id, "FIXTURE-001"));
            assert!(id.starts_with(&format!("{area}/fixture-001/")), "{id}");
        }
        assert_eq!(rule_segment("GHSA-x:y/Z"), "ghsa-x_y_z");
        assert_eq!(rule_segment(""), "_");
        assert_eq!(rule_segment("ПРАВИЛО"), "_______");
        assert_eq!(pending_id("deps"), "deps/pending");
    }
    #[test]
    fn only_core_fingerprints_survive_and_add_the_brute_force_limitation() {
        let core = secrets::fingerprint(&["weak", "pass"].join("-"));
        assert!(is_core_fingerprint(&core));
        let policy = RedactionPolicy::new(["fedcba9876543210"]);
        let fp_of = |fp: &str| {
            let mut scan = fixture();
            scan.findings[0].evidence.fingerprint = Some(fp.into());
            let safe = scan.redacted(&policy).unwrap();
            let fp = safe.as_scan().findings[0].evidence.fingerprint.clone();
            let noted = safe
                .as_scan()
                .limitations
                .contains(&FINGERPRINT_LIMITATION.to_string());
            assert_eq!(noted, fp.is_some());
            fp
        };
        assert_eq!(fp_of(&core).as_deref(), Some(core.as_str()));
        for dropped in [
            "",
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789abcdeg",
            " 0123456789abcde",
            "f2/0123456789abcdef",
            // Correct shape, but a known sensitive value: never echoed.
            "fedcba9876543210",
        ] {
            assert_eq!(fp_of(dropped), None, "{dropped:?}");
        }
        assert!(
            fixture()
                .redacted(&policy)
                .unwrap()
                .as_scan()
                .limitations
                .is_empty()
        );
    }
    #[test]
    fn same_id_on_different_lines_is_one_finding_with_a_count() {
        let policy = RedactionPolicy::default();
        let mut scan = fixture();
        scan.findings[0].id = "web/fixture-001/0123456789abcdef".into();
        scan.findings[0].evidence.fingerprint = Some("0123456789abcdef".into());
        let mut second = scan.findings[0].clone();
        second.location.line = Some(1);
        second.location.column = Some(7);
        second.evidence.redacted_excerpt = Some("different context".into());
        let mut third = scan.findings[0].clone();
        third.location.line = Some(90);
        scan.findings.push(second);
        scan.findings.push(third);
        let safe = scan.redacted(&policy).unwrap();
        let findings = &safe.as_scan().findings;
        assert_eq!(findings.len(), 1);
        // First location (lowest line) wins; its own excerpt goes with it.
        assert_eq!(findings[0].location.line, Some(1));
        assert_eq!(findings[0].location.column, Some(7));
        assert_eq!(
            findings[0].evidence.redacted_excerpt.as_deref(),
            Some("different context")
        );
        assert_eq!(findings[0].tags, ["a", "occurrences:3", "z"]);
        // Re-import is idempotent and counts accumulate across merges.
        assert_eq!(safe.as_scan().redacted(&policy).unwrap(), safe);
        let mut again = safe.as_scan().clone();
        again.findings.push(scan.findings[2].clone());
        let merged = again.redacted(&policy).unwrap();
        assert_eq!(
            merged.as_scan().findings[0].tags,
            ["a", "occurrences:4", "z"]
        );
        // A scanner id that leaves the component out of its key: the component
        // is a position inside the entry, so it merges like a line does.
        let mut parts = scan.clone();
        parts.findings.truncate(2);
        parts.findings[0].location.component = Some("resources/b@value".into());
        parts.findings[1].location.component = Some("resources/a@value".into());
        parts.findings[1].location.line = parts.findings[0].location.line;
        parts.findings[1].location.column = parts.findings[0].location.column;
        let merged = parts.redacted(&policy).unwrap();
        assert_eq!(merged.as_scan().findings.len(), 1);
        let f = &merged.as_scan().findings[0];
        assert_eq!(f.location.component.as_deref(), Some("resources/a@value"));
        assert!(f.tags.contains(&"occurrences:2".to_string()));
        // A forged non-canonical count is ignored as a count but kept as a tag.
        let mut odd = scan.clone();
        odd.findings.truncate(1);
        odd.findings[0].tags = vec!["occurrences:01".into(), "occurrences:1".into()];
        let tags = odd.redacted(&policy).unwrap().as_scan().findings[0]
            .tags
            .clone();
        assert_eq!(tags, ["occurrences:01", "occurrences:1"]);
    }
    #[test]
    fn refuses_conflicting_duplicates_without_strengthening_confidence() {
        let mut scan = fixture();
        scan.findings.push(scan.findings[0].clone());
        scan.findings[1].confidence = Confidence::Confirmed;
        assert_eq!(
            scan.redacted(&RedactionPolicy::default()),
            Err(ModelError("conflicting_finding_id"))
        );
        // Same id, different line AND different severity: still a conflict.
        scan.findings[1].confidence = Confidence::Potential;
        scan.findings[1].severity = Severity::Low;
        scan.findings[1].location.line = Some(9);
        assert_eq!(
            scan.redacted(&RedactionPolicy::default()),
            Err(ModelError("conflicting_finding_id"))
        );
        scan.findings[1].severity = Severity::High;
        scan.findings[1].title = "Another title".into();
        assert_eq!(
            scan.redacted(&RedactionPolicy::default()),
            Err(ModelError("conflicting_finding_id"))
        );
        scan.findings.pop();
        scan.checks.push(scan.checks[0].clone());
        scan.checks[1].status = CheckStatus::Partial;
        scan.checks[1].reason = Some("limit".into());
        assert_eq!(
            scan.redacted(&RedactionPolicy::default()),
            Err(ModelError("conflicting_check_id"))
        );
    }
}
