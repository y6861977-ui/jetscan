//! Strict bounded V2 import using the existing JSON parser, never its errors.
use super::*;
use crate::json::{self, Json};
use std::collections::{HashMap, HashSet};

pub(super) const MAX_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 24;
const MAX_STRING: usize = 16 * 1024;
const MAX_ITEMS: usize = 10_000;
const BAD: ModelError = ModelError("invalid_v2_json");

/// Unknown fields, duplicate keys, noncanonical IDs and unsupported versions fail
/// closed. Imported text is untrusted and is redacted again before returning.
pub fn parse(input: &str, policy: &RedactionPolicy<'_>) -> Result<RedactedScan, ModelError> {
    guard(input)?;
    let json = json::parse(input).map_err(|_| BAD)?;
    let o = object(
        &json,
        &[
            "schema_version",
            "findings",
            "checks",
            "limitations",
            "network_activities",
        ],
    )?;
    if number(field(o, "schema_version")?)? != SCHEMA_VERSION {
        return Err(ModelError("unsupported_schema_version"));
    }
    let scan = ScanResultV2 {
        schema_version: SCHEMA_VERSION,
        findings: array(field(o, "findings")?)?
            .iter()
            .map(finding)
            .collect::<Result<_, _>>()?,
        checks: array(field(o, "checks")?)?
            .iter()
            .map(check)
            .collect::<Result<_, _>>()?,
        limitations: strings(field(o, "limitations")?)?,
        network_activities: strings(field(o, "network_activities")?)?,
    };
    // Our exporter only writes canonical ids, core fingerprints and one entry
    // per id (same-id occurrences are already merged), so anything else is
    // refused instead of silently normalized.
    for f in &scan.findings {
        if !output::is_canonical_id(&f.id, &f.rule_id) {
            return Err(ModelError("noncanonical_finding_id"));
        }
        if f.evidence
            .fingerprint
            .as_deref()
            .is_some_and(|fp| !output::is_core_fingerprint(fp))
        {
            return Err(ModelError("noncanonical_fingerprint"));
        }
    }
    let mut unique: Vec<&FindingV2> = scan.findings.iter().collect();
    unique.sort();
    unique.dedup();
    if unique.windows(2).any(|w| w[0].id == w[1].id) {
        return Err(ModelError("conflicting_finding_id"));
    }
    scan.redacted(policy)
}
fn object<'a>(v: &'a Json, keys: &[&str]) -> Result<&'a HashMap<String, Json>, ModelError> {
    let o = v.as_object().ok_or(BAD)?;
    if o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(ModelError("unexpected_or_missing_field"));
    }
    Ok(o)
}
fn field<'a>(o: &'a HashMap<String, Json>, key: &str) -> Result<&'a Json, ModelError> {
    o.get(key).ok_or(BAD)
}
fn string(v: &Json) -> Result<String, ModelError> {
    v.as_str()
        .filter(|s| s.len() <= MAX_STRING)
        .map(str::to_owned)
        .ok_or(BAD)
}
fn optional(v: &Json) -> Result<Option<String>, ModelError> {
    if matches!(v, Json::Null) {
        Ok(None)
    } else {
        string(v).map(Some)
    }
}
fn array(v: &Json) -> Result<&[Json], ModelError> {
    v.as_array().filter(|a| a.len() <= MAX_ITEMS).ok_or(BAD)
}
fn strings(v: &Json) -> Result<Vec<String>, ModelError> {
    array(v)?.iter().map(string).collect()
}
fn number(v: &Json) -> Result<u32, ModelError> {
    let n = v.as_f64().ok_or(BAD)?;
    if !n.is_finite() || n < 0.0 || n > u32::MAX as f64 || n.fract() != 0.0 {
        return Err(BAD);
    }
    Ok(n as u32)
}
fn coordinate(v: &Json) -> Result<Option<u32>, ModelError> {
    if matches!(v, Json::Null) {
        Ok(None)
    } else {
        number(v).map(Some)
    }
}
fn location(v: &Json) -> Result<SourceLocation, ModelError> {
    let o = object(
        v,
        &[
            "relative_path",
            "line",
            "column",
            "archive_entry",
            "component",
        ],
    )?;
    Ok(SourceLocation {
        relative_path: string(field(o, "relative_path")?)?,
        line: coordinate(field(o, "line")?)?,
        column: coordinate(field(o, "column")?)?,
        archive_entry: optional(field(o, "archive_entry")?)?,
        component: optional(field(o, "component")?)?,
    })
}
fn finding(v: &Json) -> Result<FindingV2, ModelError> {
    let o = object(
        v,
        &[
            "id",
            "rule_id",
            "title",
            "category",
            "severity",
            "confidence",
            "location",
            "evidence",
            "explanation",
            "remediation_id",
            "references",
            "cwe_ids",
            "tags",
        ],
    )?;
    let e = object(field(o, "evidence")?, &["redacted_excerpt", "fingerprint"])?;
    Ok(FindingV2 {
        id: string(field(o, "id")?)?,
        rule_id: string(field(o, "rule_id")?)?,
        title: string(field(o, "title")?)?,
        category: string(field(o, "category")?)?,
        severity: match field(o, "severity")?.as_str() {
            Some("critical") => Severity::Critical,
            Some("high") => Severity::High,
            Some("medium") => Severity::Medium,
            Some("low") => Severity::Low,
            Some("info") => Severity::Info,
            _ => return Err(BAD),
        },
        confidence: match field(o, "confidence")?.as_str() {
            Some("confirmed") => Confidence::Confirmed,
            Some("potential") => Confidence::Potential,
            Some("needs_review") => Confidence::NeedsReview,
            _ => return Err(BAD),
        },
        location: location(field(o, "location")?)?,
        evidence: Evidence {
            redacted_excerpt: optional(field(e, "redacted_excerpt")?)?,
            fingerprint: optional(field(e, "fingerprint")?)?,
        },
        explanation: string(field(o, "explanation")?)?,
        remediation_id: optional(field(o, "remediation_id")?)?,
        references: strings(field(o, "references")?)?,
        cwe_ids: strings(field(o, "cwe_ids")?)?,
        tags: strings(field(o, "tags")?)?,
    })
}
fn check(v: &Json) -> Result<RuleCheck, ModelError> {
    let o = object(v, &["id", "status", "reason"])?;
    Ok(RuleCheck {
        id: string(field(o, "id")?)?,
        reason: optional(field(o, "reason")?)?,
        status: match field(o, "status")?.as_str() {
            Some("completed") => CheckStatus::Completed,
            Some("partial") => CheckStatus::Partial,
            Some("skipped") => CheckStatus::Skipped,
            Some("error") => CheckStatus::Error,
            _ => return Err(BAD),
        },
    })
}

// Iterative lexical safety guard, not a replacement JSON grammar/parser. Bounds
// recursion, rejects duplicate decoded keys and validates escapes/surrogates
// before handing input to the existing general-purpose parser.
fn guard(input: &str) -> Result<(), ModelError> {
    if input.len() > MAX_BYTES {
        return Err(ModelError("v2_input_limit"));
    }
    let bytes = input.as_bytes();
    let mut stack: Vec<(u8, HashSet<String>)> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let start = i;
                i = string_end(bytes, i)?;
                if i - start > MAX_STRING * 6 + 2 {
                    return Err(ModelError("v2_string_limit"));
                }
                let mut next = i;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b':') {
                    let key = json::parse(&input[start..i]).map_err(|_| BAD)?;
                    let (kind, keys) = stack.last_mut().ok_or(BAD)?;
                    if *kind != b'{' || !keys.insert(string(&key)?) {
                        return Err(ModelError("duplicate_or_invalid_key"));
                    }
                }
                continue;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while bytes
                    .get(i)
                    .is_some_and(|b| !b.is_ascii_whitespace() && !b",]}".contains(b))
                {
                    i += 1;
                }
                let token = &bytes[start..i];
                // This schema has only unsigned integer numbers. Restrict their
                // lexical spelling too, avoiding f64 rounding and loose syntax.
                if token.len() > 10
                    || !token.iter().all(u8::is_ascii_digit)
                    || (token.len() > 1 && token[0] == b'0')
                {
                    return Err(BAD);
                }
                continue;
            }
            b'{' | b'[' => {
                if stack.len() >= MAX_DEPTH {
                    return Err(ModelError("v2_depth_limit"));
                }
                stack.push((bytes[i], HashSet::new()));
            }
            b'}' | b']' => {
                let (open, _) = stack.pop().ok_or(BAD)?;
                if (open == b'{') != (bytes[i] == b'}') {
                    return Err(BAD);
                }
            }
            _ => {}
        }
        i += 1;
    }
    if !stack.is_empty() {
        return Err(BAD);
    }
    Ok(())
}
fn hex4(bytes: &[u8], i: usize) -> Result<u32, ModelError> {
    let chars = bytes.get(i..i + 4).ok_or(BAD)?;
    chars.iter().try_fold(0, |n, b| {
        (*b as char).to_digit(16).map(|d| n * 16 + d).ok_or(BAD)
    })
}
fn string_end(bytes: &[u8], start: usize) -> Result<usize, ModelError> {
    let mut i = start + 1;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => return Ok(i + 1),
            0..=31 => return Err(BAD),
            b'\\' => {
                i += 1;
                match bytes.get(i).ok_or(BAD)? {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 1,
                    b'u' => {
                        let high = hex4(bytes, i + 1)?;
                        i += 5;
                        if (0xD800..=0xDBFF).contains(&high) {
                            if bytes.get(i..i + 2) != Some(b"\\u") {
                                return Err(BAD);
                            }
                            let low = hex4(bytes, i + 2)?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(BAD);
                            }
                            i += 6;
                        } else if (0xDC00..=0xDFFF).contains(&high) {
                            return Err(BAD);
                        }
                    }
                    _ => return Err(BAD),
                }
                continue;
            }
            _ => i += 1,
        }
    }
    Err(BAD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use output::tests::fixture;
    fn exported() -> RedactedScan {
        fixture().redacted(&RedactionPolicy::default()).unwrap()
    }
    #[test]
    fn exact_roundtrip_and_independent_severity_confidence() {
        let policy = RedactionPolicy::default();
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            for confidence in [
                Confidence::Confirmed,
                Confidence::Potential,
                Confidence::NeedsReview,
            ] {
                let mut scan = fixture();
                scan.findings[0].severity = severity;
                scan.findings[0].confidence = confidence;
                let safe = scan.redacted(&policy).unwrap();
                let decoded = parse(&safe.render_json(), &policy).unwrap();
                assert_eq!(safe, decoded);
                assert_eq!(decoded.as_scan().findings[0].severity, severity);
                assert_eq!(decoded.as_scan().findings[0].confidence, confidence);
            }
        }
    }
    #[test]
    fn every_coverage_status_roundtrips_without_false_completion() {
        for status in [
            CheckStatus::Completed,
            CheckStatus::Partial,
            CheckStatus::Skipped,
            CheckStatus::Error,
        ] {
            let mut scan = fixture();
            scan.checks[0].status = status;
            scan.checks[0].reason = Some("fixture coverage".into());
            let safe = scan.redacted(&RedactionPolicy::default()).unwrap();
            let decoded = parse(&safe.render_json(), &RedactionPolicy::default()).unwrap();
            assert_eq!(
                decoded.as_scan().completed(),
                matches!(status, CheckStatus::Completed | CheckStatus::Skipped)
            );
            assert_eq!(decoded.as_scan().checks[0].status, status);
        }
    }
    #[test]
    fn strict_versions_unknown_fields_types_and_identifiers() {
        let source = exported().render_json();
        let policy = RedactionPolicy::default();
        for version in [
            "1",
            "3",
            "-1",
            "2.5",
            "null",
            "\"2\"",
            "1e999",
            "02",
            "2.",
            "2.00000000000000001",
        ] {
            let input = source.replace(
                "\"schema_version\": 2",
                &format!("\"schema_version\": {version}"),
            );
            assert!(parse(&input, &policy).is_err());
        }
        for input in [
            source.replacen('{', "{\"future\":true,", 1),
            source.replace("\"line\": 3", "\"line\": 0"),
            source.replace("\"line\": 3", "\"line\": 4294967296"),
            source.replace("\"confidence\": \"potential\"", "\"confidence\": \"high\""),
            source.replace("\"component\": null", "\"component\": null,\"future\":true"),
            source.replace("f2/fixture-001/", "f2/FIXTURE-001/"),
            source.replace("f2/fixture-001/", "F2/fixture-001/"),
            source.replace("f2/fixture-001/", "f2/other-001/"),
            source.replace("f2/fixture-001/", "f2/fixture-001/0/"),
            source.replace(
                "\"fingerprint\": null",
                "\"fingerprint\": \"0123456789ABCDEF\"",
            ),
            source.replace("\"fingerprint\": null", "\"fingerprint\": \"raw-secret\""),
        ] {
            assert!(parse(&input, &policy).is_err());
        }
        // Scanner areas are not ours to forge-check: a well-formed id from any
        // area is kept, and a core fingerprint roundtrips (with its limitation).
        let id = exported().as_scan().findings[0].id.clone();
        let forged = id.replace("f2/", "web/");
        let decoded = parse(&source.replace(&id, &forged), &policy).unwrap();
        assert_eq!(decoded.as_scan().findings[0].id, forged);
        let with_fp = source.replace(
            "\"fingerprint\": null",
            "\"fingerprint\": \"0123456789abcdef\"",
        );
        let decoded = parse(&with_fp, &policy).unwrap();
        assert_eq!(
            decoded.as_scan().findings[0]
                .evidence
                .fingerprint
                .as_deref(),
            Some("0123456789abcdef")
        );
        assert_eq!(
            parse(&decoded.render_json(), &policy).unwrap(),
            decoded,
            "fingerprint + limitation must roundtrip exactly"
        );
        let mut invalid = fixture();
        invalid.schema_version = 1;
        assert!(invalid.redacted(&policy).is_err());
    }
    #[test]
    fn malicious_json_cannot_panic_or_smuggle_duplicate_keys() {
        let policy = RedactionPolicy::default();
        for input in [
            r#"{"schema_version":2,"schema_version":2}"#,
            r#"{"a":0,"\u0061":1}"#,
            r#"{"x":"\uD800\u0000"}"#,
            r#"{"x":"\uD800"}"#,
            r#"{"x":"\uDC00"}"#,
            r#"{"x":"\q"}"#,
            "{\"x\":\"\n\"}",
            "[[[}",
        ] {
            assert!(parse(input, &policy).is_err());
        }
        assert!(guard(r#"{"x":"\uD83D\uDE00"}"#).is_ok());
        assert!(parse(&"[".repeat(100_000), &policy).is_err());
        assert!(parse(&" ".repeat(MAX_BYTES + 1), &policy).is_err());
        let valid = exported().render_json();
        for (end, _) in valid.char_indices().filter(|(end, _)| *end > 0) {
            assert!(parse(&valid[..end], &policy).is_err());
        }
    }
    #[test]
    fn import_redacts_again_and_rejects_conflicting_duplicates() {
        let policy = RedactionPolicy::default();
        let safe = exported();
        let raw = format!("{}{}", "ghp_", "aB9cD8eF7gH6iJ5kL4mN3oP2qR1sT0uV9wX8");
        let input = safe.render_json().replace("Possible issue", &raw);
        let decoded = parse(&input, &policy).unwrap();
        assert!(!decoded.render_json().contains(&raw));
        let mut doc = safe.to_json();
        if let Json::Obj(o) = &mut doc
            && let Json::Arr(findings) = o.get_mut("findings").unwrap()
        {
            findings.push(findings[0].clone());
        }
        assert_eq!(parse(&json::stringify(&doc), &policy).unwrap(), safe);
        if let Json::Obj(o) = &mut doc
            && let Json::Arr(findings) = o.get_mut("findings").unwrap()
            && let Json::Obj(f) = &mut findings[1]
        {
            f.insert("confidence".into(), Json::Str("confirmed".into()));
        }
        assert_eq!(
            parse(&json::stringify(&doc), &policy),
            Err(ModelError("conflicting_finding_id"))
        );
        // The exporter merges same-id occurrences, so an unmerged pair (same id,
        // other line) is not something we wrote: refused on import.
        if let Json::Obj(o) = &mut doc
            && let Json::Arr(findings) = o.get_mut("findings").unwrap()
            && let Json::Obj(f) = &mut findings[1]
        {
            f.insert("confidence".into(), Json::Str("potential".into()));
            if let Some(Json::Obj(l)) = f.get_mut("location") {
                l.insert("line".into(), Json::Num(77.0));
            }
        }
        assert_eq!(
            parse(&json::stringify(&doc), &policy),
            Err(ModelError("conflicting_finding_id"))
        );
    }

    #[test]
    fn model_and_wire_limits_preserve_roundtrip() {
        let policy = RedactionPolicy::default();
        let mut scan = fixture();
        scan.findings[0].title = "\\".repeat(MAX_STRING);
        let safe = scan.redacted(&policy).unwrap();
        assert_eq!(parse(&safe.render_json(), &policy).unwrap(), safe);
        scan.findings[0].title.push('x');
        assert_eq!(scan.redacted(&policy), Err(ModelError("v2_model_limit")));
        let mut scan = fixture();
        scan.limitations = vec![String::new(); MAX_ITEMS + 1];
        assert_eq!(scan.redacted(&policy), Err(ModelError("v2_model_limit")));
    }
}
