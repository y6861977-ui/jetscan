//! SPDX 2.3 JSON. Обязательная дата — SOURCE_DATE_EPOCH или фиксированная эпоха
//! 1970-01-01, а не время запуска. Namespace — SHA-256 документа без namespace.

use super::cyclonedx::source_date_epoch;
use super::purl::purl;
use crate::deps::scan::DepsReport;
use crate::hash;
use crate::json::{self, Json};
use std::path::Path;

pub fn render(r: &DepsReport) -> Result<String, String> {
    let created = source_date_epoch()?.unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
    Ok(render_with_created(r, created))
}

fn render_with_created(r: &DepsReport, created: String) -> String {
    let mut packages = Vec::with_capacity(r.packages.len());
    let mut relationships = Vec::with_capacity(r.packages.len());
    for (index, p) in r.packages.iter().enumerate() {
        let id = format!("SPDXRef-Package-{}", index + 1);
        packages.push(obj(vec![
            ("SPDXID", Json::Str(id.clone())),
            ("name", Json::Str(p.name.clone())),
            ("versionInfo", Json::Str(p.version.clone())),
            ("downloadLocation", Json::Str("NOASSERTION".into())),
            // No file analysis: no verification code or licenseInfoFromFiles.
            ("filesAnalyzed", Json::Bool(false)),
            ("licenseConcluded", Json::Str("NOASSERTION".into())),
            ("licenseDeclared", Json::Str("NOASSERTION".into())),
            ("copyrightText", Json::Str("NOASSERTION".into())),
            (
                "externalRefs",
                Json::Arr(vec![obj(vec![
                    ("referenceCategory", Json::Str("PACKAGE-MANAGER".into())),
                    ("referenceType", Json::Str("purl".into())),
                    ("referenceLocator", Json::Str(purl(p))),
                ])]),
            ),
        ]));
        relationships.push(obj(vec![
            ("spdxElementId", Json::Str("SPDXRef-DOCUMENT".into())),
            ("relationshipType", Json::Str("DESCRIBES".into())),
            ("relatedSpdxElement", Json::Str(id)),
        ]));
    }
    let mut document = obj(vec![
        ("spdxVersion", Json::Str("SPDX-2.3".into())),
        ("dataLicense", Json::Str("CC0-1.0".into())),
        ("SPDXID", Json::Str("SPDXRef-DOCUMENT".into())),
        ("name", Json::Str(project_name(&r.root))),
        (
            "creationInfo",
            obj(vec![
                (
                    "creators",
                    Json::Arr(vec![Json::Str(format!(
                        "Tool: jetscan-{}",
                        env!("CARGO_PKG_VERSION")
                    ))]),
                ),
                ("created", Json::Str(created)),
            ]),
        ),
        ("packages", Json::Arr(packages)),
        ("relationships", Json::Arr(relationships)),
    ]);
    let digest = hash::hex(&hash::sha256(json::stringify_pretty(&document).as_bytes()));
    if let Json::Obj(fields) = &mut document {
        fields.insert(
            "documentNamespace".into(),
            Json::Str(format!("https://jetscan.invalid/spdx/{digest}")),
        );
    }
    json::stringify_pretty(&document)
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn project_name(root: &Path) -> String {
    // Accept both path separators even when rendering a report from another OS.
    // Do not canonicalize: filesystem access would make rendering non-reproducible.
    root.to_string_lossy()
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty() && *name != "." && *name != ".." && !name.ends_with(':'))
        .unwrap_or("project")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::scan::LockfileReport;
    use crate::deps::{Ecosystem, Package};

    fn report() -> DepsReport {
        DepsReport {
            root: r"C:\Users\private\my-project".into(),
            lockfiles: vec![LockfileReport {
                rel: "/private/do-not-export/Cargo.lock".into(),
                label: "Cargo.lock",
                ecosystem: Ecosystem::CratesIo,
                packages: 1,
                error: Some("/private/do-not-export/error".into()),
            }],
            packages: vec![
                Package {
                    ecosystem: Ecosystem::Npm,
                    name: "@scope/name".into(),
                    version: "1.0.0".into(),
                    lockfiles: vec!["/private/do-not-export/package-lock.json".into()],
                },
                Package {
                    ecosystem: Ecosystem::CratesIo,
                    name: "example".into(),
                    version: "2.0.0".into(),
                    lockfiles: vec!["Cargo.lock".into()],
                },
            ],
            findings: vec![],
            unchecked: vec![],
            from_cache: 0,
            fresh: 2,
            stale_cache_age: None,
            osv_unavailable: false,
            offline: false,
            warnings: vec!["/private/do-not-export/warning".into()],
            install_scripts: vec![],
            typosquats: vec![],
        }
    }

    fn render_epoch(r: &DepsReport) -> String {
        render_with_created(r, "1970-01-01T00:00:00Z".into())
    }

    fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
        value.get(key).unwrap().as_array().unwrap()
    }

    #[test]
    fn document_packages_relationships_and_determinism() {
        let r = report();
        let output = render_epoch(&r);
        assert_eq!(output, render_epoch(&r));
        assert!(!output.contains("private"));
        assert!(!output.contains("do-not-export"));
        let doc = json::parse(&output).unwrap();
        for (key, expected) in [
            ("spdxVersion", "SPDX-2.3"),
            ("dataLicense", "CC0-1.0"),
            ("SPDXID", "SPDXRef-DOCUMENT"),
            ("name", "my-project"),
        ] {
            assert_eq!(doc.get(key).and_then(Json::as_str), Some(expected));
        }
        let creation = doc.get("creationInfo").unwrap();
        assert_eq!(
            creation.get("created").and_then(Json::as_str),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            array(creation, "creators"),
            [Json::Str(format!(
                "Tool: jetscan-{}",
                env!("CARGO_PKG_VERSION")
            ))]
        );
        let packages = array(&doc, "packages");
        let relationships = array(&doc, "relationships");
        assert_eq!(packages.len(), r.packages.len());
        assert_eq!(relationships.len(), packages.len());
        for (i, package) in packages.iter().enumerate() {
            assert_eq!(
                package.get("SPDXID"),
                Some(&Json::Str(format!("SPDXRef-Package-{}", i + 1)))
            );
            assert_eq!(
                package.get("name").and_then(Json::as_str),
                Some(r.packages[i].name.as_str())
            );
            assert_eq!(
                package.get("versionInfo").and_then(Json::as_str),
                Some(r.packages[i].version.as_str())
            );
            assert_eq!(
                package.get("filesAnalyzed").and_then(Json::as_bool),
                Some(false)
            );
            for field in [
                "downloadLocation",
                "licenseConcluded",
                "licenseDeclared",
                "copyrightText",
            ] {
                assert_eq!(
                    package.get(field).and_then(Json::as_str),
                    Some("NOASSERTION")
                );
            }
            let refs = array(package, "externalRefs");
            assert_eq!(refs.len(), 1);
            assert_eq!(
                refs[0].get("referenceCategory").and_then(Json::as_str),
                Some("PACKAGE-MANAGER")
            );
            assert_eq!(
                refs[0].get("referenceType").and_then(Json::as_str),
                Some("purl")
            );
            assert_eq!(
                refs[0].get("referenceLocator"),
                Some(&Json::Str(purl(&r.packages[i])))
            );
            assert_eq!(
                relationships[i].get("spdxElementId").and_then(Json::as_str),
                Some("SPDXRef-DOCUMENT")
            );
            assert_eq!(
                relationships[i]
                    .get("relationshipType")
                    .and_then(Json::as_str),
                Some("DESCRIBES")
            );
            assert_eq!(
                relationships[i].get("relatedSpdxElement"),
                package.get("SPDXID")
            );
        }
    }

    #[test]
    fn namespace_hashes_content_and_ignores_parent_paths() {
        let mut r = report();
        let output = render_epoch(&r);
        r.root = "/another/parent/my-project/".into();
        r.packages[0].lockfiles.clear();
        assert_eq!(output, render_epoch(&r));
        let mut doc = json::parse(&output).unwrap();
        let namespace = if let Json::Obj(fields) = &mut doc {
            fields.remove("documentNamespace").unwrap()
        } else {
            panic!("document must be an object");
        };
        let digest = hash::hex(&hash::sha256(json::stringify_pretty(&doc).as_bytes()));
        assert_eq!(
            namespace,
            Json::Str(format!("https://jetscan.invalid/spdx/{digest}"))
        );
        assert_eq!(digest.len(), 64);
        r.packages[0].version = "1.0.1".into();
        let changed = json::parse(&render_epoch(&r)).unwrap();
        assert_ne!(changed.get("documentNamespace"), Some(&namespace));
        let dated = json::parse(&render_with_created(&r, "2024-02-29T12:34:56Z".into())).unwrap();
        assert_ne!(
            dated.get("documentNamespace"),
            changed.get("documentNamespace")
        );
    }

    #[test]
    fn root_names_and_empty_report() {
        for (path, expected) in [
            ("/home/private/project/", "project"),
            (r"C:\Users\private\project\", "project"),
            (r"\\server\share\project", "project"),
            ("relative/project", "project"),
            ("/home/private/проект", "проект"),
            ("/", "project"),
            (r"C:\", "project"),
            (".", "project"),
            ("..", "project"),
            ("", "project"),
        ] {
            assert_eq!(project_name(Path::new(path)), expected);
        }
        let mut r = report();
        r.packages.clear();
        let doc = json::parse(&render_epoch(&r)).unwrap();
        assert!(array(&doc, "packages").is_empty());
        assert!(array(&doc, "relationships").is_empty());
    }
}
