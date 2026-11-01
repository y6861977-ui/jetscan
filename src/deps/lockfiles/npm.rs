//! `package-lock.json` / `npm-shrinkwrap.json` (v1, v2, v3). Порт из `seed/audit.rs`.

use crate::deps::Dep;
use crate::json::{self, Json};
use std::collections::HashMap;

pub fn parse_package_lock(text: &str) -> Result<Vec<Dep>, String> {
    let doc = json::parse(text).map_err(|e| format!("not valid JSON: {e}"))?;
    if doc.as_object().is_none() {
        return Err("not a package-lock object".to_string());
    }
    let mut out = Vec::new();

    // v2/v3: { "packages": { "": {root}, "node_modules/a": {...},
    //          "node_modules/a/node_modules/@s/b": {...}, "packages/ws": {workspace} } }
    if let Some(pkgs) = doc.get("packages").and_then(Json::as_object) {
        for (path, entry) in pkgs {
            // Только установленное в node_modules: "" — корень, "packages/ws" — workspace
            // (локальный код, в OSV его нет; в seed он ошибочно становился пакетом).
            let Some(idx) = path.rfind("node_modules/") else {
                continue;
            };
            if entry.get("link").and_then(Json::as_bool) == Some(true) {
                continue; // симлинк на workspace
            }
            let Some(version) = entry.get("version").and_then(Json::as_str) else {
                continue;
            };
            // Алиас `"x": "npm:real@1.0.0"` — в OSV искать настоящее имя.
            let name = entry
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or(&path[idx + "node_modules/".len()..]);
            push(&mut out, name, version);
        }
        return Ok(out);
    }

    // v1: { "dependencies": { "a": { "version": "1.0.0", "dependencies": {...} } } }
    if let Some(deps) = doc.get("dependencies").and_then(Json::as_object) {
        collect_v1(deps, &mut out, 0);
        return Ok(out);
    }
    // Ни `packages`, ни `dependencies` — проект без зависимостей (так бывает).
    Ok(out)
}

fn collect_v1(deps: &HashMap<String, Json>, out: &mut Vec<Dep>, depth: usize) {
    if depth > 64 {
        return; // защита от патологической вложенности
    }
    for (name, entry) in deps {
        if let Some(version) = entry.get("version").and_then(Json::as_str) {
            // v1-алиас: "version": "npm:real@1.0.0".
            match version
                .strip_prefix("npm:")
                .and_then(|v| v.rsplit_once('@'))
            {
                Some((real, v)) => push(out, real, v),
                None => push(out, name, version),
            }
        }
        if let Some(nested) = entry.get("dependencies").and_then(Json::as_object) {
            collect_v1(nested, out, depth + 1);
        }
    }
}

/// Только версии из реестра: `file:`, `git+...`, `https://...tgz` в OSV не найти.
fn push(out: &mut Vec<Dep>, name: &str, version: &str) {
    if name.is_empty() || version.is_empty() || version.contains(':') || version.contains('/') {
        return;
    }
    out.push(Dep {
        name: name.to_string(),
        version: version.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(mut v: Vec<Dep>) -> Vec<(String, String)> {
        v.sort();
        v.into_iter().map(|d| (d.name, d.version)).collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn v3_installed_packages_only() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "packages/ws": {"name": "ws-local", "version": "0.1.0"},
            "node_modules/ws-local": {"resolved": "packages/ws", "link": true},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/@scope/b": {"version": "2.0.0"},
            "node_modules/alias": {"name": "real-pkg", "version": "3.1.0"},
            "node_modules/local": {"version": "file:../local"}
          }
        }"#;
        assert_eq!(
            sorted(parse_package_lock(text).unwrap()),
            pairs(&[
                ("@scope/b", "2.0.0"),
                ("lodash", "4.17.20"),
                ("real-pkg", "3.1.0")
            ])
        );
    }

    #[test]
    fn v1_nested_dependencies_and_aliases() {
        let text = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            "al": {"version": "npm:real@4.0.0"},
            "g": {"version": "git+https://github.com/x/y.git#abc"}
          }
        }"#;
        assert_eq!(
            sorted(parse_package_lock(text).unwrap()),
            pairs(&[("a", "1.0.0"), ("b", "2.0.0"), ("real", "4.0.0")])
        );
    }

    #[test]
    fn broken_file_is_an_error_not_empty() {
        assert!(parse_package_lock("{ nope").is_err());
        assert!(parse_package_lock("[]").is_err());
        assert_eq!(
            parse_package_lock(r#"{"lockfileVersion":3}"#).unwrap(),
            vec![]
        );
    }
}
