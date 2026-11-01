//! Python (PyPI): exact pins from requirements, Poetry, Pipenv and uv.
//!
//! - `requirements*.txt`: только точные пины `name==1.2.3` (с extras `name[x]==`,
//!   маркерами `; python_version<...`, хэшами `--hash=...`, продолжениями строк `\`).
//!   Диапазоны (`>=`, `~=`), `-r`/`-e`/URL — пропускать.
//! - `poetry.lock`, `uv.lock`: `[[package]]` name/version (uv: без `source = { editable/path }`).
//! - `Pipfile.lock`: JSON, секции `default` и `develop`, `"version": "==1.2.3"`.
//!
//! Names are normalized with `deps::pep503`, as required by T2.2.
//! Markers are not evaluated against the scanner's own Python/platform.

use super::cargo::toml;
use crate::deps::{Dep, pep503};
use crate::json;

pub fn parse_requirements(text: &str) -> Result<Vec<Dep>, String> {
    let mut out = Vec::new();
    let mut logical = String::new();
    let mut continued = false;
    let mut start = 1;
    for (index, line) in text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .enumerate()
    {
        if logical.is_empty() && !continued {
            start = index + 1;
        }
        let line = requirement_comment(line).trim_end();
        if line.trim().is_empty() {
            continue;
        }
        continued = line.ends_with('\\');
        logical.push_str(if continued {
            &line[..line.len() - 1]
        } else {
            line
        });
        if continued {
            continue;
        }
        if let Some(dep) =
            requirement(&logical).map_err(|e| format!("requirements.txt line {start}: {e}"))?
        {
            out.push(dep);
        }
        logical.clear();
    }
    if continued {
        return Err(format!(
            "requirements.txt line {start}: unfinished line continuation"
        ));
    }
    Ok(out)
}

pub fn parse_poetry_lock(text: &str) -> Result<Vec<Dep>, String> {
    parse_toml(text, false).map_err(|e| format!("poetry.lock: {e}"))
}

pub fn parse_pipfile_lock(text: &str) -> Result<Vec<Dep>, String> {
    // Bound untrusted input before calling the recursive shared JSON parser.
    json_depth(text)?;
    let doc = json::parse(text).map_err(|e| format!("Pipfile.lock: invalid JSON: {e}"))?;
    let root = doc
        .as_object()
        .ok_or("Pipfile.lock: expected a JSON object")?;
    let mut found = false;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        let Some(entries) = root.get(section) else {
            continue;
        };
        found = true;
        let entries = entries
            .as_object()
            .ok_or_else(|| format!("Pipfile.lock: {section} must be an object"))?;
        // Json objects are HashMaps; keep parser output deterministic.
        let mut names: Vec<_> = entries.keys().collect();
        names.sort();
        for name in names {
            validate_name(name)?;
            let entry = entries[name]
                .as_object()
                .ok_or("Pipfile.lock: package entry must be an object")?;
            if ["git", "path", "file", "url", "workspace"]
                .iter()
                .any(|key| entry.contains_key(*key))
                || entry.get("editable").and_then(crate::json::Json::as_bool) == Some(true)
            {
                continue;
            }
            let Some(version) = entry.get("version") else {
                continue;
            };
            let version = version
                .as_str()
                .ok_or("Pipfile.lock: version must be a string")?;
            if let Some(version) = pin(version)? {
                out.push(Dep {
                    name: pep503(name),
                    version: version.into(),
                });
            }
        }
    }
    if !found {
        return Err("Pipfile.lock: missing default/develop sections".into());
    }
    Ok(out)
}

pub fn parse_uv_lock(text: &str) -> Result<Vec<Dep>, String> {
    parse_toml(text, true).map_err(|e| format!("uv.lock: {e}"))
}

fn parse_toml(text: &str, uv: bool) -> Result<Vec<Dep>, String> {
    let doc = toml::parse(text)?;
    let mut out = Vec::new();
    for package in toml::packages(&doc)? {
        let name = toml::required_string(package, "name")?;
        validate_name(name)?;
        let source = package.get("source").map(toml::Value::table).transpose()?;
        let local = if let Some(source) = source {
            if uv {
                let source_keys = [
                    "registry",
                    "editable",
                    "path",
                    "virtual",
                    "directory",
                    "git",
                    "url",
                    "file",
                    "workspace",
                ];
                if source.len() != 1 || !source_keys.iter().any(|key| source.contains_key(*key)) {
                    return Err("unknown or ambiguous uv package source".into());
                }
                let (key, _) = source.iter().next().ok_or("empty uv source")?;
                if toml::required_string(source, key)?.is_empty() {
                    return Err("empty uv package source".into());
                }
                key != "registry"
            } else {
                match toml::optional_string(source, "type")? {
                    Some("legacy" | "registry") => false,
                    Some("git" | "directory" | "file" | "url" | "path") => true,
                    Some(_) => return Err("unknown Poetry package source type".into()),
                    None => return Err("package.source is missing type".into()),
                }
            }
        } else {
            false
        };
        // uv virtual/editable workspace entries need not have a version.
        if local {
            continue;
        }
        let version = toml::required_string(package, "version")?;
        if version.is_empty() {
            return Err(format!("empty version for {name}"));
        }
        if toml::exact_version(version) {
            out.push(Dep {
                name: pep503(name),
                version: version.into(),
            });
        } else if !toml::constraint(version) {
            return Err(format!("invalid version for {name}"));
        }
    }
    Ok(out)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        Ok(())
    } else {
        Err("invalid Python package name".into())
    }
}

fn requirement_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    let mut whitespace = true;
    for (index, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && c == '\\' {
            escaped = true;
            continue;
        }
        if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if quote.is_none() && c == '#' && whitespace {
            return &line[..index];
        }
        whitespace = c.is_whitespace();
    }
    line
}

fn requirement(line: &str) -> Result<Option<Dep>, String> {
    let line = line.trim();
    if line.is_empty()
        || line.starts_with('-')
        || line.starts_with("https://")
        || line.starts_with("http://")
        || line.starts_with("ftp://")
        || line.starts_with(['.', '/', '\\'])
        || line.starts_with("git+")
        || line.starts_with("file:")
        || line.ends_with(".whl")
        || line.ends_with(".tar.gz")
    {
        return Ok(None);
    }
    let line = without_hashes(line)?;
    let (specifier, marker) = line
        .split_once(';')
        .map_or((line, None), |(a, b)| (a, Some(b)));
    if let Some(marker) = marker {
        validate_marker(marker)?;
    }
    let name_end = specifier
        .find(|c: char| !c.is_ascii_alphanumeric() && !"._-".contains(c))
        .unwrap_or(specifier.len());
    let name = &specifier[..name_end];
    validate_name(name)?;
    let mut rest = specifier[name_end..].trim();
    if rest.starts_with('@') {
        return Ok(None);
    }
    if let Some(extras) = rest.strip_prefix('[') {
        let (extras, tail) = extras.split_once(']').ok_or("unclosed extras list")?;
        if extras.trim().is_empty() {
            return Err("empty extras list".into());
        }
        for extra in extras.split(',') {
            validate_name(extra.trim())?;
        }
        rest = tail.trim();
    }
    if rest.starts_with('@') {
        return Ok(None);
    }
    if let Some(inner) = rest.strip_prefix('(') {
        rest = inner
            .strip_suffix(')')
            .ok_or("unclosed version specifier")?
            .trim();
    }
    if rest.is_empty() {
        return Ok(None);
    } // valid, but unpinned
    Ok(pin(rest)?.map(|version| Dep {
        name: pep503(name),
        version: version.into(),
    }))
}

fn without_hashes(line: &str) -> Result<&str, String> {
    let mut quote = None;
    let index = line.char_indices().find_map(|(i, c)| {
        if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        }
        if quote.is_none() && line[i..].starts_with("--hash") {
            Some(i)
        } else {
            None
        }
    });
    let Some(index) = index else {
        return Ok(line);
    };
    if index == 0 || !line[..index].ends_with(char::is_whitespace) {
        return Err("invalid hash option".into());
    }
    let mut options = line[index..].split_whitespace();
    while let Some(option) = options.next() {
        let value = if option == "--hash" {
            options.next().ok_or("missing hash value")?
        } else {
            option
                .strip_prefix("--hash=")
                .ok_or("unexpected text after hash")?
        };
        if value.is_empty() || value.starts_with('-') {
            return Err("missing hash value".into());
        }
    }
    Ok(line[..index].trim_end())
}

fn validate_marker(marker: &str) -> Result<(), String> {
    struct Marker<'a> {
        rest: &'a str,
    }
    impl Marker<'_> {
        fn eat(&mut self, token: &str) -> bool {
            self.rest = self.rest.trim_start();
            if let Some(tail) = self.rest.strip_prefix(token) {
                if token.ends_with(char::is_alphabetic)
                    && tail.starts_with(|c: char| c.is_alphanumeric() || c == '_')
                {
                    return false;
                }
                self.rest = tail;
                true
            } else {
                false
            }
        }
        fn value(&mut self) -> Result<(), String> {
            self.rest = self.rest.trim_start();
            if let Some(quote @ ('\'' | '"')) = self.rest.chars().next() {
                let tail = &self.rest[1..];
                let end = tail.find(quote).ok_or("unclosed marker string")?;
                if tail[..end].chars().any(char::is_control) {
                    return Err("control character in marker".into());
                }
                self.rest = &tail[end + 1..];
            } else {
                let end = self
                    .rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(self.rest.len());
                if !matches!(
                    &self.rest[..end],
                    "python_version"
                        | "python_full_version"
                        | "os_name"
                        | "sys_platform"
                        | "platform_release"
                        | "platform_system"
                        | "platform_version"
                        | "platform_machine"
                        | "platform_python_implementation"
                        | "implementation_name"
                        | "implementation_version"
                        | "extra"
                        | "extras"
                        | "dependency_groups"
                ) {
                    return Err("expected marker variable or quoted string".into());
                }
                self.rest = &self.rest[end..];
            }
            Ok(())
        }
        fn expression(&mut self, depth: usize) -> Result<(), String> {
            if depth > 64 {
                return Err("environment marker nesting is too deep".into());
            }
            loop {
                if self.eat("(") {
                    self.expression(depth + 1)?;
                    if !self.eat(")") {
                        return Err("unclosed environment marker group".into());
                    }
                } else {
                    self.value()?;
                    if self.eat("not") {
                        if !self.eat("in") {
                            return Err("expected 'in' after 'not'".into());
                        }
                    } else if !["===", "==", "!=", "~=", "<=", ">=", "<", ">", "in"]
                        .iter()
                        .any(|op| self.eat(op))
                    {
                        return Err("expected environment marker comparison".into());
                    }
                    self.value()?;
                }
                if !self.eat("and") && !self.eat("or") {
                    break;
                }
            }
            Ok(())
        }
    }
    let mut marker = Marker { rest: marker };
    marker.expression(0)?;
    if !marker.rest.trim().is_empty() {
        return Err("unexpected text in environment marker".into());
    }
    Ok(())
}

// A multi-clause constraint isn't a lock even when one clause happens to be ==.
fn pin(specifier: &str) -> Result<Option<&str>, String> {
    if specifier.trim() == "*" {
        return Ok(None);
    }
    let mut pin = None;
    let mut clauses = 0;
    for clause in specifier.split(',') {
        clauses += 1;
        let clause = clause.trim();
        let op = ["===", "==", "!=", "~=", ">=", "<=", ">", "<"]
            .into_iter()
            .find(|op| clause.starts_with(op))
            .ok_or("invalid version specifier")?;
        let version = clause[op.len()..].trim();
        if version.is_empty()
            || version
                .chars()
                .any(|c| c.is_whitespace() || "<>=~,;()[]\"'".contains(c))
        {
            return Err("missing or malformed version".into());
        }
        if (op == "==" && toml::exact_version(version))
            || (op == "==="
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-+!".contains(&b)))
        {
            pin = Some(version);
        } else if !toml::constraint(version) && !toml::exact_version(version) {
            return Err("invalid version".into());
        }
    }
    Ok(if clauses == 1 { pin } else { None })
}

fn json_depth(text: &str) -> Result<(), String> {
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0usize;
    for c in text.chars() {
        if quoted {
            if c.is_control() {
                return Err("Pipfile.lock: control character in JSON string".into());
            }
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else {
            match c {
                '"' => quoted = true,
                '[' | '{' => {
                    depth += 1;
                    if depth > 64 {
                        return Err("Pipfile.lock: JSON nesting is too deep".into());
                    }
                }
                ']' | '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deps(pairs: &[(&str, &str)]) -> Vec<Dep> {
        pairs
            .iter()
            .map(|(name, version)| Dep {
                name: (*name).into(),
                version: (*version).into(),
            })
            .collect()
    }

    #[test]
    fn requirements_extras_markers_hashes_and_continuations() {
        let text = "\u{feff}# pip-compile output\r\n\
            Requests[security,socks] == 2.32.3 ; python_version < \"3.13\" \\\r\n\
                --hash=sha256:example-one \\\r\n\
                --hash sha256:example-two # comment\r\n\
            Zope__Interface==7.2\n\
            Custom.Pkg===vendor-release\n\
            demo (==1!2.0rc1+local.1) ; (sys_platform == 'win32')\n\
            split==1.\\\n2.3\n";
        assert_eq!(
            parse_requirements(text).unwrap(),
            deps(&[
                ("requests", "2.32.3"),
                ("zope-interface", "7.2"),
                ("custom-pkg", "vendor-release"),
                ("demo", "1!2.0rc1+local.1"),
                ("split", "1.2.3"),
            ])
        );
    }

    #[test]
    fn requirements_skip_unpinned_local_and_urls() {
        let text = r#"
requests>=2.0
django~=5.0
other==1.*
other==1.0,!=1.0.post1
unpinned
-r requirements-base.txt
-c constraints.txt
-e ../local
--index-url https://example.invalid/simple
https://example.invalid/pkg.whl#fragment
local @ https://example.invalid/local.whl
local@file:../local
./local
../local
file:../local
git+ssh://example.invalid/repo
"#;
        assert!(parse_requirements(text).unwrap().is_empty());
        assert!(parse_requirements("# comment\n\n").unwrap().is_empty());
    }

    #[test]
    fn malformed_requirements_fail() {
        for text in [
            "not a requirement",
            "pkg==",
            "pkg=1.0",
            "pkg[a==1.0",
            "pkg[]==1.0",
            "pkg==1.0 junk",
            "pkg==1.0 \\",
            "pkg==1.0;",
            "pkg==1.0; python_version < \"3.8",
            "pkg==1.0 --hash=",
            "pkg==1.0 --hash=example junk",
            "pkg (==1.0",
            "pkg>=",
            "pkg==1.0\n<broken>",
            "pkg==1.0,",
            "pkg==1.0; (python_version < '3.8'",
        ] {
            assert!(parse_requirements(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn poetry_packages_sources_and_nested_dependencies() {
        let text = r#"# Generated by Poetry
[[package]]
name = "Requests"
version = "2.32.3"
description = "A string containing # and an escaped \"quote\""
optional = false
python-versions = ">=3.8"
groups = ["main"]
files = [
 {file = "requests.whl", hash = "sha256:example"},
]
[package.dependencies]
urllib3 = ">=1.21.1,<3"
other = {version = "1.0", markers = "python_version < '3.8'"}
[[package]]
name = "Zope.Interface"
version = "7.2"
[package.source]
type = "legacy"
url = "https://example.invalid/simple"
reference = "private-index"
[[package]]
name = "local"
version = "0.1.0"
[package.source]
type = "directory"
url = "../local"
[[package]]
name = "git-package"
version = "1.0"
[package.source]
type = "git"
url = "https://example.invalid/repo"
[[package]]
name = "range"
version = ">=1.0"
[metadata]
lock-version = "2.1"
python-versions = ">=3.8"
content-hash = "example"
"#;
        assert_eq!(
            parse_poetry_lock(text).unwrap(),
            deps(&[("requests", "2.32.3"), ("zope-interface", "7.2")])
        );
    }

    #[test]
    fn uv_registry_and_every_non_registry_source() {
        let mut text = String::from(
            r#"version = 1
revision = 3
requires-python = ">=3.12"
resolution-markers = ["sys_platform == 'win32'"]
[[package]]
name = "PyYAML"
version = "6.0.2"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example.invalid/pypi.tar.gz", hash = "sha256:example", size = 123 }
wheels = [
 { url = "https://example.invalid/pypi.whl", hash = "sha256:example", size = 456 },
]
[package.optional-dependencies]
test = [{ name = "pytest" }]
"#,
        );
        for key in [
            "editable",
            "path",
            "virtual",
            "directory",
            "git",
            "url",
            "file",
            "workspace",
        ] {
            text.push_str(&format!(
                "\n[[package]]\nname='local-{key}'\nsource={{ {key}='.' }}\n"
            ));
        }
        assert_eq!(parse_uv_lock(&text).unwrap(), deps(&[("pyyaml", "6.0.2")]));
    }

    #[test]
    fn toml_multiline_strings_escapes_and_empty_locks() {
        let text = r#"[[package]]
name = "d\u0065mo"
version = '1.0'
description = """
Not a section:
[[package]]
name = "fake"
"""
"#;
        assert_eq!(parse_poetry_lock(text).unwrap(), deps(&[("demo", "1.0")]));
        assert!(parse_uv_lock("version=1\npackage=[]").unwrap().is_empty());
        assert!(
            parse_poetry_lock("package=[]\n[metadata]\nlock-version='2.1'")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn malformed_toml_locks_fail() {
        for parse in [parse_poetry_lock, parse_uv_lock] {
            for text in [
                "",
                "garbage",
                "[[package]]\nname='a'",
                "[[package]]\nversion='1.0'",
                "[[package]]\nname='a'\nversion=1",
                "[[package]]\nname='a'\nversion='1.0'\nsource=42",
                "[[package]]\nname='a'\nversion='1.0'\nfiles=[{file='a'}",
                "[[package]]\nname='a'\nversion='1.0'\nsource={git='unfinished}",
                "[[package]]\nname='a'\nversion='1.0'\n[package.dependencies]\nx={version='1.0' markers='x'}",
            ] {
                assert!(parse(text).is_err(), "accepted {text:?}");
            }
        }
    }

    #[test]
    fn pipfile_sections_pins_and_local_entries() {
        let text = r#"{
 "_meta": {"pipfile-spec": 6},
 "default": {
   "Requests": {"version": "==2.32.3", "hashes": ["sha256:example"], "markers": "python_version >= '3.8'"},
   "zope.interface": {"version": "==7.2"},
   "range": {"version": ">=1.0"},
   "wildcard": {"version": "==1.*"},
   "unlocked": {"version": "*"},
   "local": {"path": ".", "version": "==0.1"},
   "git-pkg": {"git": "https://example.invalid/repo"},
   "editable": {"editable": true, "version": "==1.0"}
 },
 "develop": {"PyTest": {"version": "==8.3.5"}}
}"#;
        assert_eq!(
            parse_pipfile_lock(text).unwrap(),
            deps(&[
                ("requests", "2.32.3"),
                ("zope-interface", "7.2"),
                ("pytest", "8.3.5")
            ])
        );
        assert!(
            parse_pipfile_lock(r#"{"default":{},"develop":{}}"#)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn marker_grammar_and_quoted_option_text() {
        let marker =
            "pkg==1.0; (python_version >= '3.8' and os_name not in 'nt') or extra == '--hash'";
        assert_eq!(parse_requirements(marker).unwrap(), deps(&[("pkg", "1.0")]));
        assert_eq!(
            parse_requirements("pkg==1.0; extra == 'with#hash'").unwrap(),
            deps(&[("pkg", "1.0")])
        );
        for marker in [
            "junk",
            "python_version",
            "os_name ==",
            "os_name == 'nt' and",
            "os_name not 'nt'",
            "os_name == 'nt')",
        ] {
            assert!(parse_requirements(&format!("pkg==1.0; {marker}")).is_err());
        }
        assert!(parse_requirements("pkg==???").is_err());
        assert!(parse_requirements("pkg==1.0 junk https://example.invalid").is_err());
    }

    #[test]
    fn malformed_sources_and_non_editable_pipfile_entry() {
        for source in [
            "{git=1}",
            "{}",
            "{registry='index',git='repo'}",
            "{unknown='repo'}",
        ] {
            let text = format!("[[package]]\nname='pkg'\nversion='1.0'\nsource={source}");
            assert!(parse_uv_lock(&text).is_err());
        }
        let text = r#"{"default":{"Pkg":{"version":"==1.0","editable":false}}}"#;
        assert_eq!(parse_pipfile_lock(text).unwrap(), deps(&[("pkg", "1.0")]));
    }

    #[test]
    fn truncated_and_unicode_inputs_do_not_panic() {
        let parsers = [
            parse_requirements,
            parse_poetry_lock,
            parse_uv_lock,
            parse_pipfile_lock,
            super::super::cargo::parse,
            super::super::gomod::parse,
        ];
        let inputs = [
            "\u{feff}[[package]]\nname='demo'\nversion='1.0'\ndescription='текст 🦀'\nsource={git='.'}",
            r#"{"default":{"demo":{"version":"==1.0"}},"develop":{}}"#,
            "module example.org/a\nrequire (\nexample.org/b v1.2.3\n)\nreplace example.org/b => ../local",
            "demo[extra]==1.0; python_version < '3.8' # comment",
        ];
        for input in inputs {
            for (end, _) in input
                .char_indices()
                .chain(std::iter::once((input.len(), '\0')))
            {
                for parse in parsers {
                    let _ = parse(&input[..end]);
                }
            }
        }
    }

    #[test]
    fn malformed_pipfile_locks_fail() {
        for text in [
            "",
            "{",
            "[]",
            "{}",
            r#"{"default":[]}"#,
            r#"{"default":{"pkg":42}}"#,
            r#"{"default":{"pkg":{"version":42}}}"#,
            r#"{"default":{"pkg":{"version":"=="}}}"#,
            r#"{"default":{},"develop":null}"#,
            r#"{"default":{}} trailing"#,
        ] {
            assert!(parse_pipfile_lock(text).is_err(), "accepted {text:?}");
        }
        assert!(parse_pipfile_lock(&format!("{}0{}", "[".repeat(100), "]".repeat(100))).is_err());
    }
}
