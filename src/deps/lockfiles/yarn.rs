//! Yarn classic and Berry: registry identities from descriptors, installed
//! versions from each block's `version`. Local/git/URL descriptors are skipped.
//! A patch is reported only when its key identifies an exact npm original.

use super::pnpm::syntax;
use crate::deps::Dep;

pub fn parse(text: &str) -> Result<Vec<Dep>, String> {
    let mut classic = false;
    let mut berry = false;
    let mut lines = Vec::new();
    for (index, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        classic |= raw.trim_end() == "# yarn lockfile v1";
        let (indent, line) =
            syntax::line(raw).map_err(|e| format!("yarn.lock line {}: {e}", index + 1))?;
        if !line.is_empty() {
            if indent == 0 && syntax::mapping(line).is_ok_and(|(key, _)| key == "__metadata") {
                berry = true;
            }
            lines.push((index + 1, indent, line));
        }
    }
    if classic == berry {
        return Err("yarn.lock: expected either '# yarn lockfile v1' or Berry __metadata".into());
    }
    let mut out = Vec::new();
    let mut block: Option<Block> = None;
    let mut metadata = false;
    for (line_no, indent, line) in lines {
        let result = (|| {
            if indent == 0 {
                if let Some(previous) = block.take() {
                    previous.finish(&mut out)?;
                }
                let (keys, is_metadata) = if berry {
                    let (key, value) = syntax::mapping(line)?;
                    if !value.is_empty() {
                        return Err("expected a block mapping".into());
                    }
                    let is_metadata = key == "__metadata";
                    (
                        key.split(',').map(|s| s.trim().to_owned()).collect(),
                        is_metadata,
                    )
                } else {
                    (classic_keys(line)?, false)
                };
                if is_metadata && metadata {
                    return Err("duplicate __metadata block".into());
                }
                metadata |= is_metadata;
                let mut targets = Vec::new();
                if !is_metadata {
                    for key in keys {
                        if let Some(target) = target(&key, berry)?
                            && !targets.contains(&target)
                        {
                            targets.push(target);
                        }
                    }
                }
                block = Some(Block {
                    line_no,
                    targets,
                    metadata: is_metadata,
                    version: None,
                    fields: 0,
                    parents: vec![0],
                });
            } else {
                let block = block.as_mut().ok_or("field outside a package block")?;
                while block.parents.last().is_some_and(|parent| *parent >= indent) {
                    block.parents.pop();
                }
                if block.parents.last().copied().map(|p| p + 2) != Some(indent) {
                    return Err(
                        "unexpected indentation (expected two spaces per mapping level)".into(),
                    );
                }
                let (key, value) = if berry {
                    syntax::mapping(line)?
                } else {
                    classic_field(line)?
                };
                block.fields += 1;
                if indent == 2 && key == "version" {
                    if block.version.is_some() {
                        return Err("duplicate version field".into());
                    }
                    block.version = Some(syntax::scalar(value)?);
                } else if value.is_empty() {
                    block.parents.push(indent);
                } else if berry {
                    syntax::value(value)?;
                } else {
                    syntax::scalar(value)?;
                }
            }
            Ok(())
        })();
        result.map_err(|e: String| format!("yarn.lock line {line_no}: {e}"))?;
    }
    if let Some(last) = block {
        last.finish(&mut out)?;
    }
    Ok(out)
}

#[derive(PartialEq, Eq)]
struct Target {
    name: String,
    // The original version encoded in a patch key, when unambiguous.
    original: Option<String>,
}

struct Block {
    line_no: usize,
    targets: Vec<Target>,
    metadata: bool,
    version: Option<String>,
    fields: usize,
    parents: Vec<usize>,
}

impl Block {
    fn finish(self, out: &mut Vec<Dep>) -> Result<(), String> {
        let error = |reason: &str| format!("yarn.lock block at line {}: {reason}", self.line_no);
        if self.fields == 0 {
            return Err(error("empty or truncated block"));
        }
        if self.metadata {
            let version = self
                .version
                .as_deref()
                .ok_or_else(|| error("missing metadata version"))?;
            if !syntax::digits(version) || version.bytes().all(|b| b == b'0') {
                return Err(error("invalid metadata version"));
            }
        } else if !self.targets.is_empty() {
            let version = self
                .version
                .ok_or_else(|| error("missing installed version"))?;
            if !syntax::exact_version(&version) {
                if syntax::range(&version) {
                    return Ok(());
                }
                return Err(error("invalid installed npm version"));
            }
            for target in self.targets {
                if target
                    .original
                    .as_ref()
                    .is_some_and(|original| original != &version)
                {
                    return Err(error("patch original disagrees with installed version"));
                }
                out.push(Dep {
                    name: target.name,
                    version: version.clone(),
                });
            }
        }
        Ok(())
    }
}

fn classic_keys(line: &str) -> Result<Vec<String>, String> {
    let text = line
        .strip_suffix(':')
        .ok_or("expected package descriptors followed by ':'")?;
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => i = syntax::quoted_end(text, i)?,
            b',' => {
                out.push(syntax::scalar(&text[start..i])?);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    out.push(syntax::scalar(&text[start..])?);
    Ok(out)
}

fn classic_field(line: &str) -> Result<(String, &str), String> {
    if let Some(key) = line.strip_suffix(':') {
        return Ok((syntax::scalar(key)?, ""));
    }
    let end = if line.starts_with(['\'', '"']) {
        syntax::quoted_end(line, 0)?
    } else {
        line.find(char::is_whitespace)
            .ok_or("expected a field name and value")?
    };
    if !line[end..].starts_with(char::is_whitespace) {
        return Err("missing whitespace after field name".into());
    }
    let key = syntax::scalar(&line[..end])?;
    let value = line[end..].trim();
    if value.is_empty() {
        return Err("missing field value".into());
    }
    Ok((key, value))
}

fn descriptor(text: &str) -> Result<(&str, &str), String> {
    let start = usize::from(text.starts_with('@'));
    let separator = text[start..]
        .find('@')
        .map(|i| i + start)
        .ok_or("package descriptor is missing '@' and a selector")?;
    let (name, selector) = (&text[..separator], &text[separator + 1..]);
    if !syntax::package_name(name) || selector.is_empty() {
        return Err("invalid package descriptor name or selector".into());
    }
    Ok((name, selector))
}

fn target(text: &str, berry: bool) -> Result<Option<Target>, String> {
    let (name, selector) = descriptor(text)?;
    if berry {
        if let Some(patch) = selector.strip_prefix("patch:") {
            let Some((source, _)) = patch.split_once('#') else {
                return Ok(None);
            };
            // Yarn percent-encodes the npm locator inside the patch descriptor.
            let source = source
                .replace("%3A", ":")
                .replace("%3a", ":")
                .replace("%40", "@")
                .replace("%2F", "/")
                .replace("%2f", "/");
            let Ok((original, selector)) = descriptor(&source) else {
                return Ok(None);
            };
            return Ok(selector
                .strip_prefix("npm:")
                .filter(|v| syntax::exact_version(v))
                .map(|version| Target {
                    name: original.into(),
                    original: Some(version.into()),
                }));
        }
        if !selector.starts_with("npm:") {
            return Ok(None);
        }
    }
    if let Some(npm) = selector.strip_prefix("npm:") {
        if npm.is_empty() {
            return Err("empty npm selector".into());
        }
        if let Some((real, range)) = npm.rsplit_once('@') {
            if !syntax::package_name(real) || range.is_empty() {
                return Err("invalid npm alias target".into());
            }
            return Ok(Some(Target {
                name: real.into(),
                original: None,
            }));
        }
    } else if selector.contains([':', '/', '#']) {
        return Ok(None); // local paths, git/GitHub shorthand, and tarball URLs
    }
    Ok(Some(Target {
        name: name.into(),
        original: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deps(text: &str) -> Vec<(String, String)> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.version))
            .collect()
    }

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(a, b)| ((*a).into(), (*b).into()))
            .collect()
    }

    #[test]
    fn classic_scopes_multiple_descriptors_and_aliases() {
        let text = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.22.5"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.5.tgz#example"
  integrity sha512-example
  dependencies:
    "@babel/parser" "^7.22.5"
    version "^99.0.0"

plain@^1, "plain@~1.2":
  version "1.2.3"

"alias@npm:real@^1", "another@npm:real@~1.2":
  version "1.2.4"
  resolved "https://registry.yarnpkg.com/real/-/real-1.2.4.tgz"

"scoped-alias@npm:@scope/real@^2":
  version "2.0.0-beta.1+build.02"
"#;
        assert_eq!(
            deps(text),
            pairs(&[
                ("@babel/core", "7.22.5"),
                ("plain", "1.2.3"),
                ("real", "1.2.4"),
                ("@scope/real", "2.0.0-beta.1+build.02")
            ])
        );
    }

    #[test]
    fn classic_skips_local_git_urls_and_version_ranges() {
        let text = r#"# yarn lockfile v1
"local@file:../local":
  version "1.0.0"
"linked@link:../linked":
  resolved "link:../linked"
"ws@workspace:*":
  version "1.0.0"
"git@github:owner/repo", "git@owner/repo":
  version "2.0.0"
"remote@git+ssh://git@example.invalid/repo.git#example":
  version "3.0.0"
"tarball@https://example.invalid/pkg-1.0.0.tgz":
  version "1.0.0"
ranged@^1:
  version "^1.2.3"
"#;
        assert!(deps(text).is_empty());
    }

    #[test]
    fn berry_metadata_npm_aliases_and_nested_versions() {
        let text = r#"# This file is generated by running "yarn install" inside your project.
__metadata:
  version: 8
  cacheKey: 10c0

"@scope/name@npm:^1.2.3, @scope/name@npm:^1.0.0":
  version: 1.2.5
  resolution: "@scope/name@npm:1.2.5"
  dependencies:
    version: "npm:^9.0.0"
  checksum: example
  languageName: node
  linkType: hard

"alias@npm:real@^2, real@npm:~2.0":
  version: "2.0.1"
  resolution: "real@npm:2.0.1"

'other@npm:@scope/real@^3':
  version: '3.0.0'
"#;
        assert_eq!(
            deps(text),
            pairs(&[
                ("@scope/name", "1.2.5"),
                ("real", "2.0.1"),
                ("@scope/real", "3.0.0")
            ])
        );
    }

    #[test]
    fn berry_skips_non_registry_protocols_and_ambiguous_patches() {
        let mut text = String::from("__metadata:\n  version: 8\n");
        for selector in [
            "workspace:.",
            "link:../local",
            "portal:../local",
            "file:../local",
            "github:owner/repo",
            "git+https://example.invalid/repo.git",
            "https://example.invalid/pkg.tgz",
            "^1",
            "patch:pkg@npm%3A^1#./fix.patch",
            "patch:pkg@file%3A../local#./fix.patch",
        ] {
            text.push_str(&format!("\"pkg@{selector}\":\n  version: 1.0.0\n"));
        }
        assert!(deps(&text).is_empty());
    }

    #[test]
    fn berry_unambiguous_patch_keeps_original_name_and_version() {
        let text = r#"__metadata:
  version: 8
"alias@patch:@scope/pkg@npm%3A1.2.3#./patches/fix.patch":
  version: 1.2.3
  resolution: "@scope/pkg@patch:@scope/pkg@npm%3A1.2.3#./patches/fix.patch::version=1.2.3&hash=example"
"#;
        assert_eq!(deps(text), pairs(&[("@scope/pkg", "1.2.3")]));
        assert!(parse(&text.replace("  version: 1.2.3", "  version: 9.0.0")).is_err());
    }

    #[test]
    fn bom_crlf_comments_quotes_and_empty_projects() {
        assert!(deps("# yarn lockfile v1\n").is_empty());
        assert!(deps("__metadata:\n  version: 8\n").is_empty());
        assert_eq!(
            deps(
                "\u{feff}# yarn lockfile v1\r\n\"a@^1\": # note\r\n  version \"1.2.3\" # installed\r\n"
            ),
            pairs(&[("a", "1.2.3")])
        );
        assert_eq!(
            deps("'__metadata':\n  version: 8\n\"\\u0061@npm:^1\":\n  version: '1.2.3'\n"),
            pairs(&[("a", "1.2.3")])
        );
    }

    #[test]
    fn installed_versions_win_over_descriptors_and_nested_fields() {
        assert_eq!(
            deps(
                "# yarn lockfile v1\n@scope/pkg@^1:\n  dependencies:\n    version \"9.0.0\"\n  version \"1.2.3\"\n@scope/pkg@^2:\n  version \"2.0.0\"\n"
            ),
            pairs(&[("@scope/pkg", "1.2.3"), ("@scope/pkg", "2.0.0")])
        );
        assert_eq!(
            deps(
                "\"pkg@npm:^1\":\n  dependencies:\n    version: 9.0.0\n  version: 1.2.3\n__metadata:\n  version: 8\n"
            ),
            pairs(&[("pkg", "1.2.3")])
        );
        assert!(
            parse(
                "__metadata:\n  version: 8\n\"pkg@npm:^1\":\n  dependencies:\n    version: 1.2.3\n"
            )
            .is_err()
        );
    }

    #[test]
    fn unicode_and_every_truncated_prefix_are_safe() {
        for text in [
            "# yarn lockfile v1\n\"local@file:../пакет🦀\":\n  version \"1.0.0\"\n\"pkg@^1\":\n  version \"1.2.3\"\n",
            "__metadata:\n  version: 8\n\"local@workspace:пакет🦀\":\n  version: 0.0.0-use.local\n\"pkg@npm:^1\":\n  version: 1.2.3\n",
        ] {
            assert_eq!(deps(text), pairs(&[("pkg", "1.2.3")]));
            for end in text.char_indices().map(|(i, _)| i) {
                let _ = parse(&text[..end]);
            }
        }
    }

    #[test]
    fn broken_unknown_and_truncated_files_return_errors() {
        for text in [
            "",
            "# comment",
            "a@^1:\n  version \"1.2.3\"",
            "# yarn lockfile v1\n__metadata:\n  version: 8",
            "# yarn lockfile v1\na@^1:",
            "# yarn lockfile v1\na@^1:\n  resolved \"https://example.invalid/a.tgz\"",
            "# yarn lockfile v1\na@^1:\n  version \"1.2.3\"\nb@^1:\n  version \"broken\"",
            "# yarn lockfile v1\na@^1:\n  version \"1.2.3\n",
            "# yarn lockfile v1\n  version \"1.2.3\"",
            "# yarn lockfile v1\na@^1:\n    version \"1.2.3\"",
            "# yarn lockfile v1\na@^1:\n\tversion \"1.2.3\"",
            "# yarn lockfile v1\na@^1, :\n  version \"1.2.3\"",
            "# yarn lockfile v1\nno-selector:\n  version \"1.2.3\"",
            "# yarn lockfile v1\na@npm:@scope/b:\n  version \"1.2.3\"",
            "__metadata:\n",
            "__metadata:\n  cacheKey: 10c0",
            "__metadata:\n  version: broken",
            "__metadata:\n  version: 8\n__metadata:\n  version: 8",
            "__metadata:\n  version: 8\n\"a@npm:^1\":\n  version: 1.2.3\n  version: 2.0.0",
            "__metadata:\n  version: 8\n\"a@npm:^1\":\n  version: [1.2.3]",
            "__metadata:\n  version: 8\n\"a@npm:^1\":\n  version: '1.2.3' junk",
            "__metadata:\n  version: 8\n\"a@npm:^1\":\n  version: 1.2.3\n\"b@npm:^1\":",
        ] {
            assert!(
                parse(text).is_err(),
                "accepted malformed lockfile: {text:?}"
            );
        }
    }
}
