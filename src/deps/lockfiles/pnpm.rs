//! `pnpm-lock.yaml`: package keys in lockfile versions 5.x, 6.0 and 9.0.
//! Only `packages` supplies installed versions, never importers or snapshots.
//! This reads generated lockfiles, not arbitrary YAML.

use crate::deps::Dep;

/// pnpm 9+ пишет НЕСКОЛЬКО YAML-документов через `---`: первый — lockfile самого pnpm
/// (`packageManagerDependencies`, config-зависимости), второй — проекта. Разбираем каждый,
/// пакеты объединяем (ревью Claude: без этого современный pnpm-lock.yaml целиком «not checked»).
pub fn parse(text: &str) -> Result<Vec<Dep>, String> {
    let text = text.trim_start_matches('\u{feff}');
    let mut docs: Vec<(usize, String)> = vec![(0, String::new())];
    for (index, raw) in text.lines().enumerate() {
        if raw.trim_end() == "---" {
            docs.push((index + 1, String::new()));
            continue;
        }
        let doc = &mut docs.last_mut().expect("never empty").1;
        doc.push_str(raw);
        doc.push('\n');
    }
    let docs: Vec<(usize, String)> = docs
        .into_iter()
        .filter(|(_, d)| !d.trim().is_empty())
        .collect();
    if docs.is_empty() {
        return Err("pnpm-lock.yaml: empty file".into());
    }
    let mut out = Vec::new();
    for (offset, doc) in &docs {
        // Номера строк в ошибках — от начала файла, а не документа.
        let deps = parse_document(doc).map_err(|e| shift_line(&e, *offset))?;
        out.extend(deps);
    }
    Ok(out)
}

fn shift_line(err: &str, offset: usize) -> String {
    let prefix = "pnpm-lock.yaml line ";
    match err
        .strip_prefix(prefix)
        .and_then(|rest| rest.split_once(':'))
    {
        Some((n, rest)) if offset > 0 => match n.parse::<usize>() {
            Ok(n) => format!("{prefix}{}:{rest}", n + offset),
            Err(_) => err.to_string(),
        },
        _ => err.to_string(),
    }
}

fn parse_document(text: &str) -> Result<Vec<Dep>, String> {
    let mut version = None;
    let mut packages = false;
    let mut settings = false;
    let mut importers = false;
    let mut in_packages = false;
    let mut keys = Vec::new();
    let mut pending_entry = false;
    let mut parents = Vec::new();

    for (index, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line_no = index + 1;
        let result = (|| {
            let (indent, line) = syntax::line(raw)?;
            if line.is_empty() {
                return Ok(());
            }
            while parents.last().is_some_and(|parent| *parent >= indent) {
                parents.pop();
            }
            if indent > 0 && parents.last().copied().map(|p| p + 2) != Some(indent) {
                return Err(
                    "unexpected indentation (expected two spaces per mapping level)".into(),
                );
            }
            if let Some(item) = line.strip_prefix("- ") {
                if indent == 0 || (in_packages && indent <= 4) {
                    return Err("expected a mapping, not a sequence".into());
                }
                // Элемент списка — сам уровень: соседние ключи элемента идут на `indent + 2`
                // (`- a: 1` / `  b: 2`), а `- key:` открывает вложенный маппинг ещё глубже.
                // Так pnpm 10+ пишет `node@runtime:` (`variants: - resolution: ...`).
                parents.push(indent);
                match syntax::mapping(item) {
                    Ok((_, "")) => parents.push(indent + 2),
                    Ok((_, v)) => syntax::value(v)?,
                    Err(_) => syntax::value(item)?,
                }
                return Ok(());
            }
            let (key, value) = syntax::mapping(line)?;
            syntax::value(value)?;
            if value.is_empty() {
                parents.push(indent);
            }
            if indent == 0 {
                if pending_entry {
                    return Err("package entry has no mapping body".into());
                }
                if in_packages && keys.is_empty() {
                    return Err("empty packages block; expected a mapping or {}".into());
                }
                in_packages = false;
                match key.as_str() {
                    "lockfileVersion" => {
                        if version.is_some() {
                            return Err("duplicate lockfileVersion".into());
                        }
                        let value = syntax::scalar(value)?;
                        let major = if value == "6.0" {
                            6
                        } else if value == "9.0" {
                            9
                        } else if value == "5"
                            || value.strip_prefix("5.").is_some_and(syntax::digits)
                        {
                            5
                        } else {
                            return Err(
                                "unsupported lockfileVersion (expected 5.x, 6.0 or 9.0)".into()
                            );
                        };
                        version = Some(major);
                    }
                    "packages" => {
                        if packages {
                            return Err("duplicate packages section".into());
                        }
                        packages = true;
                        match value {
                            "" => in_packages = true,
                            "{}" => {}
                            _ => return Err("packages must be a block mapping or {}".into()),
                        }
                    }
                    "settings" => settings = true,
                    "importers" => importers = true,
                    _ => {}
                }
            } else if in_packages {
                if indent == 2 {
                    if pending_entry {
                        return Err("package entry has no mapping body".into());
                    }
                    if !matches!(value, "" | "{}") {
                        return Err("package entry must be a block mapping or {}".into());
                    }
                    pending_entry = value.is_empty();
                    keys.push((key, line_no));
                } else {
                    if pending_entry && indent != 4 {
                        return Err("expected package fields at four spaces".into());
                    }
                    pending_entry = false;
                }
            }
            Ok(())
        })();
        result.map_err(|e: String| format!("pnpm-lock.yaml line {line_no}: {e}"))?;
    }
    let version = version.ok_or("pnpm-lock.yaml: missing lockfileVersion")?;
    if !packages {
        // pnpm 8 emits a v6 lock containing only version + settings for an
        // empty project. pnpm 9+ emits version + settings + importers and
        // likewise omits packages. Those are valid clean lockfiles, not a
        // failed parse. v5 does not emit an empty lockfile at all.
        if (version == 6 && settings) || (version == 9 && settings && importers) {
            return Ok(Vec::new());
        }
        return Err("pnpm-lock.yaml: missing packages mapping".into());
    }
    if pending_entry {
        return Err("pnpm-lock.yaml: package entry has no mapping body".into());
    }
    if in_packages && keys.is_empty() {
        return Err("pnpm-lock.yaml: empty packages block; expected a mapping or {}".into());
    }
    let mut out = Vec::new();
    for (key, line_no) in keys {
        if let Some(dep) =
            package_key(&key, version).map_err(|e| format!("pnpm-lock.yaml line {line_no}: {e}"))?
        {
            out.push(dep);
        }
    }
    Ok(out)
}

fn package_key(key: &str, format: u8) -> Result<Option<Dep>, String> {
    let key = key.strip_prefix('/').unwrap_or(key);
    // A URL/path may end in a version, but does not identify a registry package.
    let selector = key[usize::from(key.starts_with('@'))..]
        .split_once('@')
        .map_or(key, |(_, selector)| selector);
    let non_registry = |s: &str| {
        [
            "link:",
            "file:",
            "workspace:",
            "http:",
            "https:",
            "git:",
            "git+",
            "github:",
            "gitlab:",
            "bitbucket:",
            "ssh:",
        ]
        .iter()
        .any(|prefix| s.starts_with(prefix))
    };
    let remote_path = key.split_once('/').is_some_and(|(host, path)| {
        !host.starts_with('@')
            && !host.contains('@')
            && host.contains('.')
            && !matches!(host, "." | "..")
            && !path.as_bytes().first().is_some_and(u8::is_ascii_digit)
            && (format != 5 || path.contains('/'))
    });
    // Любой `протокол:` в селекторе — не реестр npm: `runtime:` (pnpm 10, бинарник Node),
    // `jsr:` и будущие. Пропускаем, а не роняем файл (ревью Claude, pnpm/pnpm lockfile).
    // Только вида `имя@протокол:…` — бессмысленный ключ без `имя@` остаётся ошибкой.
    let has_name = key[usize::from(key.starts_with('@'))..].contains('@');
    let protocol = has_name && selector.split('(').next().is_some_and(|s| s.contains(':'));
    if non_registry(key)
        || non_registry(selector)
        || protocol
        || key.starts_with("git@")
        || remote_path
        || key.ends_with(".tgz")
    {
        return Ok(None);
    }
    let base = key.split_once('(').map_or(key, |(base, _)| base);
    if base.len() != key.len() {
        let mut depth = 0usize;
        let mut previous = 0;
        for b in key[base.len()..].bytes() {
            match b {
                b'(' => depth += 1,
                b')' if depth > 0 && previous != b'(' => depth -= 1,
                b')' => return Err("invalid peer dependency suffix".into()),
                _ if depth == 0 => return Err("invalid peer dependency suffix".into()),
                _ => {}
            }
            previous = b;
        }
        if depth != 0 {
            return Err("unbalanced peer dependency suffix".into());
        }
    }
    let split = if format == 5 {
        // Split before the version, not inside a scoped peer suffix.
        let start = if base.starts_with('@') {
            base.find('/').map(|i| i + 1).unwrap_or(base.len())
        } else {
            0
        };
        base[start..]
            .find('/')
            .map(|i| (&base[..start + i], &base[start + i + 1..]))
    } else {
        base.rsplit_once('@')
    };
    let Some((name, version)) = split else {
        return Err("unrecognized package key (missing name/version separator)".into());
    };
    if !syntax::package_name(name) {
        return Err("invalid npm package name".into());
    }
    let version = if format == 5 {
        match version.split_once('_') {
            Some((_, "")) => return Err("empty peer dependency suffix".into()),
            Some((version, _)) => version,
            None => version,
        }
    } else {
        version
    };
    if !syntax::exact_version(version) {
        if syntax::range(version) {
            return Ok(None);
        }
        return Err("package key does not contain an exact npm version".into());
    }
    Ok(Some(Dep {
        name: name.into(),
        version: version.into(),
    }))
}

/// Lexical helpers shared with yarn.lock; no general YAML object tree is built.
pub(super) mod syntax {
    pub(crate) fn line(raw: &str) -> Result<(usize, &str), String> {
        let indent = raw.bytes().take_while(|b| *b == b' ').count();
        let text = &raw[indent..];
        if text.starts_with('\t') || text.chars().any(|c| c.is_control() && c != '\t') {
            return Err("invalid control character or tab indentation".into());
        }
        let mut i = 0;
        let bytes = text.as_bytes();
        while i < bytes.len() {
            match bytes[i] {
                b'\'' | b'"' => i = quoted_end(text, i)?,
                b'#' if i == 0 || bytes[i - 1].is_ascii_whitespace() => {
                    return Ok((indent, text[..i].trim_end()));
                }
                _ => i += 1,
            }
        }
        Ok((indent, text.trim_end()))
    }

    pub(crate) fn quoted_end(text: &str, start: usize) -> Result<usize, String> {
        let bytes = text.as_bytes();
        let quote = bytes[start];
        let mut i = start + 1;
        while i < bytes.len() {
            if quote == b'"' && bytes[i] == b'\\' {
                i += 2;
            } else if bytes[i] == quote {
                if quote == b'\'' && bytes.get(i + 1) == Some(&quote) {
                    i += 2;
                } else {
                    return Ok(i + 1);
                }
            } else {
                i += 1;
            }
        }
        Err("unterminated quoted scalar".into())
    }

    pub(crate) fn scalar(text: &str) -> Result<String, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("missing scalar value".into());
        }
        if text.starts_with(['\'', '"']) {
            if quoted_end(text, 0)? != text.len() {
                return Err("unexpected text after quoted scalar".into());
            }
            if text.starts_with('"') {
                return match crate::json::parse(text)? {
                    crate::json::Json::Str(value) => Ok(value),
                    _ => Err("expected a quoted string".into()),
                };
            }
            return Ok(text[1..text.len() - 1].replace("''", "'"));
        }
        if text.starts_with(['[', '{', '*', '&', '!', '|', '>'])
            || matches!(text, "null" | "~")
            || text.contains(['\'', '"'])
        {
            return Err("unsupported or invalid scalar".into());
        }
        Ok(text.into())
    }

    pub(crate) fn mapping(text: &str) -> Result<(String, &str), String> {
        let mut i = 0;
        let bytes = text.as_bytes();
        while i < bytes.len() {
            match bytes[i] {
                b'\'' | b'"' => i = quoted_end(text, i)?,
                b':' if bytes.get(i + 1).is_none_or(u8::is_ascii_whitespace) => {
                    return Ok((scalar(&text[..i])?, text[i + 1..].trim()));
                }
                _ => i += 1,
            }
        }
        Err("expected a mapping key followed by ':'".into())
    }

    // Values we do not need still must not hide a truncated collection. Full
    // YAML (anchors, block scalars, multiline flow/quoted scalars) is unsupported.
    pub(crate) fn value(text: &str) -> Result<(), String> {
        if text.is_empty() || matches!(text, "null" | "~") {
            return Ok(());
        }
        if !text.starts_with(['[', '{']) {
            scalar(text)?;
            return Ok(());
        }
        let mut stack = Vec::new();
        let mut i = 0;
        let bytes = text.as_bytes();
        while i < bytes.len() {
            match bytes[i] {
                b'\'' | b'"' => {
                    i = quoted_end(text, i)?;
                    continue;
                }
                b'[' => stack.push(b']'),
                b'{' => stack.push(b'}'),
                b']' | b'}' => {
                    if stack.pop() != Some(bytes[i]) {
                        return Err("mismatched flow collection delimiters".into());
                    }
                    if stack.is_empty() && i + 1 != bytes.len() {
                        return Err("unexpected text after flow collection".into());
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if !stack.is_empty() {
            return Err("unclosed or unsupported multiline flow collection".into());
        }
        Ok(())
    }

    pub(crate) fn digits(value: &str) -> bool {
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
    }

    pub(crate) fn package_name(name: &str) -> bool {
        let part = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        };
        if let Some(scoped) = name.strip_prefix('@') {
            scoped
                .split_once('/')
                .is_some_and(|(a, b)| part(a) && part(b))
        } else {
            part(name)
        }
    }

    pub(crate) fn exact_version(version: &str) -> bool {
        let (version, build) = version
            .split_once('+')
            .map_or((version, None), |(a, b)| (a, Some(b)));
        let (core, pre) = version
            .split_once('-')
            .map_or((version, None), |(a, b)| (a, Some(b)));
        let numeric = |s: &str| digits(s) && (s == "0" || !s.starts_with('0'));
        let identifiers = |s: &str, prerelease: bool| {
            s.split('.').all(|p| {
                !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && (!prerelease || !digits(p) || numeric(p))
            })
        };
        core.split('.').count() == 3
            && core.split('.').all(numeric)
            && pre.is_none_or(|p| identifiers(p, true))
            && build.is_none_or(|b| identifiers(b, false))
    }

    pub(crate) fn range(version: &str) -> bool {
        version.starts_with(['^', '~', '<', '>', '='])
            || version.contains("||")
            || version.contains(" - ")
            || version.split('.').any(|p| matches!(p, "*" | "x" | "X"))
            || ((1..=2).contains(&version.split('.').count()) && version.split('.').all(digits))
    }
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

    /// Как пишет pnpm 9+ (ревью Claude, по реальным файлам pnpm/vite/vue): два документа.
    #[test]
    fn v9_multi_document_files_are_merged() {
        let text = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies: {}\n\npackages:\n\n  pnpm@12.15.0:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  pnpm@12.15.0: {}\n\n---\nlockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: 4.17.21\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-y}\n";
        assert_eq!(
            deps(text),
            pairs(&[("pnpm", "12.15.0"), ("lodash", "4.17.21")])
        );
        // Ошибка во втором документе — номер строки от начала файла.
        let broken = format!("{text}\n  bad line without colon\n");
        let err = parse(&broken).unwrap_err();
        let expected = format!("line {}:", text.lines().count() + 2);
        assert!(err.contains(&expected), "{err} (want {expected})");
    }

    /// pnpm 10+: `node@runtime:` с вложенными списками маппингов (реальный pnpm/pnpm lockfile).
    #[test]
    fn runtime_entries_with_nested_sequences_are_skipped_not_fatal() {
        let text = "lockfileVersion: '9.0'\n\npackages:\n\n  node@runtime:26.12.1:\n    resolution:\n      type: variations\n      variants:\n        - resolution:\n            archive: tarball\n            bin:\n              node: bin/node\n            type: binary\n          targets:\n            - cpu: arm64\n              os: darwin\n    hasBin: true\n\n  ms@2.1.3:\n    resolution: {integrity: sha512-x}\n";
        assert_eq!(deps(text), pairs(&[("ms", "2.1.3")]));
    }

    #[test]
    fn v5_scopes_peers_and_local_packages() {
        let text = r#"lockfileVersion: 5.4
specifiers:
  alias: npm:real@^1
dependencies:
  alias: /real/1.2.3
packages:
  /real/1.2.3:
    resolution: {integrity: sha512-example}
    dev: false
  /@scope/plugin/2.0.0_react@18.0.0+@types+react@18.0.0:
    resolution: {integrity: sha512-example}
    peerDependencies:
      react: ^18
  /pre/1.0.0-rc.1+build.02:
    resolution: {integrity: sha512-example}
  file:../local:
    resolution: {directory: ../local, type: directory}
  link:../linked: {}
  workspace:../ws: {}
  github.com/owner/repo/abcdef: {}
"#;
        assert_eq!(
            deps(text),
            pairs(&[
                ("real", "1.2.3"),
                ("@scope/plugin", "2.0.0"),
                ("pre", "1.0.0-rc.1+build.02")
            ])
        );
    }

    #[test]
    fn v6_scopes_nested_peers_and_alias_targets() {
        let text = r#"lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:real@^1
        version: /real@1.2.3
packages:
  /real@1.2.3:
    resolution: {integrity: sha512-example}
  /@scope/plugin@2.1.0(@scope/peer@3.0.0)(react-dom@18.0.0(react@18.0.0)):
    resolution: {integrity: sha512-example}
    dependencies:
      react: 18.0.0
  /local@file:../local: {}
  /remote@https://example.invalid/pkg.tgz: {}
"#;
        assert_eq!(
            deps(text),
            pairs(&[("real", "1.2.3"), ("@scope/plugin", "2.1.0")])
        );
    }

    #[test]
    fn v9_packages_only_not_snapshots_or_importers() {
        let text = r#"lockfileVersion: '9.0' # generated
settings:
  autoInstallPeers: true
importers:
  .:
    dependencies:
      declared:
        specifier: ^9
        version: 9.0.0
packages:
  '@scope/name@1.2.3':
    resolution: {integrity: sha512-example}
    engines: {node: '>=18'}
    os:
      - win32
  "plain@2.0.0(react@18.0.0)": {}
  'https://example.invalid/package.tgz': {}
  'git+https://example.invalid/repo.git#abcdef': {}
snapshots:
  '@scope/name@1.2.3': {}
  snapshot-only@3.0.0: {}
"#;
        assert_eq!(
            deps(text),
            pairs(&[("@scope/name", "1.2.3"), ("plain", "2.0.0")])
        );
    }

    #[test]
    fn empty_mapping_and_bom_crlf_are_valid() {
        assert!(deps("lockfileVersion: '9.0'\npackages: {}\n").is_empty());
        assert!(deps("lockfileVersion: '6.0'\nsettings:\n  autoInstallPeers: true\n").is_empty());
        assert!(
            deps(
                "lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\nimporters:\n  .: {}\n"
            )
            .is_empty()
        );
        assert_eq!(
            deps("\u{feff}lockfileVersion: \"9.0\"\r\npackages:\r\n  a@1.2.3: {}\r\n"),
            pairs(&[("a", "1.2.3")])
        );
        assert!(deps("lockfileVersion: 5.3\npackages:\n  /a/^1.2.3: {}\n").is_empty());
    }

    #[test]
    fn peers_do_not_change_identity_or_hide_dotted_package_names() {
        assert_eq!(
            deps(
                "lockfileVersion: 5.4\npackages:\n  /name.with.dots/1.2.3_@scope/peer@2.0.0: {}\n  /@scope/pkg/2.0.0_@scope/peer@2.0.0: {}\n"
            ),
            pairs(&[("name.with.dots", "1.2.3"), ("@scope/pkg", "2.0.0")])
        );
        for (format, prefix) in [("6.0", "/"), ("9.0", "")] {
            let text = format!(
                "lockfileVersion: '{format}'\npackages:\n  '{prefix}plain@1.2.3(@scope/peer@2.0.0)': {{}}\n  '{prefix}plain@2.0.0(@scope/peer@2.0.0)': {{}}\n"
            );
            assert_eq!(
                deps(&text),
                pairs(&[("plain", "1.2.3"), ("plain", "2.0.0")])
            );
        }
    }

    #[test]
    fn malformed_metadata_or_wrong_key_format_does_not_return_partial_results() {
        let header = "lockfileVersion: '9.0'\npackages:\n  good@1.0.0: {}\n";
        for tail in [
            "  a/1.2.3: {}",
            "  a@1.2.3: []",
            "  bad:protocol: {}",
            "  a@1.2.3:\n    resolution: {integrity: example",
            "  a@1.2.3:\n    cpu: [x64}",
            "  a@1.2.3:\n    resolution: {} junk",
            "  a@1.2.3:\n    resolution: {}\n      nested: bad",
            "  a@1.2.3:\n    - not-a-mapping",
            "  a@1.2.3: {}\n    resolution: {}",
            "snapshots:\n  not a mapping",
        ] {
            let error = parse(&format!("{header}{tail}\n")).unwrap_err();
            assert!(error.contains("line"), "{error}");
        }
        assert!(parse("lockfileVersion: '9.0'\npackages:\nsnapshots: {}\n").is_err());
    }

    #[test]
    fn unicode_and_every_truncated_prefix_are_safe() {
        let text = "\u{feff}lockfileVersion: '9.0'\npackages:\n  'file:../пакет🦀':\n    resolution: {directory: '../пакет🦀', type: directory}\n  '@scope/pkg@1.2.3': {}\n";
        assert_eq!(deps(text), pairs(&[("@scope/pkg", "1.2.3")]));
        for end in text.char_indices().map(|(i, _)| i) {
            let _ = parse(&text[..end]);
        }
    }

    #[test]
    fn broken_or_unknown_input_is_an_error() {
        for text in [
            "",
            "not yaml",
            "lockfileVersion: '8.0'\npackages: {}",
            "packages: {}",
            "lockfileVersion: '9.0'",
            "lockfileVersion: '9.0'\npackages:",
            "lockfileVersion: '9.0'\npackages: []",
            "lockfileVersion: '9.0'\npackages:\n  a@1.2.3:",
            "lockfileVersion: '9.0'\npackages:\n    a@1.2.3: {}",
            "lockfileVersion: '9.0'\npackages:\n  a@1.2.3: {}\n  broken: {}",
            "lockfileVersion: '9.0'\npackages:\n  a@1.2.3: {}\n  b@bad: {}",
            "lockfileVersion: '9.0'\npackages:\n  a@1.2.3(react@18.0.0: {}",
            "lockfileVersion: '9.0'\npackages:\n  a@1.2.3(react@18.0.0)junk: {}",
            "lockfileVersion: '9.0'\npackages:\n  'a@1.2.3: {}",
            "lockfileVersion: '9.0'\npackages:\n\ta@1.2.3: {}",
            "lockfileVersion: '9.0'\npackages: {}\npackages: {}",
            "lockfileVersion: '9.0'\nlockfileVersion: '6.0'\npackages: {}",
        ] {
            assert!(
                parse(text).is_err(),
                "accepted malformed lockfile: {text:?}"
            );
        }
    }

    #[test]
    fn npm_versions_are_exact_and_names_are_not_paths() {
        for valid in ["0.0.0", "1.2.3", "1.2.3-beta.1+build.001"] {
            assert!(syntax::exact_version(valid));
        }
        for invalid in [
            "",
            "1",
            "1.2",
            "^1.2.3",
            "1.2.3.4",
            "01.2.3",
            "1.2.3-01",
            "1.2.3-",
            "1.2.3+",
            "1.2.3+bad+build",
            "1.2.3\n",
            "1.2.3/other",
        ] {
            assert!(!syntax::exact_version(invalid), "{invalid}");
        }
        for invalid in [
            "",
            "@scope",
            "@/name",
            "@scope/",
            "@scope/name/extra",
            "../local",
            "name with spaces",
        ] {
            assert!(!syntax::package_name(invalid), "{invalid}");
        }
    }
}
