//! `go.mod`: require directives with version-specific and wildcard replacements.
//! Versions retain their `v` prefix, including pseudo-versions and +incompatible.

use crate::deps::Dep;
use std::collections::BTreeMap;

pub fn parse(text: &str) -> Result<Vec<Dep>, String> {
    let mut required = Vec::new();
    let mut replacements = BTreeMap::new();
    let mut block: Option<String> = None;
    let mut seen = false;
    let mut module = false;
    for (line_no, line) in text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .enumerate()
    {
        let result = (|| {
            let mut tokens = tokens(line)?;
            if tokens.is_empty() {
                return Ok(());
            }
            seen = true;
            if tokens[0] == ")" {
                if tokens.len() != 1 || block.take().is_none() {
                    return Err("unexpected ')'".into());
                }
                return Ok(());
            }
            let directive = match &block {
                Some(name) => name.clone(),
                None => tokens.remove(0),
            };
            // Незнакомая директива из будущих версий Go (слово из строчных букв) —
            // пропускаем, а не роняем весь файл в «not checked» (ревью Claude).
            // Мусор вместо директивы — по-прежнему ошибка: это не go.mod.
            if !directive.bytes().all(|b| b.is_ascii_lowercase())
                && !matches!(
                    directive.as_str(),
                    "module"
                        | "go"
                        | "toolchain"
                        | "require"
                        | "replace"
                        | "exclude"
                        | "retract"
                        | "godebug"
                        | "tool"
                        | "ignore"
                )
            {
                return Err(format!("unknown directive {directive}"));
            }
            let opens = tokens.first().is_some_and(|t| t == "(");
            if opens {
                if block.is_some() || matches!(directive.as_str(), "module" | "go" | "toolchain") {
                    return Err("unexpected '('".into());
                }
                tokens.remove(0);
                block = Some(directive.clone());
            }
            let closes = tokens.last().is_some_and(|t| t == ")");
            if closes {
                if block.take().is_none() {
                    return Err("unexpected ')'".into());
                }
                tokens.pop();
            }
            if tokens.is_empty() && (opens || closes) {
                return Ok(());
            }
            if tokens.iter().any(|t| t == "(" || t == ")") {
                return Err("unexpected parenthesis".into());
            }
            match directive.as_str() {
                "require" | "exclude" => {
                    if tokens.len() != 2 {
                        return Err(format!("{directive} needs a module and version"));
                    }
                    validate_module(&tokens[0])?;
                    if pinned(&tokens[1])? && directive == "require" && !local(&tokens[0]) {
                        required.push(Dep {
                            name: tokens[0].clone(),
                            version: tokens[1].clone(),
                        });
                    }
                }
                "replace" => {
                    let arrow = tokens
                        .iter()
                        .position(|t| t == "=>")
                        .ok_or("replace is missing '=>'")?;
                    if !(1..=2).contains(&arrow) {
                        return Err("invalid replace source".into());
                    }
                    validate_module(&tokens[0])?;
                    let version = if arrow == 2 {
                        if !pinned(&tokens[1])? {
                            return Err("replace source needs an exact version".into());
                        }
                        Some(tokens[1].clone())
                    } else {
                        None
                    };
                    let target = &tokens[arrow + 1..];
                    let replacement = match target {
                        [path] if local(path) => None,
                        [name, version] if !local(name) => {
                            validate_module(name)?;
                            if !pinned(version)? {
                                return Err("replace target needs an exact version".into());
                            }
                            Some(Dep {
                                name: name.clone(),
                                version: version.clone(),
                            })
                        }
                        _ => {
                            return Err(
                                "replace target needs a local path or module and version".into()
                            );
                        }
                    };
                    if replacements
                        .insert((tokens[0].clone(), version), replacement)
                        .is_some()
                    {
                        return Err("duplicate replace directive".into());
                    }
                }
                "module" => {
                    if tokens.len() != 1 || module {
                        return Err("invalid or duplicate module directive".into());
                    }
                    validate_module(&tokens[0])?;
                    module = true;
                }
                "go" => {
                    if tokens.len() != 1
                        || !(2..=3).contains(&tokens[0].split('.').count())
                        || !tokens[0]
                            .split('.')
                            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                    {
                        return Err("invalid go version".into());
                    }
                }
                "toolchain" | "tool" | "ignore" | "godebug" => {
                    if tokens.len() != 1 {
                        return Err(format!("{directive} needs one argument"));
                    }
                }
                "retract" => {
                    let version = tokens.join("");
                    if let Some(range) = version.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
                    {
                        let (a, b) = range.split_once(',').ok_or("invalid retract range")?;
                        if !pinned(a)? || !pinned(b)? {
                            return Err("invalid retract range".into());
                        }
                    } else if !pinned(&version)? {
                        return Err("invalid retract version".into());
                    }
                }
                // Голое слово без аргументов — не директива, а мусор: это не go.mod.
                _ if tokens.is_empty() => {
                    return Err(format!("unknown directive {directive} without arguments"));
                }
                _ => {} // будущая директива: на зависимости не влияет (см. выше)
            }
            Ok(())
        })();
        result.map_err(|e: String| format!("go.mod line {}: {e}", line_no + 1))?;
    }
    if let Some(block) = block {
        return Err(format!("go.mod: unclosed {block} block"));
    }
    if !seen {
        return Err("go.mod: no directives found".into());
    }
    // Resolve after reading the entire file: replacements can precede require.
    // Exact-version replacements take priority over an all-versions replacement.
    Ok(required
        .into_iter()
        .filter_map(|dep| {
            replacements
                .get(&(dep.name.clone(), Some(dep.version.clone())))
                .or_else(|| replacements.get(&(dep.name.clone(), None)))
                .cloned()
                .unwrap_or(Some(dep))
        })
        .collect())
}

fn local(path: &str) -> bool {
    path == "."
        || path == ".."
        || path.starts_with("./")
        || path.starts_with("../")
        || path.starts_with('/')
        || path.starts_with(".\\")
        || path.starts_with("..\\")
        || path.starts_with("\\\\")
        || path.as_bytes().get(1) == Some(&b':')
}

fn validate_module(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "@<>=()\"'".contains(c))
        || (!local(name) && (name.contains(':') || name.contains('\\')))
    {
        Err("invalid module path".into())
    } else {
        Ok(())
    }
}

fn pinned(version: &str) -> Result<bool, String> {
    if version.contains(['*', '<', '>', '~', '^', '=', ','])
        || version.split('.').any(|p| p == "x" || p == "X")
    {
        return Ok(false);
    }
    let Some(v) = version.strip_prefix('v') else {
        return Err("module version must start with 'v'".into());
    };
    let (v, build) = v.split_once('+').map_or((v, None), |(a, b)| (a, Some(b)));
    let (core, pre) = v.split_once('-').map_or((v, None), |(a, b)| (a, Some(b)));
    let identifiers = |value: &str, prerelease: bool| {
        value.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !(prerelease
                    && part.len() > 1
                    && part.starts_with('0')
                    && part.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    if core.split('.').count() != 3
        || !core.split('.').all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p == "0" || !p.starts_with('0'))
        })
        || pre.is_some_and(|s| !identifiers(s, true))
        || build.is_some_and(|s| !identifiers(s, false))
    {
        return Err("invalid module version".into());
    }
    Ok(true)
}

// Comments only start outside quoted tokens (quoted local paths may contain //).
fn tokens(line: &str) -> Result<Vec<String>, String> {
    let mut chars = line.chars().peekable();
    let mut out = Vec::new();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            break;
        }
        if c == '(' || c == ')' {
            out.push(c.to_string());
            continue;
        }
        if c == '=' && chars.peek() == Some(&'>') {
            chars.next();
            out.push("=>".into());
            continue;
        }
        let mut token = String::new();
        if c == '"' || c == '`' {
            loop {
                let next = chars.next().ok_or("unterminated quoted token")?;
                if next == c {
                    break;
                }
                if next == '\\' && c == '"' {
                    token.push(match chars.next().ok_or("unfinished escape")? {
                        '\\' => '\\',
                        '"' => '"',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => return Err("unsupported quoted escape".into()),
                    });
                } else {
                    token.push(next);
                }
            }
            if chars
                .peek()
                .is_some_and(|c| !c.is_whitespace() && *c != ')')
            {
                return Err("missing space after quoted token".into());
            }
        } else {
            token.push(c);
            while let Some(&next) = chars.peek() {
                if next.is_whitespace() || next == '(' || next == ')' {
                    break;
                }
                if next == '/' && chars.clone().nth(1) == Some('/') {
                    break;
                }
                if next == '=' && chars.clone().nth(1) == Some('>') {
                    break;
                }
                token.push(next);
                chars.next();
            }
        }
        out.push(token);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(deps: Vec<Dep>) -> Vec<(String, String)> {
        deps.into_iter().map(|d| (d.name, d.version)).collect()
    }

    #[test]
    fn require_blocks_comments_and_versions() {
        let text = "\u{feff}module example.org/app\r\ngo 1.24.0\r\ntoolchain go1.24.1\r\n\
            require golang.org/x/text v0.22.0 // indirect\n\
            require (\n\
              example.org/Upper/Case v2.0.0+incompatible // comment\n\
              example.org/pseudo v0.0.0-20240102030405-abcdef123456\n\
              example.org/pre v1.2.3-rc.1\n\
            )\n\
            exclude example.org/old v1.0.0\nretract [v1.0.0, v1.0.1]\n";
        assert_eq!(
            pairs(parse(text).unwrap()),
            vec![
                ("golang.org/x/text".into(), "v0.22.0".into()),
                (
                    "example.org/Upper/Case".into(),
                    "v2.0.0+incompatible".into()
                ),
                (
                    "example.org/pseudo".into(),
                    "v0.0.0-20240102030405-abcdef123456".into()
                ),
                ("example.org/pre".into(), "v1.2.3-rc.1".into()),
            ]
        );
    }

    #[test]
    fn replacements_apply_after_require_and_exact_version_wins() {
        let text = r#"replace (
  example.org/a => example.org/fork v1.5.0
  example.org/a v1.0.0 => example.org/specific v1.6.0
  example.org/b => ../local
  example.org/c v1.0.0 => "C:\\work\\local"
  example.org/unused => example.org/no-dependency v1.0.0
)
require (
 example.org/a v1.0.0
 example.org/a v1.1.0
 example.org/b v1.0.0
 example.org/c v1.0.0
 example.org/c v1.1.0
)
replace example.org/specific => example.org/not-recursive v2.0.0
"#;
        assert_eq!(
            pairs(parse(text).unwrap()),
            vec![
                ("example.org/specific".into(), "v1.6.0".into()),
                ("example.org/fork".into(), "v1.5.0".into()),
                ("example.org/c".into(), "v1.1.0".into()),
            ]
        );
    }

    #[test]
    fn quoted_modules_empty_blocks_and_ranges() {
        assert_eq!(
            parse("require ( \"example.org/a\" \"v1.0.0\" )").unwrap()[0].name,
            "example.org/a"
        );
        assert!(
            parse("module example.org/app\nrequire (\n)\n")
                .unwrap()
                .is_empty()
        );
        assert!(
            parse("require example.org/a >=v1.0.0\nrequire example.org/b v1.*")
                .unwrap()
                .is_empty()
        );
        assert!(
            parse("require example.org/a v1.0.0\nreplace example.org/a => ./local")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn future_directives_do_not_void_the_file() {
        let text = "module example.com/app

go 1.30
futurething example.com/x v1.0.0
newblock (
	a b
	c d
)
require golang.org/x/text v0.3.0
";
        let deps = parse(text).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "golang.org/x/text");
        // Не строчное слово — не директива go.mod.
        assert!(
            parse(
                "module a
Require x v1.0.0"
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_files_fail() {
        for text in [
            "",
            "// comment",
            "nonsense",
            "require",
            "require x",
            "require x v1.0.0 extra",
            "require (\nx v1.0.0",
            ")",
            "require x version",
            "require x v1.2",
            "require (\nrequire (\n)",
            "replace x",
            "replace x =>",
            "replace x => remote",
            "replace x => ../local v1.0.0",
            "replace x => y v1.0.0 extra",
            "replace x => y v1.0.0\nreplace x => z v1.0.0",
            "require \"unclosed v1.0.0",
            "require x v1.0.0\nbroken",
            "module",
            "module a\nmodule b",
            "go nope",
            "go 1.2.3.4",
            "require x v01.2.3",
            "require x v1.2.3-a..b",
            "require x v1.2.3-01",
            "require x v1.2.3+build+other",
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }
}
