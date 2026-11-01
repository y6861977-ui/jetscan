//! `jetscan deps --fix` (T4.1): план исправления — точные команды под менеджер пакетов.
//! Файлы проекта НЕ правим и ничего не запускаем: команды печатаются, решает человек.
//!
//! Тонкости, из-за которых «просто npm install x@y» не работает:
//! - Транзитивную зависимость так не обновить — нужен `overrides` (npm), `resolutions`
//!   (yarn), `pnpm.overrides` (pnpm). Прямая она или нет — по package.json рядом с lockfile.
//! - Команду копируют в терминал: имя и версия из lockfile'а — недоверенные. Только
//!   безопасный алфавит, иначе вместо команды — предупреждение (никакой инъекции в шелл).

use super::scan::{DepsReport, Upgrade};
use super::{Ecosystem, Package};
use crate::json::{self, Json};
use std::fs;
use std::path::Path;

/// Один шаг плана.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// lockfile, к которому относится (относительно корня скана).
    pub lockfile: String,
    pub package: String,
    pub from: String,
    pub to: String,
    /// Команда для терминала, или `None`, если это правка файла (см. `edit`).
    pub command: Option<String>,
    /// Что дописать в манифест (overrides/resolutions), если команды нет.
    pub edit: Option<String>,
    pub note: Option<&'static str>,
}

/// Безопасно ли вставить строку в команду без кавычек.
fn shell_safe(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@/._-+~".contains(&b))
}

/// Прямые зависимости из package.json рядом с lockfile'ом (npm/yarn/pnpm).
fn direct_npm_deps(project: &Path) -> Vec<String> {
    let Some(doc) = fs::read_to_string(project.join("package.json"))
        .ok()
        .and_then(|t| json::parse(t.trim_start_matches('\u{feff}')).ok())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(m) = doc.get(section).and_then(Json::as_object) {
            out.extend(m.keys().cloned());
        }
    }
    out
}

fn step_for(root: &Path, lockfile: &str, p: &Package, to: &str) -> Step {
    let base = Step {
        lockfile: lockfile.to_string(),
        package: p.name.clone(),
        from: p.version.clone(),
        to: to.to_string(),
        command: None,
        edit: None,
        note: None,
    };
    if !shell_safe(&p.name) || !shell_safe(to) {
        return Step {
            note: Some("unusual characters in name/version — not printing a command; fix by hand"),
            ..base
        };
    }
    let file = lockfile.rsplit('/').next().unwrap_or(lockfile);
    let project = root.join(lockfile.rsplit_once('/').map_or("", |(dir, _)| dir));
    let (name, v) = (&p.name, to);
    let npm_like = |add: &str, field: &str| {
        if direct_npm_deps(&project).contains(name) {
            Step {
                command: Some(format!("{add} {name}@{v}")),
                ..base.clone()
            }
        } else {
            Step {
                edit: Some(format!(
                    "package.json: \"{field}\": {{ \"{name}\": \"{v}\" }}"
                )),
                note: Some("transitive dependency — pin it, then reinstall"),
                ..base.clone()
            }
        }
    };
    match (p.ecosystem, file) {
        (Ecosystem::Npm, "yarn.lock") => npm_like("yarn add", "resolutions"),
        (Ecosystem::Npm, "pnpm-lock.yaml") => npm_like("pnpm add", "pnpm.overrides"),
        (Ecosystem::Npm, _) => npm_like("npm install", "overrides"),
        (Ecosystem::CratesIo, _) => Step {
            command: Some(format!("cargo update -p {name} --precise {v}")),
            note: Some("if cargo refuses, raise the version requirement in Cargo.toml"),
            ..base
        },
        (Ecosystem::Go, _) => {
            let v = if v.starts_with('v') {
                v.to_string()
            } else {
                format!("v{v}")
            };
            Step {
                command: Some(format!("go get {name}@{v} && go mod tidy")),
                ..base
            }
        }
        (Ecosystem::PyPI, "poetry.lock") => Step {
            command: Some(format!("poetry add \"{name}>={v}\"")),
            ..base
        },
        (Ecosystem::PyPI, "uv.lock") => Step {
            command: Some(format!("uv lock --upgrade-package {name}=={v}")),
            ..base
        },
        (Ecosystem::PyPI, "Pipfile.lock") => Step {
            command: Some(format!("pipenv install \"{name}>={v}\"")),
            ..base
        },
        (Ecosystem::PyPI, _) => Step {
            edit: Some(format!("{file}: {name}=={v}")),
            ..base
        },
        (Ecosystem::Maven, _) => Step {
            edit: Some(format!("pom.xml / build.gradle: {name} → {v}")),
            ..base
        },
    }
}

/// План: по шагу на (пакет, lockfile) для всего, у чего есть исправление.
/// Вредоносные пакеты не «обновляются» — их удаляют (в плане отдельной строкой).
pub fn plan(r: &DepsReport) -> Vec<Step> {
    let malicious = r.malicious_packages();
    let mut out = Vec::new();
    for Upgrade { package, to, .. } in r.upgrades() {
        if malicious.contains(&package) {
            for l in &package.lockfiles {
                out.push(Step {
                    lockfile: l.clone(),
                    package: package.name.clone(),
                    from: package.version.clone(),
                    to: String::new(),
                    command: None,
                    edit: None,
                    note: Some("MALICIOUS — remove it and the dependency that pulled it in"),
                });
            }
            continue;
        }
        let Some(to) = to else { continue };
        for l in &package.lockfiles {
            out.push(step_for(&r.root, l, package, &to));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(eco: Ecosystem, name: &str, version: &str, lock: &str) -> Package {
        Package {
            ecosystem: eco,
            name: name.into(),
            version: version.into(),
            lockfiles: vec![lock.into()],
        }
    }

    #[test]
    fn direct_vs_transitive_npm_and_other_managers() {
        let d = std::env::temp_dir().join(format!("jetscan-fix-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("web")).unwrap();
        fs::write(
            d.join("package.json"),
            r#"{"dependencies":{"axios":"^0.21.0"}}"#,
        )
        .unwrap();
        fs::write(
            d.join("web/package.json"),
            r#"{"devDependencies":{"vite":"5"}}"#,
        )
        .unwrap();

        let s = step_for(
            &d,
            "package-lock.json",
            &pkg(Ecosystem::Npm, "axios", "0.21.0", ""),
            "0.33.0",
        );
        assert_eq!(s.command.as_deref(), Some("npm install axios@0.33.0"));
        let s = step_for(
            &d,
            "package-lock.json",
            &pkg(Ecosystem::Npm, "minimist", "1.2.5", ""),
            "1.2.6",
        );
        assert_eq!(s.command, None);
        assert_eq!(
            s.edit.as_deref(),
            Some("package.json: \"overrides\": { \"minimist\": \"1.2.6\" }")
        );
        let s = step_for(
            &d,
            "web/pnpm-lock.yaml",
            &pkg(Ecosystem::Npm, "vite", "5.4.21", ""),
            "6.4.4",
        );
        assert_eq!(s.command.as_deref(), Some("pnpm add vite@6.4.4"));
        let s = step_for(
            &d,
            "web/yarn.lock",
            &pkg(Ecosystem::Npm, "nanoid", "3.3.1", ""),
            "3.3.8",
        );
        assert!(s.edit.unwrap().contains("\"resolutions\""));

        let s = step_for(
            &d,
            "Cargo.lock",
            &pkg(Ecosystem::CratesIo, "quick-xml", "0.36.2", ""),
            "0.41.0",
        );
        assert_eq!(
            s.command.as_deref(),
            Some("cargo update -p quick-xml --precise 0.41.0")
        );
        let s = step_for(
            &d,
            "go.mod",
            &pkg(Ecosystem::Go, "github.com/google/cel-go", "v0.29.2", ""),
            "v0.30.0",
        );
        assert_eq!(
            s.command.as_deref(),
            Some("go get github.com/google/cel-go@v0.30.0 && go mod tidy")
        );
        let s = step_for(
            &d,
            "requirements.txt",
            &pkg(Ecosystem::PyPI, "django", "3.2.0", ""),
            "3.2.25",
        );
        assert_eq!(s.edit.as_deref(), Some("requirements.txt: django==3.2.25"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn hostile_names_never_become_commands() {
        let d = std::env::temp_dir();
        for (name, to) in [
            ("x; rm -rf ~", "1.0.0"),
            ("x", "1.0.0 && curl evil"),
            ("$(id)", "1.0.0"),
            ("--registry=evil", "1.0.0"),
            ("x`id`", "1.0.0"),
        ] {
            let s = step_for(
                &d,
                "package-lock.json",
                &pkg(Ecosystem::Npm, name, "0.1.0", ""),
                to,
            );
            assert!(s.command.is_none() && s.edit.is_none(), "{name} {to}");
            assert!(s.note.is_some());
        }
    }
}
