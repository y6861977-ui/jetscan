//! CL-WEB-01: определение фреймворка без исполнения и без сборки.
//! Читаем только корневой `package.json` (с лимитом размера) и смотрим на дерево каталогов.
//! Нет манифеста → режим `generic`, а не ошибка. Битый манифест → `generic` + честная причина.

use crate::json::{self, Json};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Больше — не читаем: `package.json` на мегабайт — не манифест, а что-то странное.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameworkKind {
    NextJs,
    ViteReact,
    /// Нет признаков поддержанного фреймворка: общие правила, без знания границы клиент/сервер.
    Generic,
    /// Узнали фреймворк, но его семантику не поддерживаем (Nuxt, SvelteKit, ...): работаем как generic.
    Unsupported,
}

impl FrameworkKind {
    pub fn label(self) -> &'static str {
        match self {
            FrameworkKind::NextJs => "nextjs",
            FrameworkKind::ViteReact => "vite-react",
            FrameworkKind::Generic => "generic",
            FrameworkKind::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Manifest {
    Found,
    Missing,
    /// Не прочитали (права, слишком большой, симлинк). Причина — для отчёта.
    Unreadable(String),
    /// Прочитали, но это не JSON-объект. Причина — для отчёта.
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameworkInfo {
    pub kind: FrameworkKind,
    pub manifest: Manifest,
    /// Имя неподдержанного фреймворка (`nuxt`, `@sveltejs/kit`), если `kind == Unsupported`.
    pub unsupported: Option<String>,
    /// Строка версии из манифеста как есть (`^14.2.3`) — не интерпретируем.
    pub version: Option<String>,
    /// Каталоги App Router, от корня (`app`, `src/app`).
    pub app_dirs: Vec<String>,
    /// Каталоги Pages Router (`pages`, `src/pages`).
    pub pages_dirs: Vec<String>,
    /// В зависимостях есть клиент Supabase — для WEB-SUPABASE-005 и проверки RLS.
    pub uses_supabase: bool,
    /// В зависимостях есть Firebase или в корне `firebase.json` — для проверки WEB-FIREBASE-010.
    pub uses_firebase: bool,
    /// Vite: каталог точки входа из `<script type="module" src="…">` в `index.html`
    /// (`src`, или `""` — корень проекта). `None` — входа не нашли, считаем `src`.
    pub vite_entry_dir: Option<String>,
    /// Что важно знать о распознавании (для `limitations`).
    pub notes: Vec<String>,
}

impl FrameworkInfo {
    pub fn app_router(&self) -> bool {
        self.kind == FrameworkKind::NextJs && !self.app_dirs.is_empty()
    }

    pub fn pages_router(&self) -> bool {
        self.kind == FrameworkKind::NextJs && !self.pages_dirs.is_empty()
    }
}

/// Мажорная версия Next.js из строки зависимости (`^16.4.3` → 16); `None` — не Next или не разобрать
/// (`canary`, `latest`, тег, путь).
pub fn next_major(framework: &FrameworkInfo) -> Option<u32> {
    if framework.kind != FrameworkKind::NextJs {
        return None;
    }
    let v = framework.version.as_deref()?;
    let digits: String = v
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Мета-фреймворки, чью границу клиент/сервер мы не понимаем. Порядок — приоритет.
const UNSUPPORTED: &[&str] = &[
    "nuxt",
    "@sveltejs/kit",
    "@remix-run/react",
    "@react-router/dev",
    "astro",
    "gatsby",
    "@angular/core",
    "@builder.io/qwik",
    "solid-js",
    "vue",
    "svelte",
];

pub fn detect(root: &Path) -> FrameworkInfo {
    let (manifest, deps) = read_manifest(&root.join("package.json"));
    let dep = |name: &str| deps.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    let mut info = FrameworkInfo {
        kind: FrameworkKind::Generic,
        manifest: manifest.clone(),
        unsupported: None,
        version: None,
        app_dirs: Vec::new(),
        pages_dirs: Vec::new(),
        uses_supabase: dep("@supabase/supabase-js").is_some()
            || dep("@supabase/ssr").is_some()
            || dep("@supabase/auth-helpers-nextjs").is_some()
            || is_dir(&root.join("supabase")),
        uses_firebase: [
            "firebase",
            "firebase-admin",
            "reactfire",
            "@angular/fire",
            "vuefire",
        ]
        .iter()
        .any(|d| dep(d).is_some())
            || is_file(&root.join("firebase.json")),
        vite_entry_dir: None,
        notes: Vec::new(),
    };
    match &manifest {
        Manifest::Found => {}
        Manifest::Missing => info
            .notes
            .push("no package.json: framework inferred from files only".to_string()),
        Manifest::Unreadable(why) | Manifest::Invalid(why) => info.notes.push(format!(
            "package.json could not be used ({why}): framework inferred from files only"
        )),
    }

    let has_config = |stem: &str| {
        ["js", "mjs", "cjs", "ts", "mts", "cts"]
            .iter()
            .any(|ext| is_file(&root.join(format!("{stem}.{ext}"))))
    };

    if let Some(version) = dep("next") {
        info.kind = FrameworkKind::NextJs;
        info.version = Some(version);
    } else if manifest != Manifest::Found && has_config("next.config") {
        info.kind = FrameworkKind::NextJs;
        info.notes
            .push("Next.js recognised by next.config only (no usable package.json)".to_string());
    } else if let Some(name) = UNSUPPORTED.iter().find(|name| dep(name).is_some()) {
        info.kind = FrameworkKind::Unsupported;
        info.unsupported = Some(name.to_string());
        info.notes.push(format!(
            "{name} is not supported: client/server boundaries are not understood, generic checks only"
        ));
    } else if let Some(version) = dep("vite") {
        let react = ["react", "@vitejs/plugin-react", "@vitejs/plugin-react-swc"]
            .iter()
            .any(|name| dep(name).is_some());
        if react {
            info.kind = FrameworkKind::ViteReact;
            info.version = Some(version);
        } else {
            info.notes
                .push("vite without React: generic checks only".to_string());
        }
    } else if manifest != Manifest::Found && has_config("vite.config") {
        info.kind = FrameworkKind::ViteReact;
        info.notes.push(
            "Vite recognised by vite.config only (no usable package.json); React assumed"
                .to_string(),
        );
    } else if has_config("vite.config")
        && ["react", "@vitejs/plugin-react", "@vitejs/plugin-react-swc"]
            .iter()
            .any(|name| dep(name).is_some())
    {
        // Полевой тест 2026-11-12, W1: в монорепо `vite` часто только в корневом package.json.
        info.kind = FrameworkKind::ViteReact;
        info.notes.push(
            "Vite recognised by vite.config + React (vite itself is not a dependency here, \
             probably installed at the workspace root)"
                .to_string(),
        );
    }
    if info.kind == FrameworkKind::ViteReact {
        info.vite_entry_dir = vite_entry_dir(root);
    }

    if info.kind == FrameworkKind::NextJs {
        for dir in ["app", "src/app"] {
            if is_dir(&root.join(dir)) {
                info.app_dirs.push(dir.to_string());
            }
        }
        for dir in ["pages", "src/pages"] {
            if is_dir(&root.join(dir)) {
                info.pages_dirs.push(dir.to_string());
            }
        }
        if info.app_dirs.is_empty() && info.pages_dirs.is_empty() {
            info.notes.push(
                "Next.js without app/ or pages/ at the root or in src/: route files not recognised"
                    .to_string(),
            );
        }
    }
    // Полевой тест 2026-11-12, W2: монорепо узнаём и по pnpm/lerna/turbo/nx/rush, а не только по
    // ключу `workspaces`, и называем вложенные приложения, которые стоит сканировать по отдельности.
    let markers = [
        "pnpm-workspace.yaml",
        "lerna.json",
        "turbo.json",
        "nx.json",
        "rush.json",
    ];
    let workspace = deps.iter().any(|(name, _)| name == "workspaces")
        || markers.iter().any(|m| is_file(&root.join(m)));
    if workspace {
        let apps = nested_apps(root);
        let note = if apps.is_empty() {
            "workspace root: nested packages are not detected separately; point the scan at the app folder"
                .to_string()
        } else {
            let listed: Vec<String> = apps
                .iter()
                .take(MAX_LISTED_APPS)
                .map(|(dir, kind)| format!("{dir} ({})", kind.label()))
                .collect();
            let more = apps.len().saturating_sub(MAX_LISTED_APPS);
            format!(
                "workspace root: framework rules apply per app; scan each app folder separately \
                 (e.g. `jetscan web source {}`). Apps found: {}{}",
                apps[0].0,
                listed.join(", "),
                if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                }
            )
        };
        info.notes.push(note);
    }
    info
}

const MAX_LISTED_APPS: usize = 8;

/// `apps/*` и `packages/*` с Next.js или Vite+React в package.json (без рекурсии, с лимитом).
fn nested_apps(root: &Path) -> Vec<(String, FrameworkKind)> {
    let mut found = Vec::new();
    for parent in ["apps", "packages"] {
        let Ok(entries) = fs::read_dir(root.join(parent)) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names.into_iter().take(200) {
            let (manifest, deps) =
                read_manifest(&root.join(parent).join(&name).join("package.json"));
            if manifest != Manifest::Found {
                continue;
            }
            let has = |n: &str| {
                deps.iter().any(|(d, _)| d == n)
                    // W1: `vite` бывает только в корне — тогда признак Vite-приложения — его vite.config.
                    || (n == "vite"
                        && ["js", "mjs", "cjs", "ts", "mts", "cts"].iter().any(|ext| {
                            is_file(&root.join(parent).join(&name).join(format!("vite.config.{ext}")))
                        }))
            };
            let kind = if has("next") {
                FrameworkKind::NextJs
            } else if has("react")
                && (has("vite") || has("@vitejs/plugin-react") || has("@vitejs/plugin-react-swc"))
            {
                FrameworkKind::ViteReact
            } else {
                continue;
            };
            found.push((
                format!("{parent}/{}", crate::ui::sanitize_line(&name)),
                kind,
            ));
        }
    }
    found
}

/// Каталог модуля-входа Vite из `index.html` (`<script type="module" src="/src/main.tsx">` → `src`).
fn vite_entry_dir(root: &Path) -> Option<String> {
    let path = root.join("index.html");
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let html = fs::read_to_string(&path).ok()?;
    let mut rest = html.as_str();
    while let Some(at) = rest.find("<script") {
        let tag_end = rest[at..].find('>').map(|e| at + e)?;
        let tag = &rest[at..tag_end];
        rest = &rest[tag_end..];
        if !(tag.contains("type=\"module\"") || tag.contains("type='module'")) {
            continue;
        }
        let Some(src_at) = tag.find("src=") else {
            continue;
        };
        let value = &tag[src_at + 4..];
        let quote = value.chars().next()?;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let src = value[1..].split(quote).next()?;
        if src.contains("://") || src.starts_with("//") {
            continue;
        }
        let src = src.trim_start_matches("./").trim_start_matches('/');
        let dir = src.rsplit_once('/').map_or("", |(d, _)| d);
        if dir.split('/').any(|seg| seg == "..") {
            return None;
        }
        return Some(dir.to_string());
    }
    None
}

/// Манифест и плоский список зависимостей (dependencies + devDependencies + peerDependencies).
/// Ключ `workspaces` тоже кладём в список (с пустой версией) — это признак монорепо.
fn read_manifest(path: &Path) -> (Manifest, Vec<(String, String)>) {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Manifest::Missing, vec![]),
        Err(_) => return (Manifest::Unreadable("cannot stat".to_string()), vec![]),
    };
    if meta.file_type().is_symlink() {
        return (
            Manifest::Unreadable("symlink, not followed".to_string()),
            vec![],
        );
    }
    if !meta.is_file() {
        return (Manifest::Unreadable("not a file".to_string()), vec![]);
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return (
            Manifest::Unreadable("larger than 1 MiB".to_string()),
            vec![],
        );
    }
    let mut bytes = Vec::new();
    let read = fs::File::open(path)
        .and_then(|file| file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes));
    if read.is_err() {
        return (Manifest::Unreadable("read error".to_string()), vec![]);
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return (Manifest::Invalid("not UTF-8".to_string()), vec![]);
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let parsed = match json::parse(text) {
        Ok(value) => value,
        Err(_) => return (Manifest::Invalid("not valid JSON".to_string()), vec![]),
    };
    let Some(object) = parsed.as_object() else {
        return (Manifest::Invalid("not a JSON object".to_string()), vec![]);
    };
    let mut deps = Vec::new();
    for section in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(Json::Obj(map)) = object.get(section) {
            for (name, version) in map {
                deps.push((name.clone(), version.as_str().unwrap_or("").to_string()));
            }
        }
    }
    if object.contains_key("workspaces") {
        deps.push(("workspaces".to_string(), String::new()));
    }
    deps.sort();
    (Manifest::Found, deps)
}

/// Каталог и не симлинк (симлинки не разыменовываем нигде, кроме корня).
fn is_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn is_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::{TempProject, fixture};

    #[test]
    fn next_app_router_fixture() {
        let project = fixture("next-app");
        let info = detect(project.path());
        assert_eq!(info.kind, FrameworkKind::NextJs);
        assert!(info.app_router());
        assert!(!info.pages_router());
        assert_eq!(info.manifest, Manifest::Found);
        assert!(info.version.is_some());
        assert!(info.uses_supabase);
    }

    #[test]
    fn next_pages_router_fixture() {
        let project = fixture("next-pages");
        let info = detect(project.path());
        assert_eq!(info.kind, FrameworkKind::NextJs);
        assert!(info.pages_router());
        assert!(!info.app_router());
    }

    #[test]
    fn vite_react_fixture() {
        let project = fixture("vite-react");
        let info = detect(project.path());
        assert_eq!(info.kind, FrameworkKind::ViteReact);
        assert!(info.app_dirs.is_empty() && info.pages_dirs.is_empty());
    }

    #[test]
    fn src_dir_routers_and_hybrid() {
        let t = TempProject::new();
        t.write(
            "package.json",
            r#"{"dependencies":{"next":"15.0.0","react":"19"}}"#,
        );
        t.write(
            "src/app/page.tsx",
            "export default function P() { return null }",
        );
        t.write(
            "src/pages/old.tsx",
            "export default function O() { return null }",
        );
        let info = detect(t.path());
        assert_eq!(info.app_dirs, vec!["src/app".to_string()]);
        assert_eq!(info.pages_dirs, vec!["src/pages".to_string()]);
    }

    #[test]
    fn missing_manifest_is_generic_not_failure() {
        let t = TempProject::new();
        t.write("index.js", "console.log(1)");
        let info = detect(t.path());
        assert_eq!(info.kind, FrameworkKind::Generic);
        assert_eq!(info.manifest, Manifest::Missing);
        assert!(!info.notes.is_empty());
    }

    #[test]
    fn broken_manifest_is_reported_not_silently_generic() {
        let project = fixture("broken-manifest");
        let info = detect(project.path());
        assert!(matches!(info.manifest, Manifest::Invalid(_)));
        assert_eq!(info.kind, FrameworkKind::Generic);
        assert!(info.notes.iter().any(|n| n.contains("package.json")));
    }

    #[test]
    fn next_config_without_manifest_still_next() {
        let t = TempProject::new();
        t.write("next.config.mjs", "export default {}");
        t.write(
            "app/page.tsx",
            "export default function P() { return null }",
        );
        let info = detect(t.path());
        assert_eq!(info.kind, FrameworkKind::NextJs);
        assert!(info.app_router());
    }

    #[test]
    fn unsupported_framework_is_named() {
        let project = fixture("unsupported-nuxt");
        let info = detect(project.path());
        assert_eq!(info.kind, FrameworkKind::Unsupported);
        assert_eq!(info.unsupported.as_deref(), Some("nuxt"));
    }

    #[test]
    fn vite_without_react_is_generic() {
        let t = TempProject::new();
        t.write("package.json", r#"{"devDependencies":{"vite":"5"}}"#);
        let info = detect(t.path());
        assert_eq!(info.kind, FrameworkKind::Generic);
    }

    #[test]
    fn workspace_root_is_detected() {
        let t = TempProject::new();
        t.write("package.json", r#"{"workspaces":["apps/*"]}"#);
        let info = detect(t.path());
        assert_eq!(info.kind, FrameworkKind::Generic);
        assert!(info.notes.iter().any(|n| n.starts_with("workspace root")));
    }

    #[test]
    fn manifest_with_bom_parses() {
        let t = TempProject::new();
        t.write(
            "package.json",
            "\u{feff}{\"dependencies\":{\"next\":\"14\"}}",
        );
        assert_eq!(detect(t.path()).kind, FrameworkKind::NextJs);
    }
}
