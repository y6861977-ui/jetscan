//! The MCP tools: definitions (`tools/list`) and execution (`tools/call`).
//!
//! Every tool is read-only: nothing in the workspace is written, no command from the
//! project is run, and there is deliberately NO tool that applies a fix — applying is a
//! human step (`jetscan resolve apply <plan> --confirm`) or an edit the AI makes itself
//! after the user agrees. Paid checks run only when `entitled` says so.

use super::report::{self, Notes, Report};
use super::workspace::{Kind, Workspace, plain};
use jetscan::deps::osv::{Http, OsvOptions, real_sleep};
use jetscan::deps::scan::NoNetwork;
use jetscan::finding_v2::{ModelError, RedactionPolicy, RemediationState, adapters};
use jetscan::json::Json;
use jetscan::license::{self, Status};
use jetscan::secrets::scan::ScanOptions;
use jetscan::{
    android_audit, apk_audit, deps, ios_audit, resolve, secrets, ui, web_audit, workflows,
};
use std::collections::HashMap;
use std::path::PathBuf;

pub const SITE: &str = "https://jetscan.jet.kim";

/// What a tool call needs from the server. Injected so tests can fake the license
/// and the network.
pub struct Env<'a> {
    pub ws: &'a Workspace,
    pub license: &'a dyn Fn() -> Status,
    /// Used only by `scan_dependencies` with `offline: false`.
    pub http: &'a dyn Http,
    pub osv_cache: Option<PathBuf>,
}

/// One `tools/call` result. `is_error` = the tool could not do its job (bad input,
/// refused path, scanner error); a paywall notice is NOT an error.
pub struct ToolResult {
    pub texts: Vec<String>,
    pub is_error: bool,
}

impl ToolResult {
    fn error(text: impl Into<String>) -> ToolResult {
        ToolResult {
            texts: vec![text.into()],
            is_error: true,
        }
    }
    fn notice(text: String) -> ToolResult {
        ToolResult {
            texts: vec![text],
            is_error: false,
        }
    }
    fn report(r: Report) -> ToolResult {
        ToolResult {
            texts: vec![r.summary, r.json_text],
            is_error: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Licensing
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    Web,
    Apk,
    Android,
    Ios,
}

impl Feature {
    fn tool(self) -> &'static str {
        match self {
            Feature::Web => "audit_web_source",
            Feature::Apk => "audit_apk",
            Feature::Android => "audit_android_source",
            Feature::Ios => "audit_ios_source",
        }
    }
    fn what(self) -> &'static str {
        match self {
            Feature::Web => {
                "a static audit of Next.js / Vite React source code: privileged keys in \
                 client code or public env variables (NEXT_PUBLIC_*, VITE_*), a Supabase \
                 service-role key in the browser, state-changing server handlers without a \
                 visible access check, non-constant HTML in DOM sinks, CORS that lets any site \
                 send credentials, public source maps"
            }
            Feature::Apk => {
                "a static audit of an Android APK file (nothing is installed or run): \
                 manifest flags such as debuggable, exported components and cleartext \
                 traffic, backup settings, permissions, and keys embedded in resources \
                 and DEX code"
            }
            Feature::Android => {
                "a static audit of an Android app's source project (Gradle, Kotlin/Java, XML; \
                 nothing is built or run): exported components, debuggable/backup/cleartext \
                 settings, R8 off in release, signing passwords and keystores in the project, \
                 provider keys in code and buildConfigField, trust-all TLS, risky WebView \
                 bridges, weak ciphers, secrets in logs"
            }
            Feature::Ios => {
                "a static audit of an iOS app's source project (Xcode project, Swift/Objective-C, \
                 plists; nothing is built or run): App Transport Security exceptions, get-task-allow \
                 in release entitlements, provider keys and signing files in the repository, tokens \
                 in UserDefaults, Keychain items readable while locked, trust-all URLSession \
                 handlers, UIWebView and file:// web views, weak ciphers, secrets in logs"
            }
        }
    }
}

/// The single place that decides whether a paid check may run. Today any valid,
/// unexpired jetscan Teams key unlocks every Pro check; a future Pro key (another
/// `plan` accepted by `license::check`) slots in here, per feature if needed.
pub fn entitled(feature: Feature, status: &Status) -> bool {
    match feature {
        // Same as the CLI's Teams flags: the 14-day grace period still unlocks.
        Feature::Web | Feature::Apk | Feature::Android | Feature::Ios => {
            matches!(status, Status::Active { .. } | Status::Grace { .. })
        }
    }
}

/// The paywall notice, relayed by the AI. Never prints the key, only its state.
fn paywall(feature: Feature, status: &Status) -> String {
    let state = match status {
        Status::Free => "No jetscan license key was found on this machine.".to_string(),
        Status::Grace { license: l, .. } | Status::Expired { license: l, .. } => format!(
            "The jetscan license key on this machine expired on {}.",
            license::format_date(l.expires)
        ),
        Status::Invalid(reason) => format!(
            "The jetscan license key on this machine was not accepted: {}.",
            ui::sanitize_line(reason)
        ),
        Status::Active { .. } => "This license does not include this check.".to_string(),
    };
    format!(
        "{tool} was not run: it is part of jetscan Pro.\n\
         What it does: {what}.\n\
         {state}\n\
         To enable it: get a key at {SITE}, then save it as one line in ~/.jetscan/license \
         (read on every call, no restart needed) or set JETSCAN_LICENSE in the environment \
         that starts `jetscan mcp` (restart the server). The key is checked on this machine; \
         nothing is sent anywhere. A jetscan Teams key also unlocks it.\n\
         Free tools that work without a key: scan_secrets, scan_dependencies, \
         scan_github_actions, resolve_plan.",
        tool = feature.tool(),
        what = feature.what(),
    )
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn s(text: &str) -> Json {
    Json::Str(text.to_string())
}

const PATH_HELP: &str = "Folder to check, relative to the workspace folder or absolute \
inside it. Default: the workspace folder. Paths outside the workspace are refused.";

struct Def {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    /// (name, JSON type, description)
    params: &'static [(&'static str, &'static str, &'static str)],
    required: &'static [&'static str],
    open_world: bool,
}

const DEFS: &[Def] = &[
    Def {
        name: "scan_secrets",
        title: "Scan for leaked secrets",
        description: "Looks for leaked credentials — API keys and tokens of known providers, \
private keys, passwords in .env and config files — in the project files and, unless history \
is false, in the git history. Runs locally and offline; nothing is sent anywhere. Returns each \
finding with file and line and whether git tracks the file; secret values are never returned, \
not even partially. A finding is a pattern match to review, not proof the key works; no \
findings does not prove there are no secrets. Read-only. Useful after writing or changing \
code or config.",
        params: &[
            ("path", "string", PATH_HELP),
            (
                "history",
                "boolean",
                "Also scan git history (needs git; slower on big repositories). Default: true.",
            ),
        ],
        required: &[],
        open_world: false,
    },
    Def {
        name: "scan_dependencies",
        title: "Check dependencies for known vulnerabilities",
        description: "Reads lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, \
go.mod, requirements.txt, poetry.lock, Pipfile.lock, uv.lock) and reports locked package \
versions with known vulnerabilities or malicious-package reports in the OSV.dev database, with \
upgrade versions where known. Offline by default: only the local OSV cache (~/.jetscan/osv-cache, \
filled by earlier online runs) is used, nothing is sent, and packages missing from the cache are \
reported as not checked. With offline: false, package names and versions (never code or file \
paths) are sent to api.osv.dev — ask the user first if they have not agreed to that. Does not \
check whether the vulnerable code is reachable. Read-only; no package manager is run.",
        params: &[
            ("path", "string", PATH_HELP),
            (
                "offline",
                "boolean",
                "true (default): use only the local OSV cache, no network. false: query \
api.osv.dev with package names and versions.",
            ),
        ],
        required: &[],
        open_world: true,
    },
    Def {
        name: "scan_github_actions",
        title: "Check GitHub Actions workflows",
        description: "Checks .github/workflows/*.yml and action.yml for documented attack \
patterns: untrusted pull request / issue text expanded into run scripts, privileged \
pull_request_target workflows that check out PR code, actions not pinned to a commit SHA, \
`permissions: write-all`, re-enabled insecure workflow commands. Local and offline. The workflow check does not report whether every \
file parsed, so its coverage is always marked partial. Read-only.",
        params: &[("path", "string", PATH_HELP)],
        required: &[],
        open_world: false,
    },
    Def {
        name: "resolve_plan",
        title: "Plan fixes (preview only, changes nothing)",
        description: "Builds a fix plan for the GitHub Actions findings of a folder and returns \
it with a preview diff. Only reviewed, provably safe edits (currently: moving untrusted \
expressions out of run scripts into env variables) become file patches; everything else is \
advice. This tool NEVER changes files and there is no MCP tool that applies a plan. Show the \
diff to the user. Applying is the user's decision: they run `jetscan resolve plan <folder> --out \
plan.json`, `jetscan resolve preview plan.json` and `jetscan resolve apply plan.json --confirm` in \
a terminal, or you make the same edit yourself only after the user agrees.",
        params: &[("path", "string", PATH_HELP)],
        required: &[],
        open_world: false,
    },
    Def {
        name: "audit_web_source",
        title: "Audit Next.js / Vite React source (jetscan Pro)",
        description: "jetscan Pro. Static, offline audit of a Next.js or Vite React project's \
source: privileged keys in client code or public env variables, a Supabase service-role key in \
the browser, state-changing route handlers / server actions without a visible access check \
(needs review), non-constant HTML in DOM sinks, CORS with credentials for any origin, public \
source maps. Findings carry \
file, line, confidence and a masked excerpt; an unsupported framework is reported as not \
checked. Read-only. Without a jetscan Pro or Teams license it does not scan and returns a short \
notice on how to get one — relay that notice to the user as is.",
        params: &[("path", "string", PATH_HELP)],
        required: &[],
        open_world: false,
    },
    Def {
        name: "audit_apk",
        title: "Audit an Android APK (jetscan Pro)",
        description: "jetscan Pro. Static, offline audit of an Android .apk file inside the \
workspace — nothing is installed or run: debuggable and backup flags, exported components, \
cleartext traffic and network security config, dangerous permissions, keys embedded in \
resources and DEX code. Read-only. Without a jetscan Pro or Teams license it does not scan and \
returns a short notice on how to get one — relay that notice to the user as is.",
        params: &[(
            "file",
            "string",
            "The .apk file, relative to the workspace folder or absolute inside it.",
        )],
        required: &["file"],
        open_world: false,
    },
    Def {
        name: "audit_android_source",
        title: "Audit an Android app's source project (jetscan Pro)",
        description: "jetscan Pro. Static, offline audit of an Android Gradle project's source \
inside the workspace — nothing is built or run: exported components and manifest flags (with \
release/flavor manifests merged), debuggable or unminified release builds, signing passwords and \
keystore files in the project, provider keys in code, resources and buildConfigField, trust-all \
TrustManager/HostnameVerifier, WebView JavaScript bridges, weak ciphers, secrets in logs. Findings \
carry file, line, column, confidence and a masked excerpt; Gradle values that are not literals are \
reported as not fully checked. Read-only. Without a jetscan Pro or Teams license it does not scan \
and returns a short notice on how to get one — relay that notice to the user as is.",
        params: &[("path", "string", PATH_HELP)],
        required: &[],
        open_world: false,
    },
    Def {
        name: "audit_ios_source",
        title: "Audit an iOS app's source project (jetscan Pro)",
        description: "jetscan Pro. Static, offline audit of an iOS app's source project inside the \
workspace — nothing is built or run: App Transport Security in Info.plist, custom URL schemes, \
get-task-allow and wildcard domains in entitlements (per Xcode build configuration), provider keys in \
code, plists and xcconfig, signing files (.p12, AuthKey_*.p8) by name only, tokens in UserDefaults, \
kSecAttrAccessibleAlways, trust-all URLSession challenge handlers, UIWebView and file:// access, weak \
ciphers, secrets in logs and on the pasteboard. Findings carry file, line, column, confidence and a \
masked excerpt; build settings that are not literals are reported as not fully checked. Read-only. \
Without a jetscan Pro or Teams license it does not scan and returns a short notice on how to get \
one — relay that notice to the user as is.",
        params: &[("path", "string", PATH_HELP)],
        required: &[],
        open_world: false,
    },
];

/// `tools/list`: the tools in a fixed order.
pub fn list() -> Json {
    Json::Arr(
        DEFS.iter()
            .map(|d| {
                let props = Json::Obj(
                    d.params
                        .iter()
                        .map(|(n, t, desc)| {
                            (
                                n.to_string(),
                                obj(vec![("type", s(t)), ("description", s(desc))]),
                            )
                        })
                        .collect(),
                );
                let mut schema = vec![
                    ("type", s("object")),
                    ("properties", props),
                    ("additionalProperties", Json::Bool(false)),
                ];
                if !d.required.is_empty() {
                    schema.push((
                        "required",
                        Json::Arr(d.required.iter().map(|r| s(r)).collect()),
                    ));
                }
                obj(vec![
                    ("name", s(d.name)),
                    ("title", s(d.title)),
                    ("description", s(d.description)),
                    ("inputSchema", obj(schema)),
                    (
                        "annotations",
                        obj(vec![
                            ("title", s(d.title)),
                            ("readOnlyHint", Json::Bool(true)),
                            ("destructiveHint", Json::Bool(false)),
                            ("idempotentHint", Json::Bool(true)),
                            ("openWorldHint", Json::Bool(d.open_world)),
                        ]),
                    ),
                ])
            })
            .collect(),
    )
}

pub fn known(name: &str) -> bool {
    DEFS.iter().any(|d| d.name == name)
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

struct Args<'a> {
    map: Option<&'a HashMap<String, Json>>,
}

impl<'a> Args<'a> {
    /// Unknown names and wrong types are input errors for the AI to fix.
    fn new(def: &Def, raw: &'a Json) -> Result<Args<'a>, String> {
        let map = match raw {
            Json::Null => None,
            Json::Obj(m) => Some(m),
            _ => return Err("arguments must be a JSON object".into()),
        };
        if let Some(m) = map {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                let Some((_, ty, _)) = def.params.iter().find(|(n, _, _)| n == k) else {
                    let allowed: Vec<&str> = def.params.iter().map(|(n, _, _)| *n).collect();
                    return Err(format!(
                        "unknown argument '{}' (allowed: {})",
                        ui::sanitize_line(k),
                        allowed.join(", ")
                    ));
                };
                let ok = match (*ty, &m[k]) {
                    ("string", Json::Str(_)) | ("boolean", Json::Bool(_)) => true,
                    (_, Json::Null) => true, // same as leaving it out
                    _ => false,
                };
                if !ok {
                    return Err(format!("argument '{k}' must be a {ty}"));
                }
            }
        }
        for r in def.required {
            if map.and_then(|m| m.get(*r)).is_none_or(|v| *v == Json::Null) {
                return Err(format!("argument '{r}' is required"));
            }
        }
        Ok(Args { map })
    }
    fn str(&self, k: &str) -> Option<&'a str> {
        self.map.and_then(|m| m.get(k)).and_then(Json::as_str)
    }
    fn bool(&self, k: &str, default: bool) -> bool {
        self.map
            .and_then(|m| m.get(k))
            .and_then(Json::as_bool)
            .unwrap_or(default)
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// `None`: no such tool (a protocol error for the caller).
pub fn call(name: &str, raw_args: &Json, env: &Env<'_>) -> Option<ToolResult> {
    let def = DEFS.iter().find(|d| d.name == name)?;
    let args = match Args::new(def, raw_args) {
        Ok(a) => a,
        Err(e) => return Some(ToolResult::error(format!("{name}: {e}"))),
    };
    let result = match name {
        "scan_secrets" => scan_secrets(&args, env),
        "scan_dependencies" => scan_dependencies(&args, env),
        "scan_github_actions" => scan_github_actions(&args, env),
        "resolve_plan" => resolve_plan(&args, env),
        "audit_web_source" => audit_web(&args, env),
        "audit_android_source" => audit_android(&args, env),
        "audit_ios_source" => audit_ios(&args, env),
        _ => audit_apk(&args, env),
    };
    Some(result.unwrap_or_else(|e| ToolResult::error(format!("{name}: {e}"))))
}

type Outcome = Result<ToolResult, String>;

fn v2_err(e: ModelError) -> String {
    format!("the result could not be converted to Findings V2 ({e}); nothing is shown")
}

fn scan_secrets(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let path = env.ws.resolve(a.str("path"), Kind::Any)?;
    let history = a.bool("history", true);
    let opts = ScanOptions {
        history,
        verify: false,
        ..ScanOptions::default()
    };
    let rep = secrets::scan::scan(&plain(&path), &opts).map_err(|e| ui::sanitize_line(&e))?;
    let target = env.ws.relative(&path);
    let mut notes = Notes::default();
    if rep.total() > 0 {
        notes.add(
            "What to do",
            vec![
                "Treat a secret in a tracked file or in git history as exposed: revoke or rotate \
                 it at the provider first, then remove it from the code (rewriting git history \
                 does not un-leak it). jetscan cannot rotate keys."
                    .into(),
                "Move secrets to environment variables or a secret manager; keep .env files in \
                 .gitignore."
                    .into(),
                "False positive: add `jetscan:ignore` on that line, or the finding's fingerprint \
                 to .jetscanignore."
                    .into(),
            ],
        );
    }
    let cli = format!(
        "jetscan secrets {target}{}",
        if history { "" } else { " --no-history" }
    );
    report::render(
        "scan_secrets",
        &target,
        &cli,
        report::secrets_v2(&rep, history),
        &notes,
    )
    .map(ToolResult::report)
}

fn scan_dependencies(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let dir = env.ws.resolve(a.str("path"), Kind::Dir)?;
    let offline = a.bool("offline", true);
    let opts = OsvOptions {
        cache_dir: env.osv_cache.clone(),
        no_cache: false,
        offline,
    };
    let http: &dyn Http = if offline { &NoNetwork } else { env.http };
    let rep = deps::scan::scan(&plain(&dir), &opts, http, &real_sleep)
        .map_err(|e| ui::sanitize_line(&e))?;
    let (scan, unknown) = report::deps_v2(&rep);
    let mut notes = Notes::default();
    notes.add("Advisories without a severity", unknown);
    let upgrades: Vec<String> = rep
        .upgrades()
        .iter()
        .take(20)
        .map(|u| {
            let p = u.package;
            match &u.to {
                Some(to) => format!(
                    "{} {} {} -> {} fixes {} of {} known advisories",
                    p.ecosystem.osv_name(),
                    p.name,
                    p.version,
                    to,
                    u.fixes,
                    u.fixes + u.unfixed
                ),
                None => format!(
                    "{} {} {}: no fixed version published yet",
                    p.ecosystem.osv_name(),
                    p.name,
                    p.version
                ),
            }
        })
        .collect();
    notes.add("Upgrades (check the changelog before upgrading)", upgrades);
    notes.add(
        "Names that look like popular packages (heuristic, not a verdict)",
        rep.typosquats
            .iter()
            .take(20)
            .map(|(p, sus)| {
                format!(
                    "{} {}@{} looks like {} ({})",
                    p.ecosystem.osv_name(),
                    p.name,
                    p.version,
                    sus.looks_like,
                    sus.reason
                )
            })
            .collect(),
    );
    if !rep.install_scripts.is_empty() {
        notes.add(
            "Install scripts",
            vec![format!(
                "{} run scripts on `npm install` (from package-lock.json); review them with \
                 `jetscan deps` in a terminal",
                ui::plural(rep.install_scripts.len(), "package", "packages")
            )],
        );
    }
    notes.add(
        "Warnings",
        rep.warnings
            .iter()
            .take(10)
            .map(|w| ui::sanitize_line(w))
            .collect(),
    );
    let target = env.ws.relative(&dir);
    let cli = format!(
        "jetscan deps {target}{}",
        if offline { " --offline" } else { "" }
    );
    report::render("scan_dependencies", &target, &cli, scan, &notes).map(ToolResult::report)
}

fn scan_github_actions(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let dir = env.ws.resolve(a.str("path"), Kind::Dir)?;
    let issues = workflows::check(&plain(&dir));
    let scan = adapters::workflows(&issues).map_err(v2_err)?;
    let policy = RedactionPolicy::default();
    let mut advice: Vec<String> = Vec::new();
    for i in &issues {
        let line = format!("{}: {}", i.id, policy.text(&i.fix));
        if !advice.contains(&line) && advice.len() < 20 {
            advice.push(line);
        }
    }
    let mut notes = Notes::default();
    notes.add("How to fix (advice; nothing was changed)", advice);
    if !issues.is_empty() {
        notes.add(
            "Next",
            vec![
                "resolve_plan builds a reviewed patch with a diff preview for the fixes jetscan \
                 can prove safe; the user applies it."
                    .into(),
            ],
        );
    }
    let target = env.ws.relative(&dir);
    let cli = format!("jetscan scan {target} --no-history --offline");
    report::render("scan_github_actions", &target, &cli, scan, &notes).map(ToolResult::report)
}

fn state_label(state: RemediationState) -> &'static str {
    match state {
        RemediationState::GuidanceOnly => "guidance_only (advice, nothing to apply)",
        RemediationState::Available => "available (file patches ready for the user to apply)",
        RemediationState::AppliedUnverified => "applied_unverified",
        RemediationState::Verified => "verified",
        RemediationState::Failed => "failed",
        RemediationState::RolledBack => "rolled_back",
    }
}

const MAX_PREVIEW: usize = 64 * 1024;
const MAX_PLAN_JSON: usize = 256 * 1024;

fn resolve_plan(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let dir = env.ws.resolve(a.str("path"), Kind::Dir)?;
    let policy = RedactionPolicy::default();
    let scan = adapters::workflows(&workflows::check(&plain(&dir)))
        .and_then(|s| s.redacted(&policy))
        .map_err(v2_err)?;
    let refused = |resolve::ResolveError(code)| format!("resolve plan refused: {code}");
    let built = resolve::plan(&dir, scan.as_scan(), &policy).map_err(refused)?;
    let plan = built.plan;
    let shown = resolve::preview(&plan, &policy).map_err(refused)?;
    let target = env.ws.relative(&dir);
    let patches = plan.preconditions().len();
    let mut text = format!(
        "jetscan resolve_plan — {target}\nPlan {} · {} · {} · status {}\n",
        plan.id(),
        ui::plural(plan.finding_ids().len(), "finding", "findings"),
        ui::plural(patches, "file patch", "file patches"),
        state_label(plan.status())
    );
    if built.status == jetscan::finding_v2::CheckStatus::Partial {
        text.push_str(
            "Input coverage is partial (the workflow check does not report whether every file \
             parsed); the plan covers the findings listed, not the whole project.\n",
        );
    }
    text.push_str("NOTHING WAS CHANGED. This tool only plans and previews.\n");
    if plan.status() == RemediationState::Available {
        let dir_arg = if target == "." {
            ".".to_string()
        } else {
            target.clone()
        };
        text.push_str(&format!(
            "Show the diff below to the user. If they want it applied, they run in a terminal \
             in the workspace folder:\n  jetscan resolve plan {dir_arg} --out jetscan-plan.json\n  \
             jetscan resolve preview jetscan-plan.json   (same plan id {} if nothing changed)\n  \
             jetscan resolve apply jetscan-plan.json --confirm\n  \
             jetscan resolve verify jetscan-plan.json\n\
             Or, if the user agrees, make exactly this edit yourself.\n",
            plan.id()
        ));
    }
    text.push_str("\nPreview:\n");
    if shown.text.len() > MAX_PREVIEW {
        let mut end = MAX_PREVIEW;
        while !shown.text.is_char_boundary(end) {
            end -= 1;
        }
        text.push_str(&shown.text[..end]);
        text.push_str(
            "\n[preview cut for the AI context; run `jetscan resolve preview` for all of it]\n",
        );
    } else {
        text.push_str(&shown.text);
    }
    let plan_json = plan
        .render_json()
        .map_err(|resolve::ResolveError(code)| format!("plan could not be rendered: {code}"))?;
    let second = if plan_json.len() > MAX_PLAN_JSON {
        "[the plan JSON is too large for the AI context; use `jetscan resolve plan --out`]"
            .to_string()
    } else {
        plan_json
    };
    Ok(ToolResult {
        texts: vec![text, second],
        is_error: false,
    })
}

fn audit_web(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let status = (env.license)();
    if !entitled(Feature::Web, &status) {
        return Ok(ToolResult::notice(paywall(Feature::Web, &status)));
    }
    let dir = env.ws.resolve(a.str("path"), Kind::Dir)?;
    let r = web_audit::scan_source(&plain(&dir), &web_audit::WebScanOptions::default())
        .map_err(|e| ui::sanitize_line(&e))?;
    let scan = adapters::web(&r).map_err(v2_err)?;
    let target = env.ws.relative(&dir);
    let cli = format!("jetscan web source {target}");
    report::render("audit_web_source", &target, &cli, scan, &Notes::default())
        .map(ToolResult::report)
}

fn audit_apk(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let status = (env.license)();
    if !entitled(Feature::Apk, &status) {
        return Ok(ToolResult::notice(paywall(Feature::Apk, &status)));
    }
    let file = env.ws.resolve(a.str("file"), Kind::File)?;
    let r = apk_audit::scan_apk(&plain(&file), &apk_audit::ApkScanOptions::default())
        .map_err(|e| ui::sanitize_line(&e))?;
    let scan = adapters::apk(&r).map_err(v2_err)?;
    let target = env.ws.relative(&file);
    let cli = format!("jetscan apk {target}");
    report::render("audit_apk", &target, &cli, scan, &Notes::default()).map(ToolResult::report)
}

fn audit_android(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let status = (env.license)();
    if !entitled(Feature::Android, &status) {
        return Ok(ToolResult::notice(paywall(Feature::Android, &status)));
    }
    let dir = env.ws.resolve(a.str("path"), Kind::Dir)?;
    let r = android_audit::scan_source(&plain(&dir), &android_audit::AndroidScanOptions::default())
        .map_err(|e| ui::sanitize_line(&e))?;
    let scan = adapters::android(&r).map_err(v2_err)?;
    let target = env.ws.relative(&dir);
    let cli = format!("jetscan android {target}");
    report::render(
        "audit_android_source",
        &target,
        &cli,
        scan,
        &Notes::default(),
    )
    .map(ToolResult::report)
}

fn audit_ios(a: &Args<'_>, env: &Env<'_>) -> Outcome {
    let status = (env.license)();
    if !entitled(Feature::Ios, &status) {
        return Ok(ToolResult::notice(paywall(Feature::Ios, &status)));
    }
    let dir = env.ws.resolve(a.str("path"), Kind::Dir)?;
    let r = ios_audit::scan_source(&plain(&dir), &ios_audit::IosScanOptions::default())
        .map_err(|e| ui::sanitize_line(&e))?;
    let scan = adapters::ios(&r).map_err(v2_err)?;
    let target = env.ws.relative(&dir);
    let cli = format!("jetscan ios {target}");
    report::render("audit_ios_source", &target, &cli, scan, &Notes::default())
        .map(ToolResult::report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetscan::json;
    use std::path::Path;

    fn lic(expires_in: i64) -> license::License {
        let today = license::today();
        license::License {
            id: "JS-TEST".into(),
            org: "Acme".into(),
            plan: "teams".into(),
            seats: 5,
            issued: today - 10,
            expires: today + expires_in,
        }
    }

    #[test]
    fn active_or_grace_license_is_entitled() {
        for f in [Feature::Web, Feature::Apk, Feature::Android, Feature::Ios] {
            assert!(entitled(
                f,
                &Status::Active {
                    license: lic(100),
                    days_left: 100
                }
            ));
            assert!(entitled(
                f,
                &Status::Grace {
                    license: lic(-3),
                    days_over: 3,
                }
            ));
            for closed in [
                Status::Free,
                Status::Expired {
                    license: lic(-30),
                    days_over: 30,
                },
                Status::Invalid("bad".into()),
            ] {
                assert!(!entitled(f, &closed));
                let text = paywall(f, &closed);
                assert!(
                    text.contains("jetscan Pro") && text.contains(SITE),
                    "{text}"
                );
                assert!(text.contains("~/.jetscan/license") && text.contains("JETSCAN_LICENSE"));
            }
        }
    }

    #[test]
    fn definitions_are_read_only_and_valid() {
        let list = list();
        let tools = list.as_array().unwrap();
        assert_eq!(tools.len(), 8);
        for t in tools {
            let name = t.get("name").and_then(Json::as_str).unwrap();
            assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            let ann = t.get("annotations").unwrap();
            assert_eq!(ann.get("readOnlyHint"), Some(&Json::Bool(true)), "{name}");
            assert_eq!(ann.get("destructiveHint"), Some(&Json::Bool(false)));
            let schema = t.get("inputSchema").unwrap();
            assert_eq!(schema.get("type").and_then(Json::as_str), Some("object"));
            let d = t.get("description").and_then(Json::as_str).unwrap();
            // Modest wording: no promise that the code is secure.
            let lower = d.to_lowercase();
            for word in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
                assert!(
                    !matches!(word, "secure" | "secures" | "guarantee" | "guarantees"),
                    "{name}: {word}"
                );
            }
        }
        let names: Vec<&str> = tools
            .iter()
            .map(|t| t.get("name").and_then(Json::as_str).unwrap())
            .collect();
        assert!(!names.iter().any(|n| n.contains("apply")));
    }

    struct Temp(PathBuf);
    impl Temp {
        fn new(tag: &str) -> Temp {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!(
                "jetscan-mcp-tools-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Temp(std::fs::canonicalize(p).unwrap())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Fake OSV: every queried package has one HIGH advisory.
    struct FakeOsv;
    impl Http for FakeOsv {
        fn request(&self, url: &str, body: Option<&str>) -> deps::osv::Attempt {
            if url.ends_with("/querybatch") {
                let doc = json::parse(body.unwrap()).unwrap();
                let n = doc.get("queries").and_then(Json::as_array).unwrap().len();
                let one = r#"{"vulns":[{"id":"GHSA-test-test-test"}]}"#;
                return deps::osv::Attempt::Ok(format!(
                    "{{\"results\":[{}]}}",
                    vec![one; n].join(",")
                ));
            }
            if url.ends_with("/GHSA-test-test-test") {
                return deps::osv::Attempt::Ok(
                    r#"{"id":"GHSA-test-test-test","summary":"fixture advisory",
                    "database_specific":{"severity":"HIGH"},
                    "affected":[{"package":{"ecosystem":"npm","name":"left-pad"},
                    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.3.1"}]}]}]}"#
                        .into(),
                );
            }
            deps::osv::Attempt::Fatal("HTTP 404".into())
        }
    }

    fn env_call(
        root: &Path,
        status: Status,
        name: &str,
        args: &str,
        cache: Option<PathBuf>,
    ) -> ToolResult {
        let ws = Workspace::new(&[], root).unwrap();
        let status_fn = move || status.clone();
        let env = Env {
            ws: &ws,
            license: &status_fn,
            http: &FakeOsv,
            osv_cache: cache,
        };
        call(name, &json::parse(args).unwrap(), &env).unwrap()
    }

    #[test]
    fn dependencies_offline_by_default_and_online_only_when_asked() {
        let t = Temp::new("deps");
        std::fs::write(
            t.0.join("package-lock.json"),
            r#"{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"},
            "node_modules/left-pad":{"version":"1.3.0"}}}"#,
        )
        .unwrap();
        let cache = t.0.join("cache");
        let offline = env_call(
            &t.0,
            Status::Free,
            "scan_dependencies",
            "{}",
            Some(cache.clone()),
        );
        assert!(!offline.is_error, "{}", offline.texts[0]);
        assert!(
            offline.texts[0].contains("No findings"),
            "{}",
            offline.texts[0]
        );
        assert!(offline.texts[0].contains("deps.osv: partial"));
        assert!(offline.texts[0].contains("offline: false"));
        assert!(offline.texts[0].contains("Network: none"));

        let online = env_call(
            &t.0,
            Status::Free,
            "scan_dependencies",
            r#"{"offline":false}"#,
            Some(cache),
        );
        let text = &online.texts[0];
        assert!(!online.is_error, "{text}");
        assert!(text.contains("1 finding: 1 high."), "{text}");
        assert!(text.contains("GHSA-test-test-test"), "{text}");
        assert!(text.contains("left-pad 1.3.0 -> 1.3.1"), "{text}");
        assert!(
            text.contains("api.osv.dev: asked about 1 package"),
            "{text}"
        );
        assert!(online.texts[1].contains("\"schema_version\":2"));
    }

    #[test]
    fn paid_tools_scan_with_an_active_license() {
        let demo = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/apk/demo");
        let active = Status::Active {
            license: lic(100),
            days_left: 100,
        };
        let r = env_call(&demo, active, "audit_apk", r#"{"file":"demo.apk"}"#, None);
        assert!(!r.is_error, "{}", r.texts[0]);
        assert!(r.texts[0].contains("4 findings"), "{}", r.texts[0]);
        assert!(r.texts[0].contains("APK-DEBUG-002"), "{}", r.texts[0]);
        let free = env_call(
            &demo,
            Status::Free,
            "audit_apk",
            r#"{"file":"demo.apk"}"#,
            None,
        );
        assert!(!free.is_error);
        assert_eq!(free.texts.len(), 1);
        assert!(free.texts[0].starts_with("audit_apk was not run"));
    }

    #[test]
    fn android_source_audit_is_gated_and_scans_with_a_license() {
        let t = Temp::new("android");
        let app = t.0.join("app");
        std::fs::create_dir_all(app.join("src/main")).unwrap();
        std::fs::write(t.0.join("settings.gradle"), "include ':app'\n").unwrap();
        std::fs::write(
            app.join("build.gradle"),
            "apply plugin: 'com.android.application'\nandroid {\n  defaultConfig { minSdkVersion 24\n    targetSdkVersion 34 }\n  buildTypes { release { debuggable true\n    minifyEnabled true } }\n}\n",
        )
        .unwrap();
        std::fs::write(
            app.join("src/main/AndroidManifest.xml"),
            "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.example.t\"><application android:allowBackup=\"false\"/></manifest>\n",
        )
        .unwrap();
        for closed in [
            Status::Free,
            Status::Expired {
                license: lic(-30),
                days_over: 30,
            },
        ] {
            let r = env_call(&t.0, closed, "audit_android_source", "{}", None);
            assert!(!r.is_error);
            assert_eq!(r.texts.len(), 1, "notice only, no scan");
            assert!(
                r.texts[0].starts_with("audit_android_source was not run"),
                "{}",
                r.texts[0]
            );
            assert!(!r.texts[0].contains("ANDROID-"), "{}", r.texts[0]);
        }
        for open in [
            Status::Active {
                license: lic(100),
                days_left: 100,
            },
            Status::Grace {
                license: lic(-3),
                days_over: 3,
            },
        ] {
            let r = env_call(&t.0, open, "audit_android_source", r#"{"path":"."}"#, None);
            assert!(!r.is_error, "{}", r.texts[0]);
            assert!(r.texts[0].contains("ANDROID-DEBUG-002"), "{}", r.texts[0]);
            assert!(r.texts[0].contains("app/build.gradle"), "{}", r.texts[0]);
            assert!(r.texts[0].contains("Network: none"), "{}", r.texts[0]);
            assert!(
                r.texts[1].contains("\"schema_version\":2"),
                "{}",
                r.texts[1]
            );
            assert!(r.texts[1].contains("android/android-debug-002/"));
        }
        let active = Status::Active {
            license: lic(100),
            days_left: 100,
        };
        let r = env_call(
            &t.0,
            active,
            "audit_android_source",
            r#"{"path":"../.."}"#,
            None,
        );
        assert!(r.is_error, "outside the workspace: {}", r.texts[0]);
    }

    #[test]
    fn ios_source_audit_is_gated_and_scans_with_a_license() {
        let t = Temp::new("ios");
        std::fs::create_dir_all(t.0.join("App")).unwrap();
        std::fs::write(t.0.join("App/App.swift"), "import UIKit\n").unwrap();
        std::fs::write(
            t.0.join("App/Info.plist"),
            "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n  <key>NSAppTransportSecurity</key>\n  <dict>\n    <key>NSAllowsArbitraryLoads</key>\n    <true/>\n  </dict>\n</dict>\n</plist>\n",
        )
        .unwrap();
        for closed in [
            Status::Free,
            Status::Expired {
                license: lic(-30),
                days_over: 30,
            },
        ] {
            let r = env_call(&t.0, closed, "audit_ios_source", "{}", None);
            assert!(!r.is_error);
            assert_eq!(r.texts.len(), 1, "notice only, no scan");
            assert!(
                r.texts[0].starts_with("audit_ios_source was not run"),
                "{}",
                r.texts[0]
            );
            assert!(!r.texts[0].contains("IOS-"), "{}", r.texts[0]);
        }
        for open in [
            Status::Active {
                license: lic(100),
                days_left: 100,
            },
            Status::Grace {
                license: lic(-3),
                days_over: 3,
            },
        ] {
            let r = env_call(&t.0, open, "audit_ios_source", r#"{"path":"."}"#, None);
            assert!(!r.is_error, "{}", r.texts[0]);
            assert!(r.texts[0].contains("IOS-ATS-001"), "{}", r.texts[0]);
            assert!(r.texts[0].contains("App/Info.plist"), "{}", r.texts[0]);
            assert!(r.texts[0].contains("Network: none"), "{}", r.texts[0]);
            assert!(
                r.texts[1].contains("\"schema_version\":2"),
                "{}",
                r.texts[1]
            );
            assert!(r.texts[1].contains("ios/ios-ats-001/"));
        }
        let active = Status::Active {
            license: lic(100),
            days_left: 100,
        };
        let r = env_call(
            &t.0,
            active,
            "audit_ios_source",
            r#"{"path":"../.."}"#,
            None,
        );
        assert!(r.is_error, "outside the workspace: {}", r.texts[0]);
    }

    #[test]
    fn bad_arguments_are_tool_errors() {
        let t = Temp::new("args");
        for (name, args) in [
            ("scan_secrets", r#"{"paht":"."}"#),
            ("scan_secrets", r#"{"history":"yes"}"#),
            ("scan_secrets", r#"[1]"#),
            ("audit_apk", r#"{}"#),
            ("scan_github_actions", r#"{"path":"../.."}"#),
        ] {
            let active = Status::Active {
                license: lic(100),
                days_left: 100,
            };
            let r = env_call(&t.0, active, name, args, None);
            assert!(r.is_error, "{name} {args}: {}", r.texts[0]);
        }
    }
}
