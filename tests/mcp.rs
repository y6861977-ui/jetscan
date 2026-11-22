//! `jetscan mcp` end to end: the real binary, scripted JSON-RPC on stdin, every stdout
//! line checked to be a protocol message. Fake secrets are assembled at runtime so this
//! repository never contains a complete token.

use jetscan::json::{self, Json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

// jetscan Pro: the Pro tools over MCP (tests/mcp/pro.rs, private repository only).
#[cfg(feature = "pro")]
#[path = "mcp/pro.rs"]
#[rustfmt::skip] // Pro-only file: absent from the public export, so `cargo fmt` must not open it
mod pro;

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jetscan-mcp-it-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Temp(fs::canonicalize(path).unwrap())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn plain(path: &Path) -> String {
    let text = path.display().to_string();
    text.strip_prefix(r"\\?\")
        .map_or(text.clone(), str::to_string)
}

fn token() -> String {
    format!("{}{}", "ghp_", "Zq8".repeat(12))
}

/// A project with a fake token, a vulnerable workflow, a lockfile and a React page.
fn project(t: &Temp) -> PathBuf {
    let p = t.0.join("project");
    fs::create_dir_all(p.join(".github/workflows")).unwrap();
    fs::create_dir_all(p.join("src")).unwrap();
    fs::create_dir_all(p.join("app")).unwrap();
    fs::write(
        p.join("src/config.js"),
        format!("const token = \"{}\";\n", token()),
    )
    .unwrap();
    fs::write(
        p.join(".github/workflows/triage.yml"),
        "name: triage\non:\n  issues:\n    types: [opened]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
    )
    .unwrap();
    fs::write(
        p.join("package-lock.json"),
        r#"{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/left-pad":{"version":"1.3.0"}}}"#,
    )
    .unwrap();
    fs::write(
        p.join("package.json"),
        r#"{"name":"x","dependencies":{"next":"14.0.0","react":"18.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        p.join("app/page.tsx"),
        format!(
            "\"use client\";\nconst k = \"{}\";\nexport default function P() {{ return null; }}\n",
            token()
        ),
    )
    .unwrap();
    p
}

/// Runs `jetscan mcp <args>` in `cwd`, writes `lines` (then EOF), returns
/// (exit code, parsed stdout messages, stdout, stderr). Panics if stdout has a
/// line that is not a JSON-RPC 2.0 object.
fn session(
    cwd: &Path,
    args: &[&str],
    lines: &[String],
    env: &[(&str, &str)],
) -> (i32, Vec<Json>, String, String) {
    let home = cwd.parent().unwrap().join("jetscan-home");
    fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_jetscan"));
    cmd.arg("mcp")
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .env_remove("JETSCAN_LICENSE")
        // No license file, empty OSV cache: this test's own folder.
        .env("JETSCAN_HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut input = lines.join("\n");
    input.push('\n');
    // The server may exit before reading (bad arguments): a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let msgs = stdout
        .lines()
        .map(|l| {
            let m = json::parse(l).unwrap_or_else(|e| panic!("not JSON on stdout: {e}: {l}"));
            assert_eq!(m.get("jsonrpc").and_then(Json::as_str), Some("2.0"), "{l}");
            m
        })
        .collect();
    (out.status.code().unwrap_or(-1), msgs, stdout, stderr)
}

fn init(version: &str, caps: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{"protocolVersion":"{version}","capabilities":{caps},"clientInfo":{{"name":"it","version":"1"}}}}}}"#
    )
}

const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn call(id: u32, name: &str, args: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
    )
}

fn reply(msgs: &[Json], id: u32) -> &Json {
    msgs.iter()
        .find(|m| m.get("id").and_then(Json::as_f64) == Some(id as f64))
        .unwrap_or_else(|| panic!("no reply to {id}"))
}

/// (isError, joined text items, structuredContent present — never, see src/mcp).
fn tool(msgs: &[Json], id: u32) -> (bool, String, bool) {
    let r = reply(msgs, id)
        .get("result")
        .unwrap_or_else(|| panic!("error reply to {id}"));
    let texts: Vec<&str> = r
        .get("content")
        .and_then(Json::as_array)
        .unwrap()
        .iter()
        .map(|c| {
            assert_eq!(c.get("type").and_then(Json::as_str), Some("text"));
            c.get("text").and_then(Json::as_str).unwrap()
        })
        .collect();
    (
        r.get("isError") == Some(&Json::Bool(true)),
        texts.join("\n-----\n"),
        r.get("structuredContent").is_some(),
    )
}

fn error_code(msgs: &[Json], id: Option<u32>) -> f64 {
    let m = match id {
        Some(id) => reply(msgs, id),
        None => msgs
            .iter()
            .find(|m| m.get("id") == Some(&Json::Null))
            .expect("an error with id null"),
    };
    m.get("error")
        .and_then(|e| e.get("code"))
        .and_then(Json::as_f64)
        .unwrap()
}

#[test]
fn legacy_session_runs_every_free_tool() {
    let t = Temp::new("legacy");
    let p = project(&t);
    let lines = vec![
        init("2025-11-25", "{}"),
        INITIALIZED.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_string(),
        call(2, "scan_secrets", "{}"),
        call(3, "scan_dependencies", "{}"),
        call(4, "scan_github_actions", "{}"),
        call(5, "resolve_plan", "{}"),
        r#"{"jsonrpc":"2.0","id":10,"method":"ping"}"#.to_string(),
    ];
    let before = fs::read(p.join(".github/workflows/triage.yml")).unwrap();
    let (code, msgs, stdout, stderr) = session(&p, &[], &lines, &[]);
    assert_eq!(code, 0, "{stderr}");
    // Every request answered, the notification not.
    assert_eq!(msgs.len(), 7, "{stdout}");
    assert!(!stdout.contains(&token()), "raw secret in MCP output");

    let init = reply(&msgs, 0).get("result").unwrap();
    assert_eq!(
        init.get("protocolVersion").and_then(Json::as_str),
        Some("2025-11-25")
    );
    assert_eq!(
        init.get("serverInfo")
            .and_then(|s| s.get("name"))
            .and_then(Json::as_str),
        Some("jetscan")
    );
    let tools = reply(&msgs, 1)
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Json::as_array)
        .unwrap();
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t.get("name").and_then(Json::as_str).unwrap())
        .collect();
    assert_eq!(
        names[..4],
        [
            "scan_secrets",
            "scan_dependencies",
            "scan_github_actions",
            "resolve_plan",
        ]
    );
    // The free build has no other tools; jetscan Pro lists its own after these (mcp/pro.rs).
    assert_eq!(names.len(), if cfg!(feature = "pro") { 9 } else { 4 });

    let (err, text, structured) = tool(&msgs, 2);
    assert!(!err && !structured, "{text}");
    assert!(
        text.contains("HIGH github-token — src/config.js:1"),
        "{text}"
    );
    assert!(text.contains("\"schema_version\":2"), "{text}");

    let (err, text, _) = tool(&msgs, 3);
    assert!(!err, "{text}");
    assert!(text.contains("deps.osv: partial"), "{text}");
    assert!(text.contains("Network: none"), "{text}");

    let (err, text, _) = tool(&msgs, 4);
    assert!(!err, "{text}");
    assert!(
        text.contains("HIGH gha-script-injection — .github/workflows/triage.yml:9"),
        "{text}"
    );

    let (err, text, _) = tool(&msgs, 5);
    assert!(!err, "{text}");
    assert!(text.contains("NOTHING WAS CHANGED"), "{text}");
    assert!(text.contains("+          ISSUE_TITLE: ${{ github.event.issue.title }}"));
    assert!(text.contains("jetscan resolve apply jetscan-plan.json --confirm"));
    // Read-only: the workflow is untouched and no plan file was written.
    assert_eq!(
        fs::read(p.join(".github/workflows/triage.yml")).unwrap(),
        before
    );
    assert!(!p.join("jetscan-plan.json").exists());

    assert_eq!(
        reply(&msgs, 10).get("result"),
        Some(&Json::Obj(Default::default()))
    );
}

#[test]
fn modern_requests_are_stateless_with_per_request_versions() {
    let t = Temp::new("modern");
    let p = project(&t);
    let meta = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"it","version":"1"}}"#;
    let lines = vec![
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{{{meta}}}}}"#),
        format!(r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{{meta}}}}}"#),
        format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"scan_secrets","arguments":{{"history":false}},{meta}}}}}"#
        ),
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}"#.to_string(),
        // No version and no initialize: refused with the supported versions.
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#.to_string(),
    ];
    let (code, msgs, stdout, _) = session(&p, &[], &lines, &[]);
    assert_eq!(code, 0);
    assert!(!stdout.contains(&token()));
    let d = reply(&msgs, 1).get("result").unwrap();
    assert_eq!(d.get("resultType").and_then(Json::as_str), Some("complete"));
    let versions: Vec<&str> = d
        .get("supportedVersions")
        .and_then(Json::as_array)
        .unwrap()
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert_eq!(&versions[..2], ["2026-07-28", "2025-11-25"]);
    for id in [2, 3] {
        assert_eq!(
            reply(&msgs, id)
                .get("result")
                .and_then(|r| r.get("resultType"))
                .and_then(Json::as_str),
            Some("complete")
        );
    }
    let (err, text, structured) = tool(&msgs, 3);
    assert!(!err && !structured, "{text}");
    assert!(text.contains("secrets.history: skipped — not requested"));
    assert_eq!(error_code(&msgs, Some(4)), -32022.0);
    assert_eq!(error_code(&msgs, Some(5)), -32602.0);
}

#[test]
fn malformed_input_gets_json_rpc_errors_and_eof_exits_cleanly() {
    let t = Temp::new("malformed");
    let p = project(&t);
    let huge = format!(
        r#"{{"jsonrpc":"2.0","id":9,"method":"x","params":{{"p":"{}"}}}}"#,
        "a".repeat(5 * 1024 * 1024)
    );
    let lines = vec![
        "this is not json".to_string(),
        init("2025-06-18", "{}"),
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#.to_string(),
        r#"{"jsonrpc":"2.0","id":2,"method":"no/such/method"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"no_such_tool"}}"#
            .to_string(),
        call(4, "scan_secrets", r#"{"history":"yes"}"#),
        call(5, "scan_secrets", r#"{"path":"../.."}"#),
        call(6, "scan_secrets", r#"{"unknown":1}"#),
        huge,
        format!("{}{}", "[".repeat(50_000), "]".repeat(50_000)),
        String::new(),
        // Last line without a newline is still read (session() appends one; this
        // checks the blank line above is ignored).
        r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#.to_string(),
    ];
    let (code, msgs, stdout, _) = session(&p, &[], &lines, &[]);
    assert_eq!(code, 0, "{stdout}");
    let nulls: Vec<f64> = msgs
        .iter()
        .filter(|m| m.get("id") == Some(&Json::Null))
        .map(|m| {
            m.get("error")
                .and_then(|e| e.get("code"))
                .and_then(Json::as_f64)
                .unwrap()
        })
        .collect();
    // not json, batch, too large, too deep.
    assert_eq!(nulls, [-32700.0, -32600.0, -32600.0, -32700.0], "{stdout}");
    assert_eq!(error_code(&msgs, Some(2)), -32601.0);
    assert_eq!(error_code(&msgs, Some(3)), -32602.0);
    for id in [4, 5, 6] {
        let (err, text, _) = tool(&msgs, id);
        assert!(err, "{text}");
    }
    let (_, text, _) = tool(&msgs, 5);
    assert!(
        text.contains("refused: '../..' is outside the workspace"),
        "{text}"
    );
    // Still alive after all of the above.
    assert!(reply(&msgs, 7).get("result").is_some());
}

#[test]
fn client_roots_narrow_the_workspace_and_root_flag_wins() {
    let t = Temp::new("roots");
    let p = project(&t);
    let sub = p.join("app");
    let uri = {
        let s = plain(&sub).replace('\\', "/");
        if s.starts_with('/') {
            format!("file://{s}")
        } else {
            format!("file:///{s}")
        }
    };
    let roots_reply = format!(
        r#"{{"jsonrpc":"2.0","id":"jetscan-roots-1","result":{{"roots":[{{"uri":"{uri}","name":"app"}}]}}}}"#
    );
    let lines = vec![
        init("2025-11-25", r#"{"roots":{"listChanged":true}}"#),
        INITIALIZED.to_string(),
        roots_reply.clone(),
        call(1, "scan_secrets", r#"{"history":false}"#),
        call(2, "scan_secrets", r#"{"path":"../src/config.js"}"#),
    ];
    let (code, msgs, stdout, stderr) = session(&p, &[], &lines, &[]);
    assert_eq!(code, 0);
    let ask = msgs
        .iter()
        .find(|m| m.get("method").and_then(Json::as_str) == Some("roots/list"))
        .expect("server asks for roots");
    assert_eq!(
        ask.get("id").and_then(Json::as_str),
        Some("jetscan-roots-1")
    );
    assert!(stderr.contains("workspace from client roots"), "{stderr}");
    let (err, text, _) = tool(&msgs, 1);
    assert!(!err, "{text}");
    // Only app/ is scanned: its token is found, src/config.js is not.
    assert!(
        text.contains("— app/page.tsx:2") || text.contains("— page.tsx:2"),
        "{text}"
    );
    assert!(!text.contains("config.js"), "{text}");
    let (err, text, _) = tool(&msgs, 2);
    assert!(err && text.contains("outside the workspace"), "{text}");
    assert!(!stdout.contains(&token()));

    // --root is the user's explicit choice: no roots/list request at all.
    let (_, msgs, _, _) = session(
        &p,
        &["--root", "src"],
        &[
            init("2025-11-25", r#"{"roots":{}}"#),
            INITIALIZED.to_string(),
            call(1, "scan_secrets", r#"{"history":false}"#),
        ],
        &[],
    );
    assert!(msgs.iter().all(|m| m.get("method").is_none()));
    let (_, text, _) = tool(&msgs, 1);
    assert!(
        text.contains("config.js") && !text.contains("page.tsx"),
        "{text}"
    );
}

#[test]
fn bad_server_arguments() {
    let t = Temp::new("args");
    for args in [&["--bogus"][..], &["--root"], &["--root", "missing-folder"]] {
        let (code, msgs, _, _) = session(&t.0, args, &[], &[]);
        assert_eq!(code, 2, "{args:?}");
        assert!(msgs.is_empty());
    }
    let (code, _, stdout, _) = {
        let out = Command::new(env!("CARGO_BIN_EXE_jetscan"))
            .args(["mcp", "--help"])
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            (),
            String::from_utf8(out.stdout).unwrap(),
            (),
        )
    };
    assert_eq!(code, 0);
    assert!(stdout.contains("claude mcp add jetscan -- jetscan mcp"));
}
