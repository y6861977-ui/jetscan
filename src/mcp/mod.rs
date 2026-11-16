//! `jetscan mcp`: a Model Context Protocol server over stdio, so AI coding tools
//! (Claude Code, Cursor, VS Code, Devin Desktop / Windsurf...) can call jetscan's
//! checks as tools. JSON-RPC 2.0, one message per line; stdout carries protocol
//! messages only, logs go to stderr; end of input = exit 0.
//!
//! Dual-era, per the MCP versioning rules (modelcontextprotocol.io/specification/
//! 2026-07-28/basic/versioning):
//! - modern (2026-07-28): stateless; every request carries
//!   `_meta["io.modelcontextprotocol/protocolVersion"]`; `server/discover`; results
//!   carry `resultType`;
//! - legacy (2025-11-25 and earlier): the `initialize` handshake selects a version
//!   for the whole process; the server may ask the client for `roots/list`.
//!
//! Tools only (no resources, prompts, sampling). Requests are handled one at a time.
//! Tool code runs under `catch_unwind`: a bug in a check becomes a tool error, not a
//! dead server.

mod report;
mod tools;
mod workspace;

use jetscan::deps::osv::{self, Curl, Http};
use jetscan::json::{self, Json};
use jetscan::license::{self, Status};
use jetscan::ui;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use workspace::Workspace;

/// Newest first. `MODERN` speak per-request `_meta`; `LEGACY` use `initialize`.
pub const MODERN: &[&str] = &["2026-07-28"];
pub const LEGACY: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const PV_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAPS_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";

/// One incoming line larger than this is refused unread (no unbounded buffering).
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// Our JSON parser is recursive: refuse deeper nesting before parsing.
const MAX_DEPTH: usize = 64;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;
const UNSUPPORTED_VERSION: i64 = -32022;

const INSTRUCTIONS: &str = "jetscan runs local, deterministic security checks on the files \
of this workspace. Every tool is read-only. scan_secrets, scan_github_actions and resolve_plan \
are offline; scan_dependencies is offline unless called with offline: false. Results never \
contain secret values. resolve_plan never changes files: show its diff to the user, who applies \
it. audit_web_source and audit_apk need a jetscan Pro license; without one they return a short \
notice to relay to the user.";

pub const USAGE: &str = "\
usage: jetscan mcp [--root <folder>]...

Model Context Protocol server on stdin/stdout for AI coding tools. The tools only
read files inside the workspace: the --root folder(s), else the folders the client
reports (MCP roots), else the current folder. Logs go to stderr.

  Claude Code:  claude mcp add jetscan -- jetscan mcp
  Others:       see docs/mcp/README.md

Tools: scan_secrets, scan_dependencies (offline unless offline:false), scan_github_actions,
resolve_plan (preview only), audit_web_source and audit_apk (jetscan Pro).";

/// `jetscan mcp [--root <dir>]...`. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let mut roots = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return 0;
            }
            "--root" => match it.next() {
                Some(dir) => roots.push(PathBuf::from(dir)),
                None => {
                    ui::eprint_error("--root needs a folder");
                    return 2;
                }
            },
            other => {
                ui::eprint_error(&format!(
                    "unknown mcp option '{}'",
                    ui::sanitize_line(other)
                ));
                ui::eprint_hint("run `jetscan mcp --help`");
                return 2;
            }
        }
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let ws = match Workspace::new(&roots, &cwd) {
        Ok(ws) => ws,
        Err(e) => {
            ui::eprint_error(&e);
            return 2;
        }
    };
    eprintln!(
        "jetscan mcp {}: serving on stdio, workspace {}",
        env!("CARGO_PKG_VERSION"),
        ws.describe()
    );
    let load = license::load;
    let mut server = Server::new(ws, &load, &Curl, osv::default_cache_dir());
    let stdin = io::stdin();
    let mut input = stdin.lock();
    serve(&mut server, &mut input, &mut io::stdout())
}

/// The read-dispatch-write loop. Exit 0 on end of input or when the client is gone.
pub fn serve(server: &mut Server<'_>, input: &mut dyn BufRead, out: &mut dyn Write) -> i32 {
    loop {
        let replies = match read_message(input, MAX_MESSAGE) {
            Ok(Message::Eof) => return 0,
            Ok(Message::TooLong) => vec![error(
                &Json::Null,
                INVALID_REQUEST,
                "message too large",
                None,
            )],
            Ok(Message::Line(bytes)) => match String::from_utf8(bytes) {
                Ok(text) if text.trim().is_empty() => continue,
                Ok(text) => server.handle(&text),
                Err(_) => vec![error(&Json::Null, PARSE_ERROR, "not UTF-8", None)],
            },
            Err(e) => {
                eprintln!("jetscan mcp: cannot read stdin: {e}");
                return 0;
            }
        };
        for line in replies {
            if out
                .write_all(line.as_bytes())
                .and_then(|()| out.write_all(b"\n"))
                .and_then(|()| out.flush())
                .is_err()
            {
                return 0;
            }
        }
    }
}

enum Message {
    Line(Vec<u8>),
    TooLong,
    Eof,
}

/// One `\n`-terminated message (a trailing `\r` is dropped), never buffering more
/// than `max` bytes. The last line may lack its newline.
fn read_message(r: &mut dyn BufRead, max: usize) -> io::Result<Message> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(if too_long {
                Message::TooLong
            } else if line.is_empty() {
                Message::Eof
            } else {
                Message::Line(line)
            });
        }
        let (chunk, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..i], Some(i + 1)),
            None => (buf, None),
        };
        if line.len() + chunk.len() > max {
            too_long = true;
            line = Vec::new();
        } else if !too_long {
            line.extend_from_slice(chunk);
        }
        let used = done.unwrap_or(buf.len());
        r.consume(used);
        if done.is_some() {
            if too_long {
                return Ok(Message::TooLong);
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Message::Line(line));
        }
    }
}

/// Bracket depth outside strings; `None` if deeper than `MAX_DEPTH`.
fn depth_ok(text: &str) -> bool {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    for b in text.bytes() {
        if in_str {
            match b {
                _ if esc => esc = false,
                b'\\' => esc = true,
                b'"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return false;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn s(text: &str) -> Json {
    Json::Str(text.to_string())
}

fn server_info() -> Json {
    obj(vec![
        ("name", s("jetscan")),
        ("title", s("jetscan")),
        ("version", s(env!("CARGO_PKG_VERSION"))),
    ])
}

fn supported_versions() -> Json {
    Json::Arr(MODERN.iter().chain(LEGACY).map(|v| s(v)).collect())
}

fn error(id: &Json, code: i64, message: &str, data: Option<Json>) -> String {
    let mut e = vec![("code", Json::Num(code as f64)), ("message", s(message))];
    if let Some(d) = data {
        e.push(("data", d));
    }
    json::stringify(&obj(vec![
        ("jsonrpc", s("2.0")),
        ("id", id.clone()),
        ("error", obj(e)),
    ]))
}

/// A JSON-RPC id we can echo: string or integer (MCP forbids null).
fn valid_id(id: &Json) -> bool {
    match id {
        Json::Str(_) => true,
        Json::Num(n) => n.is_finite() && n.fract() == 0.0,
        _ => false,
    }
}

/// The protocol version a request is served under.
struct Era {
    version: String,
}

impl Era {
    fn modern(&self) -> bool {
        self.version.as_str() >= MODERN[MODERN.len() - 1]
    }
}

pub struct Server<'a> {
    ws: Workspace,
    /// Version negotiated by `initialize` (legacy clients only).
    legacy: Option<String>,
    client_has_roots: bool,
    pending_roots: Option<String>,
    roots_asked: u64,
    license: &'a dyn Fn() -> Status,
    http: &'a dyn Http,
    osv_cache: Option<PathBuf>,
}

impl<'a> Server<'a> {
    pub fn new(
        ws: Workspace,
        license: &'a dyn Fn() -> Status,
        http: &'a dyn Http,
        osv_cache: Option<PathBuf>,
    ) -> Server<'a> {
        Server {
            ws,
            legacy: None,
            client_has_roots: false,
            pending_roots: None,
            roots_asked: 0,
            license,
            http,
            osv_cache,
        }
    }

    /// One incoming line -> the lines to write (responses and our own requests).
    pub fn handle(&mut self, text: &str) -> Vec<String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.handle_inner(text)))
            .unwrap_or_else(|_| {
                vec![error(
                    &Json::Null,
                    INTERNAL_ERROR,
                    "internal error in jetscan",
                    None,
                )]
            })
    }

    fn handle_inner(&mut self, text: &str) -> Vec<String> {
        if !depth_ok(text) {
            return vec![error(
                &Json::Null,
                PARSE_ERROR,
                "JSON nested too deeply",
                None,
            )];
        }
        let msg = match json::parse(text) {
            Ok(m) => m,
            Err(_) => return vec![error(&Json::Null, PARSE_ERROR, "parse error", None)],
        };
        let Json::Obj(map) = &msg else {
            let what = if matches!(msg, Json::Arr(_)) {
                "batches are not supported; send one message per line"
            } else {
                "a message must be a JSON object"
            };
            return vec![error(&Json::Null, INVALID_REQUEST, what, None)];
        };
        let id = map.get("id");
        let id_ok = id.is_some_and(valid_id);
        let reply_id = if id_ok {
            id.cloned().unwrap()
        } else {
            Json::Null
        };
        if map.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
            return vec![error(
                &reply_id,
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
                None,
            )];
        }
        let Some(method) = map.get("method") else {
            // A response to one of our requests (`roots/list`).
            if id.is_some() && (map.contains_key("result") || map.contains_key("error")) {
                return self.on_response(&msg);
            }
            return vec![error(&reply_id, INVALID_REQUEST, "no method", None)];
        };
        let Some(method) = method.as_str() else {
            return vec![error(
                &reply_id,
                INVALID_REQUEST,
                "method must be a string",
                None,
            )];
        };
        let params = map
            .get("params")
            .cloned()
            .unwrap_or(Json::Obj(Default::default()));
        if !matches!(params, Json::Obj(_)) {
            if id.is_none() {
                return vec![];
            }
            return vec![error(
                &reply_id,
                INVALID_REQUEST,
                "params must be an object",
                None,
            )];
        }
        match id {
            None => self.on_notification(method),
            Some(_) if !id_ok => vec![error(
                &Json::Null,
                INVALID_REQUEST,
                "id must be a string or an integer",
                None,
            )],
            Some(id) => vec![self.on_request(id, method, &params)],
        }
    }

    fn on_notification(&mut self, method: &str) -> Vec<String> {
        match method {
            "notifications/initialized" | "notifications/roots/list_changed"
                if self.legacy.is_some()
                    && self.client_has_roots
                    && self.ws.accepts_client_roots() =>
            {
                self.roots_asked += 1;
                let id = format!("jetscan-roots-{}", self.roots_asked);
                self.pending_roots = Some(id.clone());
                vec![json::stringify(&obj(vec![
                    ("jsonrpc", s("2.0")),
                    ("id", s(&id)),
                    ("method", s("roots/list")),
                ]))]
            }
            // Cancellation, progress and anything unknown: nothing to do (calls are
            // synchronous; a notification never gets a reply).
            _ => vec![],
        }
    }

    fn on_response(&mut self, msg: &Json) -> Vec<String> {
        let id = msg.get("id").and_then(Json::as_str);
        if id.is_none() || id != self.pending_roots.as_deref() {
            return vec![];
        }
        self.pending_roots = None;
        let uris: Vec<String> = msg
            .get("result")
            .and_then(|r| r.get("roots"))
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|r| r.get("uri").and_then(Json::as_str).map(str::to_string))
            .take(64)
            .collect();
        let n = self.ws.set_client_roots(&uris);
        if n > 0 {
            eprintln!(
                "jetscan mcp: workspace from client roots: {}",
                self.ws.describe()
            );
        } else {
            eprintln!(
                "jetscan mcp: client sent no usable roots; workspace {}",
                self.ws.describe()
            );
        }
        vec![]
    }

    fn on_request(&mut self, id: &Json, method: &str, params: &Json) -> String {
        if method == "initialize" {
            return self.initialize(id, params);
        }
        let meta = params.get("_meta");
        let era = match meta.and_then(|m| m.get(PV_KEY)) {
            Some(v) => {
                let Some(v) = v.as_str() else {
                    return error(id, INVALID_PARAMS, "protocolVersion must be a string", None);
                };
                if !MODERN.contains(&v) && !LEGACY.contains(&v) {
                    return error(
                        id,
                        UNSUPPORTED_VERSION,
                        "Unsupported protocol version",
                        Some(obj(vec![
                            ("supported", supported_versions()),
                            ("requested", s(v)),
                        ])),
                    );
                }
                let era = Era {
                    version: v.to_string(),
                };
                if era.modern() && !matches!(meta.and_then(|m| m.get(CAPS_KEY)), Some(Json::Obj(_)))
                {
                    return error(
                        id,
                        INVALID_PARAMS,
                        "_meta must include io.modelcontextprotocol/clientCapabilities",
                        None,
                    );
                }
                era
            }
            None => match &self.legacy {
                Some(v) => Era { version: v.clone() },
                None if method == "ping" => Era {
                    version: LEGACY[0].to_string(),
                },
                None => {
                    return error(
                        id,
                        INVALID_PARAMS,
                        &format!(
                            "send `initialize` first, or put \"{PV_KEY}\" in params._meta; \
                             supported versions: {}",
                            MODERN
                                .iter()
                                .chain(LEGACY)
                                .copied()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        Some(obj(vec![("supported", supported_versions())])),
                    );
                }
            },
        };
        match method {
            "ping" => self.result(id, &era, vec![]),
            "server/discover" => self.result(
                id,
                &era,
                vec![
                    ("supportedVersions", supported_versions()),
                    ("capabilities", capabilities()),
                    ("instructions", s(INSTRUCTIONS)),
                ],
            ),
            "tools/list" => self.result(id, &era, vec![("tools", tools::list())]),
            "tools/call" => self.call(id, &era, params),
            _ => error(id, METHOD_NOT_FOUND, "Method not found", None),
        }
    }

    fn initialize(&mut self, id: &Json, params: &Json) -> String {
        let Some(asked) = params.get("protocolVersion").and_then(Json::as_str) else {
            return error(
                id,
                INVALID_PARAMS,
                "initialize needs params.protocolVersion",
                None,
            );
        };
        // Same version if we speak it, else our newest handshake version (the client
        // then decides whether to continue).
        let version = LEGACY
            .iter()
            .find(|v| **v == asked)
            .copied()
            .unwrap_or(LEGACY[0]);
        self.legacy = Some(version.to_string());
        self.client_has_roots = matches!(
            params.get("capabilities").and_then(|c| c.get("roots")),
            Some(Json::Obj(_))
        );
        json::stringify(&obj(vec![
            ("jsonrpc", s("2.0")),
            ("id", id.clone()),
            (
                "result",
                obj(vec![
                    ("protocolVersion", s(version)),
                    ("capabilities", capabilities()),
                    ("serverInfo", server_info()),
                    ("instructions", s(INSTRUCTIONS)),
                ]),
            ),
        ]))
    }

    fn result(&self, id: &Json, era: &Era, mut body: Vec<(&str, Json)>) -> String {
        if era.modern() {
            body.push(("resultType", s("complete")));
            body.push(("_meta", obj(vec![(SERVER_INFO_KEY, server_info())])));
        }
        json::stringify(&obj(vec![
            ("jsonrpc", s("2.0")),
            ("id", id.clone()),
            ("result", obj(body)),
        ]))
    }

    fn call(&self, id: &Json, era: &Era, params: &Json) -> String {
        let Some(name) = params.get("name").and_then(Json::as_str) else {
            return error(id, INVALID_PARAMS, "tools/call needs params.name", None);
        };
        if !tools::known(name) {
            return error(
                id,
                INVALID_PARAMS,
                &format!("Unknown tool: {}", ui::sanitize_line(name)),
                None,
            );
        }
        let args = params.get("arguments").cloned().unwrap_or(Json::Null);
        let env = tools::Env {
            ws: &self.ws,
            license: self.license,
            http: self.http,
            osv_cache: self.osv_cache.clone(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tools::call(name, &args, &env)
        }));
        let r = match result {
            Ok(Some(r)) => r,
            Ok(None) => return error(id, INVALID_PARAMS, "Unknown tool", None),
            Err(_) => tools::ToolResult {
                texts: vec![format!(
                    "{name}: jetscan stopped on an internal error (details on the server's \
                     stderr). Nothing was changed."
                )],
                is_error: true,
            },
        };
        let content = Json::Arr(
            r.texts
                .iter()
                .map(|t| obj(vec![("type", s("text")), ("text", s(t))]))
                .collect(),
        );
        // No `structuredContent`, on purpose: Claude Code 2.1 hands structuredContent
        // to the model INSTEAD of `content` (observed 2026-11-13), which drops the
        // summary. The strict V2 JSON is already the second text item.
        let body = vec![("content", content), ("isError", Json::Bool(r.is_error))];
        self.result(id, era, body)
    }
}

fn capabilities() -> Json {
    obj(vec![(
        "tools",
        obj(vec![("listChanged", Json::Bool(false))]),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetscan::deps::scan::NoNetwork;

    fn server() -> (Server<'static>, PathBuf) {
        let dir = std::env::temp_dir();
        let ws = Workspace::new(&[], &dir).unwrap();
        static FREE: fn() -> Status = || Status::Free;
        (Server::new(ws, &FREE, &NoNetwork, None), dir)
    }

    fn one(server: &mut Server<'_>, line: &str) -> Json {
        let out = server.handle(line);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(!out[0].contains('\n'));
        json::parse(&out[0]).unwrap()
    }

    fn code(v: &Json) -> Option<f64> {
        v.get("error")
            .and_then(|e| e.get("code"))
            .and_then(Json::as_f64)
    }

    #[test]
    fn json_rpc_errors() {
        let (mut s, _) = server();
        assert_eq!(code(&one(&mut s, "{")), Some(-32700.0));
        assert_eq!(code(&one(&mut s, "[]")), Some(-32600.0));
        assert_eq!(code(&one(&mut s, "42")), Some(-32600.0));
        assert_eq!(
            code(&one(&mut s, r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)),
            Some(-32600.0)
        );
        assert_eq!(
            code(&one(
                &mut s,
                r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#
            )),
            Some(-32600.0)
        );
        assert_eq!(
            code(&one(
                &mut s,
                r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#
            )),
            Some(-32600.0)
        );
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert_eq!(code(&one(&mut s, &deep)), Some(-32700.0));
        // Before initialize: only ping, everything else asks for a version.
        let pong = one(&mut s, r#"{"jsonrpc":"2.0","id":"p","method":"ping"}"#);
        assert_eq!(pong.get("result"), Some(&Json::Obj(Default::default())));
        assert_eq!(
            code(&one(
                &mut s,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#
            )),
            Some(-32602.0)
        );
        // Notifications never get a reply.
        assert!(
            s.handle(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#)
                .is_empty()
        );
    }

    #[test]
    fn legacy_handshake_negotiates_versions() {
        for (asked, got) in [
            ("2025-11-25", "2025-11-25"),
            ("2025-06-18", "2025-06-18"),
            ("2024-11-05", "2024-11-05"),
            ("2099-01-01", "2025-11-25"),
            ("2026-07-28", "2025-11-25"),
        ] {
            let (mut s, _) = server();
            let r = one(
                &mut s,
                &format!(
                    r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{"protocolVersion":"{asked}","capabilities":{{}},"clientInfo":{{"name":"t","version":"1"}}}}}}"#
                ),
            );
            let res = r.get("result").unwrap();
            assert_eq!(res.get("protocolVersion").and_then(Json::as_str), Some(got));
            assert!(
                res.get("capabilities")
                    .and_then(|c| c.get("tools"))
                    .is_some()
            );
            assert!(res.get("resultType").is_none());
            let list = one(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
            let tools = list.get("result").and_then(|r| r.get("tools")).unwrap();
            assert_eq!(tools.as_array().unwrap().len(), 6);
        }
    }

    #[test]
    fn modern_requests_carry_their_version() {
        let (mut s, _) = server();
        let meta = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;
        let d = one(
            &mut s,
            &format!(
                r#"{{"jsonrpc":"2.0","id":"d","method":"server/discover","params":{{{meta}}}}}"#
            ),
        );
        let res = d.get("result").unwrap();
        assert_eq!(
            res.get("resultType").and_then(Json::as_str),
            Some("complete")
        );
        assert_eq!(
            res.get("supportedVersions")
                .and_then(Json::as_array)
                .unwrap()[0],
            Json::Str("2026-07-28".into())
        );
        assert!(
            res.get("_meta")
                .and_then(|m| m.get(SERVER_INFO_KEY))
                .is_some()
        );
        let bad = one(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        );
        assert_eq!(code(&bad), Some(-32022.0));
        let data = bad.get("error").and_then(|e| e.get("data")).unwrap();
        assert_eq!(
            data.get("requested").and_then(Json::as_str),
            Some("1900-01-01")
        );
        let no_caps = one(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
        );
        assert_eq!(code(&no_caps), Some(-32602.0));
        let unknown = one(
            &mut s,
            &format!(r#"{{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{{{meta}}}}}"#),
        );
        assert_eq!(code(&unknown), Some(-32601.0));
        let tool = one(
            &mut s,
            &format!(
                r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"nope",{meta}}}}}"#
            ),
        );
        assert_eq!(code(&tool), Some(-32602.0));
    }

    #[test]
    fn roots_are_requested_from_legacy_clients_that_have_them() {
        let (mut s, dir) = server();
        one(
            &mut s,
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":true}}}}"#,
        );
        let out = s.handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert_eq!(out.len(), 1);
        let req = json::parse(&out[0]).unwrap();
        assert_eq!(req.get("method").and_then(Json::as_str), Some("roots/list"));
        assert_eq!(
            req.get("id").and_then(Json::as_str),
            Some("jetscan-roots-1")
        );
        let sub = dir.join(format!("jetscan-mcp-roots-{}", std::process::id()));
        std::fs::create_dir_all(&sub).unwrap();
        let canon = std::fs::canonicalize(&sub).unwrap();
        let shown = workspace::plain(&canon)
            .display()
            .to_string()
            .replace('\\', "/");
        let uri = if shown.starts_with('/') {
            format!("file://{shown}")
        } else {
            format!("file:///{shown}")
        };
        let resp = format!(
            r#"{{"jsonrpc":"2.0","id":"jetscan-roots-1","result":{{"roots":[{{"uri":"{uri}"}}]}}}}"#
        );
        assert!(s.handle(&resp).is_empty());
        assert_eq!(s.ws.roots(), &[canon]);
        let _ = std::fs::remove_dir_all(&sub);
    }

    #[test]
    fn message_reader_is_bounded() {
        let mut input: &[u8] = b"{\"a\":1}\r\n\nxxxxxxxxxxxxxxxxxxxx\nlast";
        let mut r = io::BufReader::with_capacity(4, &mut input);
        let mut got = Vec::new();
        loop {
            match read_message(&mut r, 10).unwrap() {
                Message::Eof => break,
                Message::TooLong => got.push("TOO LONG".to_string()),
                Message::Line(l) => got.push(String::from_utf8(l).unwrap()),
            }
        }
        assert_eq!(got, ["{\"a\":1}", "", "TOO LONG", "last"]);
    }
}
