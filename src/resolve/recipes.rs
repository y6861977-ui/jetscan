//! Closed allowlist of reviewed source transformations. This is deliberately
//! not a YAML or shell rewrite engine: a bounded block-YAML subset is
//! classified line by line, and anything outside it is refused with a fixed
//! reason code. A refusal means "a safe transform cannot be proven", and the
//! plan falls back to manual guidance.
//!
//! `gha-run-env-v1` (GitHub's documented mitigation for script injection):
//!
//! ```text
//!   - run: echo "${{ github.event.pull_request.title }}"
//! becomes
//!   - run: echo "${PULL_REQUEST_TITLE}"
//!     env:
//!       PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}
//! ```
//!
//! Accepted only when, for every untrusted expression in a `run:` of the file:
//! the expression is exactly one known untrusted context; it sits inside shell
//! double quotes (so `"${NAME}"` keeps the intended value without re-parsing);
//! the step is a plain `run` step whose shell is known to be bash/sh; the script
//! has no command substitution, backticks, heredocs, `eval`, nested
//! interpreters or writes to `$GITHUB_ENV`/`$GITHUB_PATH`/`$GITHUB_OUTPUT`
//! (re-evaluation or output injection would survive the edit); the new
//! variable name is unused in the step. `actions/github-script` scripts are
//! refused (JavaScript, not shell).
use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Untrusted contexts with a fixed path: the workflow scanner's list
/// (`src/workflows/checks.rs`, `UNTRUSTED`) without its wildcard entries.
/// A test checks that the scanner reports each of them.
pub(crate) const CONTEXTS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
];

/// Commands and variables that re-interpret or re-emit a string: after the edit
/// the value would still be evaluated or injected, so the fix is not proven.
const DENY_WORDS: &[&str] = &[
    "eval",
    "source",
    "exec",
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "pwsh",
    "powershell",
    "cmd",
    "python",
    "python2",
    "python3",
    "node",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "xargs",
    "osascript",
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_OUTPUT",
];

/// Step keys the recipe understands; anything else (e.g. `uses`) is refused.
const STEP_KEYS: &[&str] = &[
    "name",
    "id",
    "if",
    "shell",
    "run",
    "env",
    "working-directory",
    "continue-on-error",
    "timeout-minutes",
];

pub(crate) fn workflow_path(path: &str) -> bool {
    path.strip_prefix(".github/workflows/").is_some_and(|name| {
        !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"))
    })
}

/// Deterministic environment variable name for a known context.
pub(crate) fn var_name(context: &str) -> String {
    let tail = context
        .strip_prefix("github.event.")
        .or_else(|| context.strip_prefix("github."))
        .unwrap_or(context);
    tail.to_ascii_uppercase().replace('.', "_")
}

pub(crate) fn transform(recipe: Recipe, old: &[u8]) -> Result<Vec<u8>, ResolveError> {
    match recipe {
        Recipe::WorkflowRunEnv => run_env(old),
    }
}

/// Verification probe for `gha-run-env-v1` output: the same bytes with every
/// `${NAME}` introduced for a known context put back as `${{ context }}`. The
/// two files differ only inside run scripts, so if the workflow scanner reports
/// the injection in the probe, it parsed the patched structure, and its silence
/// on the real file is evidence rather than a parse failure.
pub(crate) fn canary(patched: &[u8]) -> Option<Vec<u8>> {
    let mut text = Text::split(patched).ok()?;
    let mut names = BTreeMap::new();
    let mut env_lines = BTreeSet::new();
    for (index, line) in text.lines.iter().enumerate() {
        let Some((name, value)) = line.trim().split_once(": ") else {
            continue;
        };
        let Some(inner) = value
            .strip_prefix("${{ ")
            .and_then(|v| v.strip_suffix(" }}"))
        else {
            continue;
        };
        if let Some(context) = CONTEXTS.iter().find(|c| **c == inner)
            && var_name(context) == name
        {
            names.insert(name.to_owned(), *context);
            env_lines.insert(index);
        }
    }
    if names.is_empty() {
        return None;
    }
    for (index, line) in text.lines.iter_mut().enumerate() {
        if env_lines.contains(&index) {
            continue;
        }
        for (name, context) in &names {
            *line = line.replace(&format!("${{{name}}}"), &format!("${{{{ {context} }}}}"));
        }
    }
    Some(text.join())
}

/// Original encoding details, restored on output.
struct Text {
    bom: bool,
    crlf: bool,
    final_newline: bool,
    lines: Vec<String>,
}
impl Text {
    fn split(bytes: &[u8]) -> Result<Self, ResolveError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ResolveError("recipe_not_utf8"))?;
        let (bom, text) = match text.strip_prefix('\u{feff}') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let crlf = text.contains('\r');
        let normalized = if crlf {
            // Mixed or lone CR line endings are refused, not normalized.
            if text.matches('\r').count() != text.matches("\r\n").count()
                || text.matches('\n').count() != text.matches("\r\n").count()
            {
                return Err(ResolveError("recipe_mixed_line_endings"));
            }
            text.replace("\r\n", "\n")
        } else {
            text.to_owned()
        };
        if normalized
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(ResolveError("recipe_control_characters"));
        }
        let final_newline = normalized.ends_with('\n');
        let mut lines: Vec<String> = normalized.split('\n').map(str::to_owned).collect();
        if final_newline {
            lines.pop();
        }
        Ok(Self {
            bom,
            crlf,
            final_newline,
            lines,
        })
    }
    fn join(&self) -> Vec<u8> {
        let eol = if self.crlf { "\r\n" } else { "\n" };
        let mut out = String::new();
        if self.bom {
            out.push('\u{feff}');
        }
        out.push_str(&self.lines.join(eol));
        if self.final_newline {
            out.push_str(eol);
        }
        out.into_bytes()
    }
}

#[derive(Clone, Debug)]
enum Kind {
    Blank,
    Comment,
    /// A line inside the block scalar whose header entry is at this index.
    Body(usize),
    Entry(Entry),
}
#[derive(Clone, Debug)]
struct Entry {
    /// Column of the first character (the dash for `- key: value`).
    indent: usize,
    dash: bool,
    key: Option<String>,
    /// Column of the key (or of the scalar after `- `).
    key_col: usize,
    /// Value with any trailing YAML comment removed.
    value: String,
    value_col: usize,
    commented: bool,
    block: Option<String>,
}

fn leading_spaces(line: &str) -> Result<usize, ResolveError> {
    let spaces = line.len() - line.trim_start_matches(' ').len();
    if line[spaces..].starts_with('\t') {
        return Err(ResolveError("recipe_tab_indentation"));
    }
    Ok(spaces)
}

/// `key: value` with a plain key, or `None` if the text is a scalar.
fn split_key(text: &str) -> Option<(&str, &str)> {
    let end = text
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))?;
    if end == 0 || text.as_bytes()[end] != b':' {
        return None;
    }
    let rest = &text[end + 1..];
    if rest.is_empty() || rest.starts_with(' ') {
        Some((&text[..end], rest))
    } else {
        None
    }
}

/// Classify every line of the bounded subset; anything else is refused.
fn classify(lines: &[String]) -> Result<Vec<Kind>, ResolveError> {
    const BAD: ResolveError = ResolveError("recipe_unsupported_yaml");
    let mut kinds = Vec::with_capacity(lines.len());
    let mut index = 0;
    let mut seen_entry = false;
    // After a scalar value no deeper line may follow (that would be a
    // multi-line plain scalar, which the scanner refuses too).
    let mut max_next: Option<usize> = None;
    while index < lines.len() {
        let line = &lines[index];
        let trimmed = line.trim();
        if trimmed.is_empty() {
            kinds.push(Kind::Blank);
            index += 1;
            continue;
        }
        let indent = leading_spaces(line)?;
        if trimmed.starts_with('#') {
            kinds.push(Kind::Comment);
            index += 1;
            continue;
        }
        if !seen_entry && trimmed == "---" && indent == 0 {
            kinds.push(Kind::Blank);
            index += 1;
            continue;
        }
        if max_next.is_some_and(|max| indent > max) {
            return Err(BAD);
        }
        let rest = line[indent..].trim_end();
        if rest.starts_with("---")
            || rest.starts_with("...")
            || rest.starts_with(['%', '?', '&', '*', '!', '|', '>', '{', '[', '"', '\''])
        {
            return Err(BAD);
        }
        let (dash, body, key_col) = if rest == "-" {
            (true, "", indent + 2)
        } else if let Some(after) = rest.strip_prefix("- ") {
            if after.starts_with(' ') || after.starts_with('-') {
                return Err(BAD);
            }
            (true, after, indent + 2)
        } else {
            (false, rest, indent)
        };
        let (key, raw_value, value_col) = match split_key(body) {
            Some((key, value)) => {
                let lead = value.len() - value.trim_start().len();
                (
                    Some(key.to_owned()),
                    value.trim(),
                    key_col + key.len() + 1 + lead,
                )
            }
            None if dash => (None, body.trim(), key_col),
            None => return Err(BAD),
        };
        let (value, commented) = strip_comment(raw_value)?;
        seen_entry = true;
        let block = if matches!(value.as_str(), "|" | "|-" | ">" | ">-") {
            Some(value.clone())
        } else if value.starts_with(['|', '>']) {
            return Err(BAD);
        } else {
            None
        };
        let entry = Entry {
            indent,
            dash,
            key,
            key_col,
            value,
            value_col,
            commented,
            block,
        };
        let header = index;
        index += 1;
        max_next = if entry.value.is_empty() {
            None
        } else if entry.key.is_some() {
            Some(entry.key_col)
        } else {
            Some(entry.indent)
        };
        if entry.block.is_some() {
            // Body: lines deeper than the key column, blank lines included.
            let start = index;
            let mut body_indent = None;
            while index < lines.len() {
                let raw = &lines[index];
                if raw.trim().is_empty() {
                    index += 1;
                    continue;
                }
                let spaces = leading_spaces(raw)?;
                if spaces <= entry.key_col {
                    if body_indent.is_none() && entry.dash && spaces > entry.indent {
                        return Err(BAD);
                    }
                    break;
                }
                let base = *body_indent.get_or_insert(spaces);
                if spaces < base {
                    return Err(BAD);
                }
                index += 1;
            }
            // Trailing blank lines are not part of the body (the next entry
            // may be inserted after the last non-blank body line).
            let mut end = index;
            while end > start && lines[end - 1].trim().is_empty() {
                end -= 1;
            }
            kinds.push(Kind::Entry(entry));
            for _ in start..end {
                kinds.push(Kind::Body(header));
            }
            for _ in end..index {
                kinds.push(Kind::Blank);
            }
            max_next = None;
            continue;
        }
        kinds.push(Kind::Entry(entry));
    }
    Ok(kinds)
}

/// Remove a trailing ` #` comment from a single-line value. Quoted values
/// must close on the same line.
fn strip_comment(value: &str) -> Result<(String, bool), ResolveError> {
    const BAD: ResolveError = ResolveError("recipe_unsupported_yaml");
    if let Some(quote) = value.chars().next().filter(|c| matches!(c, '"' | '\'')) {
        let bytes = value.as_bytes();
        let mut index = 1;
        while index < bytes.len() {
            if quote == '"' && bytes[index] == b'\\' {
                index += 2;
                continue;
            }
            if bytes[index] == quote as u8 {
                if quote == '\'' && bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                let tail = value[index + 1..].trim();
                if tail.is_empty() {
                    return Ok((value.to_owned(), false));
                }
                if tail.starts_with('#') {
                    return Ok((value[..=index].to_owned(), true));
                }
                return Err(BAD);
            }
            index += 1;
        }
        return Err(BAD);
    }
    if value.starts_with('#') {
        return Ok((String::new(), true));
    }
    match value.find(" #") {
        Some(at) => Ok((value[..at].trim_end().to_owned(), true)),
        None => Ok((value.to_owned(), false)),
    }
}

fn entry(kinds: &[Kind], index: usize) -> Option<&Entry> {
    match kinds.get(index) {
        Some(Kind::Entry(e)) => Some(e),
        _ => None,
    }
}

/// Mentions an untrusted field anywhere (also inside functions or with
/// different case): such an expression is never left behind or rewritten.
fn mentions_untrusted(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("github.head_ref")
        || (lower.contains("github.event")
            && [
                "title",
                "body",
                "message",
                "head_ref",
                ".ref",
                "label",
                "default_branch",
                "head_branch",
                "email",
                "name",
                "page_name",
            ]
            .iter()
            .any(|f| lower.contains(f)))
}

/// One `${{ ... }}` occurrence: line, byte column of `$`, end column after `}}`.
struct Expr {
    line: usize,
    start: usize,
    end: usize,
    inner: String,
}

fn expressions(lines: &[String]) -> Result<Vec<Expr>, ResolveError> {
    let mut out = Vec::new();
    for (line, text) in lines.iter().enumerate() {
        let mut cursor = 0;
        while let Some(at) = text[cursor..].find("${{") {
            let start = cursor + at;
            let Some(close) = text[start + 3..].find("}}") else {
                return Err(ResolveError("recipe_multiline_expression"));
            };
            let end = start + 3 + close + 2;
            out.push(Expr {
                line,
                start,
                end,
                inner: text[start + 3..end - 2].trim().to_owned(),
            });
            cursor = end;
        }
    }
    Ok(out)
}

/// The run step that owns a `run` entry.
struct StepInfo {
    start: usize,
    /// Last non-blank line belonging to the step.
    last: usize,
    key_col: usize,
    keys: BTreeMap<String, usize>,
}

fn step_of(kinds: &[Kind], run: usize) -> Result<StepInfo, ResolveError> {
    const BAD: ResolveError = ResolveError("recipe_unsupported_step");
    let run_entry = entry(kinds, run).ok_or(BAD)?;
    let k = run_entry.key_col;
    if k < 2 {
        return Err(BAD);
    }
    // Relative to the step's key column: a sibling key, something nested in a
    // sibling (deeper, or an indentless sequence at the key column), the dash
    // that starts this step, or outside.
    let sibling = |e: &Entry| !e.dash && e.indent == k;
    let nested = |e: &Entry| e.indent > k || (e.dash && e.indent == k);
    let mut start = run;
    if !run_entry.dash {
        let mut index = run;
        loop {
            if index == 0 {
                return Err(BAD);
            }
            index -= 1;
            let Some(e) = entry(kinds, index) else {
                continue;
            };
            if sibling(e) || nested(e) {
                continue;
            }
            if e.dash && e.indent == k - 2 && e.key.is_some() {
                start = index;
                break;
            }
            return Err(BAD);
        }
    }
    let mut keys = BTreeMap::new();
    let mut last = start;
    for (index, kind) in kinds.iter().enumerate().skip(start) {
        match kind {
            Kind::Blank | Kind::Comment => {}
            Kind::Body(_) => last = index,
            Kind::Entry(e) => {
                if index != start && !(sibling(e) || nested(e)) {
                    break;
                }
                if index == start || sibling(e) {
                    let key = e.key.clone().ok_or(BAD)?;
                    if !STEP_KEYS.contains(&key.as_str()) {
                        return Err(ResolveError("recipe_unsupported_step_key"));
                    }
                    if keys.insert(key, index).is_some() {
                        return Err(BAD);
                    }
                }
                last = index;
            }
        }
    }
    Ok(StepInfo {
        start,
        last,
        key_col: k,
        keys,
    })
}

/// bash/sh only: explicit `shell:`, or the default shell of a literal Linux or
/// macOS `runs-on` with no `defaults:` anywhere in the file.
fn shell_known(kinds: &[Kind], step: &StepInfo) -> Result<(), ResolveError> {
    const BAD: ResolveError = ResolveError("recipe_unknown_shell");
    if let Some(&at) = step.keys.get("shell") {
        let e = entry(kinds, at).ok_or(BAD)?;
        return if matches!(e.value.as_str(), "bash" | "sh") && !e.commented {
            Ok(())
        } else {
            Err(BAD)
        };
    }
    if kinds
        .iter()
        .any(|k| matches!(k, Kind::Entry(e) if e.key.as_deref() == Some("defaults")))
    {
        return Err(BAD);
    }
    // `steps:` header: the first entry above the step's dash that is not part of
    // the sequence (or, for an indentless sequence, a `steps:` at the dash column).
    let dash = step.key_col - 2;
    let mut index = step.start;
    let header = loop {
        if index == 0 {
            return Err(BAD);
        }
        index -= 1;
        let Some(e) = entry(kinds, index) else {
            continue;
        };
        if e.indent < dash || (!e.dash && e.indent == dash) {
            break index;
        }
    };
    let h = entry(kinds, header).ok_or(BAD)?;
    if h.dash || h.key.as_deref() != Some("steps") || !h.value.is_empty() {
        return Err(BAD);
    }
    let j = h.indent;
    // Job id line above, then `jobs:` at column 0.
    let mut index = header;
    let job = loop {
        if index == 0 {
            return Err(BAD);
        }
        index -= 1;
        let Some(e) = entry(kinds, index) else {
            continue;
        };
        if e.indent < j {
            break index;
        }
    };
    let job_entry = entry(kinds, job).ok_or(BAD)?;
    if job_entry.dash || !job_entry.value.is_empty() || job_entry.key.is_none() {
        return Err(BAD);
    }
    let mut index = job;
    let jobs = loop {
        if index == 0 {
            return Err(BAD);
        }
        index -= 1;
        let Some(e) = entry(kinds, index) else {
            continue;
        };
        if e.indent < job_entry.indent {
            break index;
        }
    };
    let jobs_entry = entry(kinds, jobs).ok_or(BAD)?;
    if jobs_entry.indent != 0 || jobs_entry.key.as_deref() != Some("jobs") {
        return Err(BAD);
    }
    // Siblings of `steps:` inside the job.
    let mut runs_on = None;
    for index in job + 1..kinds.len() {
        let Some(e) = entry(kinds, index) else {
            continue;
        };
        if e.indent < j {
            break;
        }
        if e.indent == j && !e.dash && e.key.as_deref() == Some("runs-on") {
            runs_on = Some(e);
        }
    }
    let runs_on = runs_on.ok_or(BAD)?;
    let value = runs_on.value.as_str();
    if runs_on.commented
        || !(value.starts_with("ubuntu-") || value.starts_with("macos-"))
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(BAD);
    }
    Ok(())
}

/// The script of a run entry plus a map from script offset to (line, column).
fn script(lines: &[String], kinds: &[Kind], run: usize) -> Result<Script, ResolveError> {
    let e = entry(kinds, run).ok_or(ResolveError("recipe_unsupported_step"))?;
    let mut text = String::new();
    let mut spans = Vec::new();
    match e.block.as_deref() {
        None => {
            if e.commented || e.value.starts_with(['"', '\'']) || e.value.contains(": ") {
                return Err(ResolveError("recipe_unsupported_run_scalar"));
            }
            spans.push((0, run, e.value_col));
            text.push_str(&e.value);
        }
        Some("|" | "|-") => {
            let body: Vec<usize> = (run + 1..kinds.len())
                .take_while(|&i| matches!(kinds[i], Kind::Body(h) if h == run))
                .collect();
            let base = body
                .iter()
                .filter(|&&i| !lines[i].trim().is_empty())
                .map(|&i| lines[i].len() - lines[i].trim_start_matches(' ').len())
                .min()
                .unwrap_or(0);
            for i in body {
                spans.push((text.len(), i, base));
                if lines[i].len() >= base {
                    text.push_str(&lines[i][base..]);
                }
                text.push('\n');
            }
        }
        // Folded scalars join lines: the shell text differs from the source.
        Some(_) => return Err(ResolveError("recipe_unsupported_run_scalar")),
    }
    Ok(Script { text, spans })
}

struct Script {
    text: String,
    /// (script offset, source line, source column of that offset).
    spans: Vec<(usize, usize, usize)>,
}
impl Script {
    fn offset(&self, line: usize, col: usize) -> Option<usize> {
        self.spans
            .iter()
            .find(|(_, l, _)| *l == line)
            .and_then(|(offset, _, base)| col.checked_sub(*base).map(|c| offset + c))
    }
}

/// Minimal POSIX quoting lexer. Every untrusted site must be inside double
/// quotes; constructs whose quoting cannot be followed are refused.
fn shell_ok(script: &str, sites: &BTreeSet<usize>) -> Result<(), ResolveError> {
    #[derive(PartialEq)]
    enum State {
        Normal,
        Single,
        Double,
    }
    let bytes = script.as_bytes();
    let mut state = State::Normal;
    let mut index = 0;
    while index < bytes.len() {
        if script[index..].starts_with("${{") {
            let end = script[index..]
                .find("}}")
                .map(|e| index + e + 2)
                .ok_or(ResolveError("recipe_multiline_expression"))?;
            if sites.contains(&index) && state != State::Double {
                return Err(ResolveError("recipe_expression_not_double_quoted"));
            }
            index = end;
            continue;
        }
        let c = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Normal => match c {
                b'\'' => state = State::Single,
                b'"' => state = State::Double,
                b'\\' => index += 1,
                b'`' => return Err(ResolveError("recipe_command_substitution")),
                b'$' if next == Some(b'(') => {
                    return Err(ResolveError("recipe_command_substitution"));
                }
                b'<' if next == Some(b'<') => return Err(ResolveError("recipe_heredoc")),
                b'#' if index == 0
                    || bytes[index - 1].is_ascii_whitespace()
                    || b";|&(".contains(&bytes[index - 1]) =>
                {
                    let end = script[index..]
                        .find('\n')
                        .map_or(bytes.len(), |e| index + e);
                    if sites.range(index..end).next().is_some() {
                        return Err(ResolveError("recipe_expression_in_comment"));
                    }
                    index = end;
                    continue;
                }
                _ => {}
            },
            State::Single => {
                if c == b'\'' {
                    state = State::Normal;
                }
            }
            State::Double => match c {
                b'"' => state = State::Normal,
                b'\\' => index += 1,
                b'`' => return Err(ResolveError("recipe_command_substitution")),
                b'$' if next == Some(b'(') => {
                    return Err(ResolveError("recipe_command_substitution"));
                }
                _ => {}
            },
        }
        index += 1;
    }
    if state != State::Normal {
        return Err(ResolveError("recipe_unbalanced_quotes"));
    }
    let words = words(script);
    if DENY_WORDS.iter().any(|w| words.contains(*w))
        || script.lines().any(|l| {
            let l = l.trim_start();
            l == "." || l.starts_with(". ")
        })
    {
        return Err(ResolveError("recipe_reevaluation"));
    }
    Ok(())
}

fn words(text: &str) -> BTreeSet<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|w| !w.is_empty())
        .collect()
}

/// A site to rewrite: line, columns and the canonical context.
struct Site {
    line: usize,
    start: usize,
    end: usize,
    context: &'static str,
}

fn run_env(old: &[u8]) -> Result<Vec<u8>, ResolveError> {
    let mut text = Text::split(old)?;
    let kinds = classify(&text.lines)?;
    // Group untrusted run sites by their run entry.
    let mut by_run: BTreeMap<usize, Vec<Site>> = BTreeMap::new();
    for expr in expressions(&text.lines)? {
        let owner = match &kinds[expr.line] {
            Kind::Body(header) => *header,
            Kind::Entry(e) if expr.start >= e.value_col => expr.line,
            Kind::Comment => continue,
            _ => {
                if mentions_untrusted(&expr.inner) {
                    return Err(ResolveError("recipe_unsupported_yaml"));
                }
                continue;
            }
        };
        let key = entry(&kinds, owner).and_then(|e| e.key.as_deref());
        match key {
            Some("run") => {}
            Some("script") if mentions_untrusted(&expr.inner) => {
                return Err(ResolveError("recipe_github_script"));
            }
            _ => continue,
        }
        let context = CONTEXTS
            .iter()
            .find(|c| c.eq_ignore_ascii_case(&expr.inner));
        match context {
            Some(context) => by_run.entry(owner).or_default().push(Site {
                line: expr.line,
                start: expr.start,
                end: expr.end,
                context,
            }),
            None if mentions_untrusted(&expr.inner) => {
                return Err(ResolveError("recipe_complex_expression"));
            }
            None => {}
        }
    }
    if by_run.is_empty() {
        return Err(ResolveError("recipe_nothing_to_change"));
    }
    // Validate every step first; edit only if all of them are provable.
    let mut edits: Vec<(Vec<Site>, BTreeMap<String, &'static str>, Insert)> = Vec::new();
    for (run, sites) in by_run {
        let step = step_of(&kinds, run)?;
        shell_known(&kinds, &step)?;
        let script = script(&text.lines, &kinds, run)?;
        let offsets = sites
            .iter()
            .map(|s| script.offset(s.line, s.start))
            .collect::<Option<BTreeSet<_>>>()
            .ok_or(ResolveError("recipe_unsupported_run_scalar"))?;
        shell_ok(&script.text, &offsets)?;
        let mut names = BTreeMap::new();
        for site in &sites {
            names.insert(var_name(site.context), site.context);
        }
        let used = words(&script.text);
        let insert = env_insert(&kinds, &step, run)?;
        for name in names.keys() {
            if used.contains(name.as_str()) || insert.existing.contains(name) {
                return Err(ResolveError("recipe_variable_name_in_use"));
            }
        }
        edits.push((sites, names, insert));
    }
    // Apply: replacements within lines (right to left), then insertions
    // (bottom to top) so earlier indices stay valid.
    let mut inserts = Vec::new();
    for (sites, names, insert) in edits {
        for site in sites.iter().rev() {
            let line = &mut text.lines[site.line];
            line.replace_range(
                site.start..site.end,
                &format!("${{{}}}", var_name(site.context)),
            );
        }
        let mut block = Vec::new();
        if insert.header {
            block.push(format!("{}env:", " ".repeat(insert.key_col)));
        }
        for (name, context) in names {
            block.push(format!(
                "{}{name}: ${{{{ {context} }}}}",
                " ".repeat(insert.entry_col)
            ));
        }
        inserts.push((insert.at, block));
    }
    inserts.sort_by_key(|insert| std::cmp::Reverse(insert.0));
    for (at, block) in inserts {
        for (offset, line) in block.into_iter().enumerate() {
            text.lines.insert(at + offset, line);
        }
    }
    let new = text.join();
    // Self-check: the result is in the subset and has no untrusted run site.
    match run_env(&new) {
        Err(ResolveError("recipe_nothing_to_change")) => Ok(new),
        _ => Err(ResolveError("recipe_self_check_failed")),
    }
}

struct Insert {
    /// Line index to insert before.
    at: usize,
    header: bool,
    key_col: usize,
    entry_col: usize,
    existing: BTreeSet<String>,
}

fn env_insert(kinds: &[Kind], step: &StepInfo, run: usize) -> Result<Insert, ResolveError> {
    const BAD: ResolveError = ResolveError("recipe_unsupported_env");
    let k = step.key_col;
    let Some(&env) = step.keys.get("env") else {
        // New `env:` before a run key on its own line, else after the step.
        let at = if run == step.start {
            step.last + 1
        } else {
            run
        };
        return Ok(Insert {
            at,
            header: true,
            key_col: k,
            entry_col: k + 2,
            existing: BTreeSet::new(),
        });
    };
    let e = entry(kinds, env).ok_or(BAD)?;
    if !e.value.is_empty() || e.commented {
        return Err(BAD);
    }
    let mut existing = BTreeSet::new();
    let mut entry_col = None;
    let mut last = None;
    for (index, kind) in kinds.iter().enumerate().take(step.last + 1).skip(env + 1) {
        match kind {
            Kind::Blank | Kind::Comment => {}
            Kind::Body(_) => return Err(BAD),
            Kind::Entry(child) => {
                if child.indent <= k && !child.dash {
                    break;
                }
                let col = *entry_col.get_or_insert(child.indent);
                let name = child.key.as_deref().ok_or(BAD)?;
                if child.dash
                    || child.indent != col
                    || child.value.is_empty()
                    || child.block.is_some()
                    || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || name.as_bytes()[0].is_ascii_digit()
                {
                    return Err(BAD);
                }
                existing.insert(name.to_owned());
                last = Some(index);
            }
        }
    }
    let (Some(entry_col), Some(last)) = (entry_col, last) else {
        return Err(BAD);
    };
    Ok(Insert {
        at: last + 1,
        header: false,
        key_col: k,
        entry_col,
        existing,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::Path;

    pub fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/resolve")
                .join(name),
        )
        .unwrap()
    }
    fn run(text: &str) -> Result<String, ResolveError> {
        transform(Recipe::WorkflowRunEnv, text.as_bytes()).map(|b| String::from_utf8(b).unwrap())
    }

    #[test]
    fn single_line_and_block_steps_move_to_env() {
        let old = "on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: t\n        run: echo \"${{ github.event.pull_request.title }}\"\n      - run: |\n          if [ -n \"${{ github.event.issue.body }}\" ]; then\n            echo \"x ${{ github.event.issue.body }} y\"\n          fi\n        shell: bash\n";
        let new = run(old).unwrap();
        assert_eq!(
            new,
            "on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: t\n        env:\n          PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"${PULL_REQUEST_TITLE}\"\n      - run: |\n          if [ -n \"${ISSUE_BODY}\" ]; then\n            echo \"x ${ISSUE_BODY} y\"\n          fi\n        shell: bash\n        env:\n          ISSUE_BODY: ${{ github.event.issue.body }}\n"
        );
        assert!(canary(new.as_bytes()).unwrap().len() > new.len());
        // CRLF and BOM survive.
        let crlf = format!("\u{feff}{}", old.replace('\n', "\r\n"));
        let out = run(&crlf).unwrap();
        assert!(out.starts_with('\u{feff}'));
        assert_eq!(out, format!("\u{feff}{}", new.replace('\n', "\r\n")));
    }

    #[test]
    fn reviewed_fixtures_have_the_expected_outcome() {
        let title = run(&fixture("workflows/pr-title.yml")).unwrap();
        assert!(title.contains(
            "      - name: Check the title format\n        env:\n          PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}\n        run: |\n          title=\"${PULL_REQUEST_TITLE}\"\n"
        ));
        let triage = run(&fixture("workflows/issue-triage.yml")).unwrap();
        assert!(triage.contains(
            "          ISSUE_NUMBER: ${{ github.event.issue.number }}\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n        run: echo \"New issue $ISSUE_NUMBER - ${ISSUE_TITLE}\"\n"
        ));
        assert!(triage.contains(
            "      - name: Pick a label\n        env:\n          ISSUE_BODY: ${{ github.event.issue.body }}\n        run: |\n          case \"${ISSUE_BODY}\" in\n"
        ));
        assert_eq!(
            run(&fixture("workflows/unquoted-comment.yml")),
            Err(ResolveError("recipe_expression_not_double_quoted"))
        );
        assert_eq!(
            run(&fixture("workflows/write-all.yml")),
            Err(ResolveError("recipe_nothing_to_change"))
        );
    }

    #[test]
    fn existing_env_block_is_extended() {
        let old = "on: issues\njobs:\n  a:\n    runs-on: ubuntu-22.04\n    steps:\n      - env:\n          OTHER: x\n        run: printf '%s' \"${{ github.event.issue.title }}\"\n";
        let new = run(old).unwrap();
        assert!(new.contains("          OTHER: x\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n        run: printf '%s' \"${ISSUE_TITLE}\"\n"));
    }

    #[test]
    fn unprovable_inputs_are_refused_with_reasons() {
        let head = "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n";
        for (step, code) in [
            (
                "      - run: echo ${{ github.event.issue.title }}\n",
                "recipe_expression_not_double_quoted",
            ),
            (
                "      - run: echo '${{ github.event.issue.title }}'\n",
                "recipe_expression_not_double_quoted",
            ),
            (
                "      - run: eval \"${{ github.event.issue.title }}\"\n",
                "recipe_reevaluation",
            ),
            (
                "      - run: echo \"t=${{ github.event.issue.title }}\" >> \"$GITHUB_OUTPUT\"\n",
                "recipe_reevaluation",
            ),
            (
                "      - run: echo \"$(echo ${{ github.event.issue.title }})\"\n",
                "recipe_command_substitution",
            ),
            (
                "      - run: echo \"${{ format('{0}', github.event.issue.title) }}\"\n",
                "recipe_complex_expression",
            ),
            (
                "      - run: echo \"${{ github.event.issue.title }}\"\n        shell: pwsh\n",
                "recipe_unknown_shell",
            ),
            (
                "      - run: echo \"${ISSUE_TITLE} ${{ github.event.issue.title }}\"\n",
                "recipe_variable_name_in_use",
            ),
            (
                "      - run: >\n          echo \"${{ github.event.issue.title }}\"\n",
                "recipe_unsupported_run_scalar",
            ),
            (
                "      - run: \"echo ${{ github.event.issue.title }}\"\n",
                "recipe_unsupported_run_scalar",
            ),
            (
                "      - run: echo \"${{ github.event.issue.title }}\" # c\n",
                "recipe_unsupported_run_scalar",
            ),
            (
                "      - uses: actions/github-script@v7\n        with:\n          script: console.log(\"${{ github.event.issue.title }}\")\n",
                "recipe_github_script",
            ),
            ("      - run: echo ok\n", "recipe_nothing_to_change"),
            (
                "      - run: |\n          cat <<EOF\n          \"${{ github.event.issue.title }}\"\n          EOF\n",
                "recipe_heredoc",
            ),
        ] {
            assert_eq!(
                run(&format!("{head}{step}")),
                Err(ResolveError(code)),
                "{step}"
            );
        }
        // Windows runner: default shell is pwsh.
        let windows = "on: issues\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n";
        assert_eq!(run(windows), Err(ResolveError("recipe_unknown_shell")));
        let defaults = format!(
            "defaults:\n  run:\n    shell: pwsh\n{head}      - run: echo \"${{{{ github.event.issue.title }}}}\"\n"
        );
        assert_eq!(run(&defaults), Err(ResolveError("recipe_unknown_shell")));
        assert_eq!(
            run("a: 1\r\nb: 2\n"),
            Err(ResolveError("recipe_mixed_line_endings"))
        );
        assert_eq!(
            run("a:\n\tb: 1\n"),
            Err(ResolveError("recipe_tab_indentation"))
        );
        assert_eq!(
            transform(Recipe::WorkflowRunEnv, b"\xff"),
            Err(ResolveError("recipe_not_utf8"))
        );
    }

    #[test]
    fn every_supported_context_is_a_scanner_finding() {
        for context in CONTEXTS {
            let p = testutil::Project::new();
            let text = format!(
                "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{{{ {context} }}}}\"\n"
            );
            p.write(".github/workflows/a.yml", &text);
            let issues = crate::workflows::check(&p.0);
            assert_eq!(issues.len(), 1, "{context}");
            assert_eq!(issues[0].id, "gha-script-injection");
            let new = run(&text).unwrap();
            p.write(".github/workflows/a.yml", &new);
            assert!(crate::workflows::check(&p.0).is_empty(), "{context}");
            p.write(
                ".github/workflows/a.yml",
                &String::from_utf8(canary(new.as_bytes()).unwrap()).unwrap(),
            );
            assert_eq!(crate::workflows::check(&p.0).len(), 1, "{context}");
        }
    }
}
