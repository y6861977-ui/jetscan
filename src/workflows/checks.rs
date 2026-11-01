//! Conservative, local GitHub Actions checks. See `super` for the contract.

use super::{Issue, Level};
use std::collections::BTreeSet;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

const MAX_BYTES: u64 = 1024 * 1024;

pub fn run(root: &Path) -> Vec<Issue> {
    let mut issues = Vec::new();
    if !directory(root) {
        return issues;
    }
    let github = root.join(".github");
    let workflows = github.join("workflows");
    if directory(&github)
        && directory(&workflows)
        && let Ok(entries) = fs::read_dir(workflows)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if (name.ends_with(".yml") || name.ends_with(".yaml"))
                && let Some(text) = read_file(&entry.path())
            {
                inspect(
                    &text,
                    &format!(".github/workflows/{name}"),
                    false,
                    &mut issues,
                );
            }
        }
    }
    for name in ["action.yml", "action.yaml"] {
        if let Some(text) = read_file(&root.join(name)) {
            inspect(&text, name, true, &mut issues);
        }
    }
    // Also stabilize direct callers; mod.rs applies the same ordering.
    issues.sort_by(|a, b| (&a.path, a.line, a.id).cmp(&(&b.path, b.line, b.id)));
    issues
}

fn linked(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !linked(&m))
}

fn read_file(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || linked(&meta) || meta.len() > MAX_BYTES {
        return None;
    }
    let file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[derive(Debug)]
enum Node {
    Map(Vec<Field>),
    Seq(Vec<Node>),
    Text(Vec<(usize, String)>),
    Block(Vec<(usize, String)>),
    // Empty values and one-line flow collections with nesting: nothing the
    // checks look into, so a miss there is possible, a false alarm is not.
    Opaque,
}

#[derive(Debug)]
struct Field {
    key: String,
    line: usize,
    value: Node,
}

impl Node {
    fn field(&self, key: &str) -> Option<&Field> {
        match self {
            Self::Map(fields) => fields.iter().find(|f| f.key == key),
            _ => None,
        }
    }
    fn text(&self) -> Option<&str> {
        match self {
            Self::Text(lines) if lines.len() == 1 => Some(&lines[0].1),
            _ => None,
        }
    }
}

// A bounded block-YAML subset, not a general YAML implementation. Parse the
// whole file before checking anything, so a later ambiguous construct cannot
// leave partial findings behind. Quotes/comments in block bodies are script
// content, whereas those on scalar headers are YAML syntax.
struct Parser<'a> {
    lines: Vec<&'a str>,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&mut self) -> Result<Option<(usize, &'a str, usize)>, ()> {
        while let Some(raw) = self.lines.get(self.pos) {
            let prefix = &raw[..raw.len() - raw.trim_start().len()];
            if prefix.bytes().any(|b| b != b' ') {
                return Err(());
            }
            let content = uncomment(raw.trim_start_matches(' '))?.trim_end();
            if content.is_empty() {
                self.pos += 1;
                continue;
            }
            if matches!(content, "---" | "...") || content.starts_with('%') {
                return Err(());
            }
            return Ok(Some((prefix.len(), content, self.pos + 1)));
        }
        Ok(None)
    }

    fn block(&mut self, indent: usize, depth: usize) -> Result<Node, ()> {
        if depth > 64 {
            return Err(());
        }
        let Some((actual, content, _)) = self.peek()? else {
            return Ok(Node::Opaque);
        };
        if actual != indent {
            return Err(());
        }
        if sequence_item(content).is_some() {
            let mut items = Vec::new();
            while let Some((actual, content, line)) = self.peek()? {
                if actual < indent {
                    break;
                }
                if actual != indent {
                    return Err(());
                }
                let Some(rest) = sequence_item(content) else {
                    break;
                };
                self.pos += 1;
                if rest.is_empty() {
                    items.push(self.child(indent, depth + 1, false)?);
                } else if mapping(rest).is_some() {
                    let key_indent = indent + content.len() - rest.len();
                    let first = self.field(rest, key_indent, line, depth + 1)?;
                    let mut fields = vec![first];
                    if let Some((next, _, _)) = self.peek()?
                        && next > indent
                    {
                        if next != key_indent {
                            return Err(());
                        }
                        let Node::Map(tail) = self.map(key_indent, depth + 1)? else {
                            return Err(());
                        };
                        fields.extend(tail);
                    }
                    unique(&fields)?;
                    items.push(Node::Map(fields));
                } else {
                    items.push(value(rest, line)?);
                }
            }
            Ok(Node::Seq(items))
        } else {
            self.map(indent, depth)
        }
    }

    fn map(&mut self, indent: usize, depth: usize) -> Result<Node, ()> {
        if depth > 64 {
            return Err(());
        }
        let mut fields = Vec::new();
        while let Some((actual, content, line)) = self.peek()? {
            if actual < indent || (actual == indent && sequence_item(content).is_some()) {
                break;
            }
            if actual != indent {
                return Err(());
            }
            self.pos += 1;
            fields.push(self.field(content, indent, line, depth + 1)?);
        }
        unique(&fields)?;
        Ok(Node::Map(fields))
    }

    fn child(&mut self, indent: usize, depth: usize, indentless: bool) -> Result<Node, ()> {
        if let Some((next, content, _)) = self.peek()?
            && (next > indent || (indentless && next == indent && sequence_item(content).is_some()))
        {
            return self.block(next, depth);
        }
        Ok(Node::Opaque)
    }

    fn field(
        &mut self,
        content: &str,
        indent: usize,
        line: usize,
        depth: usize,
    ) -> Result<Field, ()> {
        let (key, rest) = mapping(content).ok_or(())?;
        let key = atom(key)?;
        if key == "<<" || key.is_empty() {
            return Err(());
        }
        let node = if rest.is_empty() {
            self.child(indent, depth, true)?
        } else if matches!(rest, "|" | "|-" | "|+" | ">" | ">-" | ">+") {
            let mut lines = Vec::new();
            let mut body_indent = None;
            while let Some(raw) = self.lines.get(self.pos) {
                if raw.trim().is_empty() {
                    lines.push((self.pos + 1, String::new()));
                    self.pos += 1;
                    continue;
                }
                let spaces = raw.len() - raw.trim_start_matches(' ').len();
                if spaces <= indent {
                    break;
                }
                let base = *body_indent.get_or_insert(spaces);
                if spaces < base {
                    return Err(());
                }
                lines.push((self.pos + 1, raw[base..].to_owned()));
                self.pos += 1;
            }
            Node::Block(lines)
        } else {
            value(rest, line)?
        };
        Ok(Field {
            key,
            line,
            value: node,
        })
    }
}

fn unique(fields: &[Field]) -> Result<(), ()> {
    let mut seen = BTreeSet::new();
    if fields.iter().all(|f| seen.insert(&f.key)) {
        Ok(())
    } else {
        Err(())
    }
}

fn sequence_item(line: &str) -> Option<&str> {
    line.strip_prefix('-')
        .filter(|rest| rest.is_empty() || rest.starts_with(' '))
        .map(str::trim_start)
}

fn mapping(line: &str) -> Option<(&str, &str)> {
    // A flow collection (`- { os: linux }`) is a value, not a `key: value` pair.
    if line.starts_with(['{', '[']) {
        return None;
    }
    let mut quote = None;
    let mut escaped = false;
    for (index, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && c == '\\' {
            escaped = true;
            continue;
        }
        if quote == Some(c) {
            quote = None;
            continue;
        }
        if quote.is_none() {
            // Only a key that starts with a quote is quoted (`'on': push`).
            if matches!(c, '\'' | '"') && line[..index].trim().is_empty() {
                quote = Some(c);
            } else if c == ':'
                && line[index + 1..]
                    .chars()
                    .next()
                    .is_none_or(char::is_whitespace)
            {
                return Some((line[..index].trim(), line[index + 1..].trim()));
            }
        }
    }
    None
}

// A quote opens a quoted scalar only where a scalar starts: at the line start,
// after `- `, after `key: ` and after `[`, `{` or `,` in a flow collection.
// Inside a plain scalar (`name: Check PR's title`) it is an ordinary character,
// and ` #` there starts a comment, exactly as in YAML.
fn uncomment(line: &str) -> Result<&str, ()> {
    let (mut quote, mut escaped, mut previous_space) = (None, false, true);
    let (mut start, mut flow) = (true, 0usize);
    let spaced = |index: usize| {
        line[index + 1..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
    };
    for (index, c) in line.char_indices() {
        if escaped {
            escaped = false;
            previous_space = c.is_whitespace();
            continue;
        }
        if quote == Some('"') && c == '\\' {
            escaped = true;
            continue;
        }
        if quote == Some(c) {
            quote = None;
            start = false;
        } else if quote.is_none() {
            if c == '#' && previous_space {
                return Ok(&line[..index]);
            }
            if start && matches!(c, '\'' | '"') {
                quote = Some(c);
            } else if c == ':' && spaced(index) {
                start = true;
            } else if start && matches!(c, '[' | '{') {
                flow += 1;
            } else if flow > 0 && c == ',' {
                start = true;
            } else if flow > 0 && matches!(c, ']' | '}') {
                flow -= 1;
            } else if !c.is_whitespace() && !(start && c == '-' && spaced(index)) {
                // `- ` is a sequence indicator: the scalar starts after it.
                start = false;
            }
        }
        previous_space = c.is_whitespace();
    }
    if quote.is_some() || escaped {
        Err(())
    } else {
        Ok(line)
    }
}

fn atom(text: &str) -> Result<String, ()> {
    let text = text.trim();
    if text.starts_with('"') {
        // JSON escapes are a safe subset of YAML double-quoted escapes.
        match crate::json::parse(text) {
            Ok(crate::json::Json::Str(s)) => Ok(s),
            _ => Err(()),
        }
    } else if let Some(inner) = text.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        let mut chars = inner.chars();
        let mut out = String::new();
        while let Some(c) = chars.next() {
            if c == '\'' && chars.next() != Some('\'') {
                return Err(());
            }
            out.push(c);
        }
        Ok(out)
    } else if text.starts_with(['&', '*', '!', '\'', '|', '>'])
        || text.chars().any(char::is_control)
        || mapping(text).is_some()
    {
        Err(())
    } else {
        Ok(text.to_owned())
    }
}

fn value(text: &str, line: usize) -> Result<Node, ()> {
    if text.starts_with('[') {
        let inner = text.strip_suffix(']').ok_or(())?;
        let mut values = Vec::new();
        let (mut quote, mut escaped, mut start) = (None, false, 1);
        for (index, c) in inner.char_indices().skip(1) {
            if escaped {
                escaped = false;
                continue;
            }
            if quote == Some('"') && c == '\\' {
                escaped = true;
                continue;
            }
            if quote == Some(c) {
                quote = None;
                continue;
            }
            if quote.is_none() {
                if matches!(c, '\'' | '"') {
                    quote = Some(c);
                } else if matches!(c, '[' | ']' | '{' | '}') {
                    // Nested collections (a matrix `include: [{...}]`): opaque.
                    return if balanced(text) {
                        Ok(Node::Opaque)
                    } else {
                        Err(())
                    };
                } else if c == ',' {
                    values.push(Node::Text(vec![(line, atom(&inner[start..index])?)]));
                    start = index + 1;
                }
            }
        }
        if quote.is_some() || escaped {
            return Err(());
        }
        if !inner[start..].trim().is_empty() {
            values.push(Node::Text(vec![(line, atom(&inner[start..])?)]));
        }
        Ok(Node::Seq(values))
    } else if let Some(inner) = text.strip_prefix('{') {
        // `permissions: {}` is common and unambiguous. Other flow mappings are
        // not parsed (nesting and merge semantics need a full parser): a
        // balanced one-line mapping is opaque, so no check sees inside it.
        if inner.trim() == "}" {
            Ok(Node::Map(Vec::new()))
        } else if balanced(text) {
            Ok(Node::Opaque)
        } else {
            Err(())
        }
    } else {
        Ok(Node::Text(vec![(line, atom(text)?)]))
    }
}

/// One whole flow collection on one line: brackets nest correctly outside
/// quotes and the outermost one closes at the very end.
fn balanced(text: &str) -> bool {
    let bytes = text.as_bytes();
    let (mut depth, mut index, mut start) = (0usize, 0, true);
    while index < bytes.len() {
        let c = bytes[index];
        if start && matches!(c, b'\'' | b'"') {
            let Some(end) = skip_string(text, index) else {
                return false;
            };
            index = end;
            start = false;
            continue;
        }
        match c {
            b'[' | b'{' => {
                depth += 1;
                start = true;
            }
            b']' | b'}' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
                if depth == 0 {
                    return index + 1 == bytes.len();
                }
                start = false;
            }
            b',' => start = true,
            b':' if bytes.get(index + 1).is_none_or(u8::is_ascii_whitespace) => start = true,
            c if !c.is_ascii_whitespace() => start = false,
            _ => {}
        }
        index += 1;
    }
    false
}

fn inspect(text: &str, path: &str, composite: bool, issues: &mut Vec<Issue>) {
    let mut parser = Parser {
        lines: text.trim_start_matches('\u{feff}').lines().collect(),
        pos: 0,
    };
    // One optional leading document marker is unambiguous; a later marker is
    // rejected by peek(), so multi-document files never produce findings.
    if let Some((index, raw)) = parser
        .lines
        .iter()
        .enumerate()
        .find(|(_, raw)| !raw.trim().is_empty() && !raw.trim_start().starts_with('#'))
        && raw.trim_end() == "---"
    {
        parser.pos = index + 1;
    }
    let Ok(Some((0, _, _))) = parser.peek() else {
        return;
    };
    let Ok(root @ Node::Map(_)) = parser.block(0, 0) else {
        return;
    };
    if !matches!(parser.peek(), Ok(None)) {
        return;
    }
    if composite {
        if let Some(runs) = root.field("runs")
            && runs.value.field("using").and_then(|f| f.value.text()) == Some("composite")
        {
            steps(&runs.value, path, &[], false, issues);
        }
        return;
    }
    let mut triggers = Vec::new();
    if let Some(on) = root.field("on") {
        for trigger in ["pull_request_target", "workflow_run"] {
            let present = match &on.value {
                Node::Text(_) => on.value.text() == Some(trigger),
                Node::Seq(items) => items.iter().any(|n| n.text() == Some(trigger)),
                Node::Map(fields) => fields.iter().any(|f| f.key == trigger),
                Node::Opaque | Node::Block(_) => false,
            };
            if present {
                triggers.push(trigger);
            }
        }
    }
    permissions(&root, path, issues);
    environment(&root, path, issues);
    if let Some(jobs) = root.field("jobs")
        && let Node::Map(jobs) = &jobs.value
    {
        for job in jobs {
            permissions(&job.value, path, issues);
            environment(&job.value, path, issues);
            if let Some(uses) = job.value.field("uses") {
                unpinned(uses, path, issues);
            }
            let guarded = same_repository_only(&job.value, None);
            let triggers = unguarded(&job.value, &triggers);
            steps(&job.value, path, &triggers, guarded, issues);
        }
    }
}

fn emit(
    issues: &mut Vec<Issue>,
    id: &'static str,
    level: Level,
    path: &str,
    line: usize,
    message: String,
    fix: String,
) {
    issues.push(Issue {
        id,
        level,
        path: path.into(),
        line,
        message,
        fix,
    });
}

fn permissions(node: &Node, path: &str, issues: &mut Vec<Issue>) {
    if let Some(field) = node.field("permissions")
        && field.value.text() == Some("write-all")
    {
        emit(
            issues,
            "gha-write-all-permissions",
            Level::Medium,
            path,
            field.line,
            "workflow or job grants write-all permissions".into(),
            "grant only what the job needs, e.g. permissions: { contents: read }".into(),
        );
    }
}

fn environment(node: &Node, path: &str, issues: &mut Vec<Issue>) {
    if let Some(env) = node.field("env")
        && let Some(field) = env.value.field("ACTIONS_ALLOW_UNSECURE_COMMANDS")
        && field
            .value
            .text()
            .is_some_and(|s| s.eq_ignore_ascii_case("true"))
    {
        emit(
            issues,
            "gha-insecure-commands",
            Level::High,
            path,
            field.line,
            "ACTIONS_ALLOW_UNSECURE_COMMANDS enables unsafe workflow commands".into(),
            "remove it and use $GITHUB_ENV / $GITHUB_PATH files instead of set-env / add-path"
                .into(),
        );
    }
}

/// `guarded`: the job only runs for this repository's own branches, so the
/// "untrusted" contexts come from people who can already push.
fn steps(node: &Node, path: &str, triggers: &[&str], guarded: bool, issues: &mut Vec<Issue>) {
    let Some(steps) = node.field("steps") else {
        return;
    };
    let Node::Seq(steps) = &steps.value else {
        return;
    };
    for step in steps {
        environment(step, path, issues);
        let guarded = guarded || same_repository_only(step, None);
        if let Some(run) = step.field("run")
            && !guarded
        {
            injection(&run.value, path, issues);
        }
        let Some(uses) = step.field("uses") else {
            continue;
        };
        unpinned(uses, path, issues);
        let Some(action) = uses
            .value
            .text()
            .and_then(|s| s.split_once('@'))
            .map(|(a, _)| a)
        else {
            continue;
        };
        let Some(with) = step.field("with") else {
            continue;
        };
        if action.eq_ignore_ascii_case("actions/github-script")
            && !guarded
            && let Some(script) = with.value.field("script")
        {
            injection(&script.value, path, issues);
        }
        let triggers = unguarded(step, triggers);
        if action.eq_ignore_ascii_case("actions/checkout")
            && !triggers.is_empty()
            && let Some(reference) = with.value.field("ref")
            && let Node::Text(lines) | Node::Block(lines) = &reference.value
            && lines.iter().any(|(_, value)| {
                [
                    "github.event.pull_request.head.",
                    "github.head_ref",
                    "github.event.workflow_run.head_",
                    "refs/pull/",
                ]
                .iter()
                .any(|s| value.contains(s))
            })
        {
            emit(issues, "gha-pwn-request", Level::High, path, reference.line,
                format!("{} workflow checks out untrusted pull request code", triggers.join("/")),
                "do not check out the PR head in a privileged workflow; build it in a pull_request workflow without secrets and pass results as artifacts".into());
        }
    }
}

/// The privileged triggers this step or job is not guarded against.
fn unguarded<'t>(node: &Node, triggers: &[&'t str]) -> Vec<&'t str> {
    triggers
        .iter()
        .copied()
        .filter(|t| !same_repository_only(node, Some(t)))
        .collect()
}

/// `if:` that a pull request from a fork cannot satisfy: the head is a branch of
/// this repository, or the author is Dependabot. Any `||` could bypass the guard,
/// and `!` could negate it, so then it does not count. The one exception: for
/// runs started by `trigger`, `github.event_name != '<trigger>' || <guard>` is
/// exactly the guard (the left side is false), whatever surrounds it.
fn same_repository_only(node: &Node, trigger: Option<&str>) -> bool {
    let Some(Field {
        value: Node::Text(lines) | Node::Block(lines),
        ..
    }) = node.field("if")
    else {
        return false;
    };
    let mut condition: String = lines
        .iter()
        .flat_map(|(_, s)| s.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    // Whole operands only: `== github.repository_owner` is not a guard.
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || "_.-".contains(c));
    let operand = |condition: &str, at: usize, len: usize| {
        !word(condition[..at].chars().next_back()) && !word(condition[at + len..].chars().next())
    };
    if let Some(trigger) = trigger {
        let other = format!("github.event_name!='{trigger}'||");
        while let Some(at) = condition.find(&other) {
            if word(condition[..at].chars().next_back()) {
                return false;
            }
            condition.replace_range(at..at + other.len(), "");
        }
    }
    if condition.contains("||") || condition.replace("!=", "").contains('!') {
        return false;
    }
    [
        "github.event.pull_request.head.repo.full_name==github.repository",
        "github.repository==github.event.pull_request.head.repo.full_name",
        "github.event.workflow_run.head_repository.full_name==github.repository",
        "github.repository==github.event.workflow_run.head_repository.full_name",
        "github.event.pull_request.user.login=='dependabot[bot]'",
    ]
    .iter()
    .any(|guard| {
        condition
            .match_indices(guard)
            .any(|(at, _)| operand(&condition, at, guard.len()))
    })
}

fn hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn unpinned(field: &Field, path: &str, issues: &mut Vec<Issue>) {
    let Some(action) = field.value.text() else {
        return;
    };
    if action.starts_with("./") {
        return;
    }
    let fix = if let Some(image) = action.strip_prefix("docker://") {
        if image.is_empty()
            || !image
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/:._-@".contains(&b))
        {
            return;
        }
        if image
            .rsplit_once("@sha256:")
            .is_some_and(|(_, digest)| hex(digest, 64))
        {
            return;
        }
        // Other digest algorithms (or malformed digests) are not evidence of
        // a mutable tag. Only report image names/tags without a digest.
        if image.contains('@') {
            return;
        }
        let display: String = action.chars().take(100).collect();
        format!(
            "pin the image to a full digest: {}@sha256:<64-hex digest>",
            display.split('@').next().unwrap_or(&display)
        )
    } else {
        let Some((repo, reference)) = action.split_once('@') else {
            return;
        };
        let parts: Vec<_> = repo.split('/').collect();
        if parts.len() < 2
            || parts
                .iter()
                .any(|p| p.is_empty() || matches!(*p, "." | ".."))
            || !repo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || reference.is_empty()
            || !reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b))
        {
            return;
        }
        if parts[0].eq_ignore_ascii_case("actions")
            || parts[0].eq_ignore_ascii_case("github")
            || hex(reference, 40)
        {
            return;
        }
        // All variable output derives from this single bounded action name.
        let display: String = action.chars().take(100).collect();
        let (repo, reference) = display.split_once('@').unwrap_or((&display, "ref"));
        format!("pin it to a full commit SHA: {repo}@<40-hex sha> # {reference}")
    };
    let display: String = action.chars().take(100).collect();
    emit(
        issues,
        "gha-unpinned-action",
        Level::Medium,
        path,
        field.line,
        format!("third-party action {display} is pinned to a mutable tag or branch"),
        fix,
    );
}

const UNTRUSTED: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.head_commit.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
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

fn injection(node: &Node, path: &str, issues: &mut Vec<Issue>) {
    let (Node::Text(lines) | Node::Block(lines)) = node else {
        return;
    };
    let mut text = String::new();
    let mut offsets = Vec::new();
    for (line, content) in lines {
        offsets.push((text.len(), *line));
        text.push_str(content);
        text.push('\n');
    }
    let mut found = BTreeSet::new();
    let mut cursor = 0;
    while let Some(start) = text[cursor..].find("${{").map(|i| i + cursor + 3) {
        let Some(end) = expression_end(&text, start) else {
            break;
        };
        let mut index = start;
        while index < end {
            let c = text.as_bytes()[index];
            if matches!(c, b'\'' | b'"') {
                index = skip_string(&text, index).unwrap_or(end);
                continue;
            }
            if c.is_ascii_alphabetic() || c == b'_' {
                let (parts, next) = context_path(&text[..end], index);
                for canonical in UNTRUSTED {
                    let expected: Vec<_> = canonical.split('.').collect();
                    if parts.len() == expected.len()
                        && parts.iter().zip(expected).all(|(a, b)| {
                            if b == "*" {
                                a == "*" || (!a.is_empty() && a.bytes().all(|c| c.is_ascii_digit()))
                            } else {
                                a.eq_ignore_ascii_case(b)
                            }
                        })
                    {
                        let source = offsets
                            .partition_point(|(offset, _)| *offset <= index)
                            .saturating_sub(1);
                        found.insert((offsets[source].1, *canonical));
                    }
                }
                index = next;
            } else {
                index += 1;
            }
        }
        cursor = end + 2;
    }
    for (line, context) in found {
        emit(
            issues,
            "gha-script-injection",
            Level::High,
            path,
            line,
            format!("untrusted ${{{{ {context} }}}} is expanded into a shell script"),
            format!(
                "pass it through env (env: VALUE: ${{{{ {context} }}}}) and use \"$VALUE\" in the script"
            ),
        );
    }
}

fn skip_string(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == quote {
            if bytes.get(index + 1) == Some(&quote) {
                index += 2;
                continue;
            }
            return Some(index + 1);
        }
        if quote == b'"' && bytes[index] == b'\\' {
            index += 1;
        }
        index += 1;
    }
    None
}

fn expression_end(text: &str, mut index: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            index = skip_string(text, index)?;
        } else if bytes.get(index..index + 2) == Some(b"}}") {
            return Some(index);
        } else {
            index += 1;
        }
    }
    None
}

fn context_path(text: &str, start: usize) -> (Vec<String>, usize) {
    let bytes = text.as_bytes();
    let mut index = start;
    let mut parts = Vec::new();
    while index < bytes.len() {
        let begin = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-' | b'*'))
        {
            index += 1;
        }
        if begin == index {
            break;
        }
        parts.push(text[begin..index].to_owned());
        loop {
            let next = index;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if bytes.get(index) != Some(&b'[') {
                if bytes.get(index) != Some(&b'.') {
                    index = next;
                }
                break;
            }
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            let begin = index;
            let part = if bytes.get(index).is_some_and(|c| matches!(c, b'\'' | b'"')) {
                let Some(end) = skip_string(text, index) else {
                    return (parts, index.max(start + 1));
                };
                index = end;
                text[begin + 1..end - 1].to_owned()
            } else {
                while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'*')
                {
                    index += 1;
                }
                text[begin..index].to_owned()
            };
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if part.is_empty() || bytes.get(index) != Some(&b']') {
                return (parts, index.max(start + 1));
            }
            parts.push(part);
            index += 1;
        }
        if bytes.get(index) != Some(&b'.') {
            break;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
    }
    (parts, index.max(start + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn workflow(steps: &str) -> String {
        format!(
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{}\n",
            steps
                .lines()
                .map(|s| format!("      {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    fn findings(text: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        inspect(text, ".github/workflows/test.yml", false, &mut issues);
        issues
    }

    fn script(source: &str) -> Vec<Issue> {
        findings(&workflow(&format!("- run: {source}")))
    }

    fn check(issues: &[Issue], id: &str, level: Level, lines: &[usize]) {
        assert_eq!(issues.iter().map(|i| i.line).collect::<Vec<_>>(), lines);
        for issue in issues {
            assert_eq!(issue.id, id);
            assert_eq!(issue.level, level);
            assert_eq!(issue.path, ".github/workflows/test.yml");
        }
    }

    #[test]
    fn every_untrusted_context_and_index_form_is_detected() {
        for canonical in UNTRUSTED {
            for context in [
                canonical.to_string(),
                canonical.replace(".*.", "[12]."),
                canonical.replace(".*.", ".0."),
            ] {
                let issues = script(&format!("echo ${{{{ {context} }}}}"));
                check(&issues, "gha-script-injection", Level::High, &[6]);
                assert_eq!(
                    issues[0].message,
                    format!("untrusted ${{{{ {canonical} }}}} is expanded into a shell script")
                );
                assert_eq!(
                    issues[0].fix,
                    format!(
                        "pass it through env (env: VALUE: ${{{{ {canonical} }}}}) and use \"$VALUE\" in the script"
                    )
                );
            }
        }
        for context in [
            "github['head_ref']",
            "github.event['issue'].title",
            "github.event.commits[2]['author']['email']",
            "github . event . pages [ 42 ] . page_name",
        ] {
            check(
                &script(&format!("echo ${{{{ {context} }}}}")),
                "gha-script-injection",
                Level::High,
                &[6],
            );
        }
    }

    #[test]
    fn expressions_operations_strings_boundaries_and_deduplication() {
        let issues = script(
            "echo ${{ github.event.issue.title || 'fallback' }} ${{ format('{0}', github.head_ref) }} ${{ github.head_ref }}",
        );
        check(&issues, "gha-script-injection", Level::High, &[6, 6]);
        for safe in [
            "echo github.head_ref",
            "echo ${{ github.head_ref_extra }}",
            "echo ${{ notgithub.head_ref }}",
            "echo ${{ env.github.head_ref }}",
            "echo ${{ 'github.head_ref' }}",
            "echo ${{ format('github.head_ref', 'text') }}",
            "echo ${{ 'it''s github.head_ref' }}",
            "echo ${{ github.sha }}",
            "echo ${{ github.event.pull_request.number }}",
            "echo ${{ github.head_ref",
            "echo ${{ github.event.pages['unknown'].page_name }}",
        ] {
            assert!(script(safe).is_empty(), "{safe}");
        }
        check(
            &script("echo ${{ format('}}', github.head_ref) }}"),
            "gha-script-injection",
            Level::High,
            &[6],
        );
    }

    #[test]
    fn yaml_comments_and_shell_comments_have_different_meanings() {
        assert!(script("echo hi # ${{ github.head_ref }}").is_empty());
        assert!(script("echo hi # 'unterminated ${{ github.head_ref }}").is_empty());
        check(
            &script("echo '# ${{ github.head_ref }}'"),
            "gha-script-injection",
            Level::High,
            &[6],
        );
        check(
            &script("\"echo ${{ github.head_ref }}\" # comment"),
            "gha-script-injection",
            Level::High,
            &[6],
        );
        check(
            &script("'echo ${{ github.head_ref }}'"),
            "gha-script-injection",
            Level::High,
            &[6],
        );
        for indicator in ["|", "|-", "|+", ">", ">-", ">+"] {
            let text = workflow(&format!(
                "- run: {indicator} # header\n    echo before\n    # ${{{{ github.head_ref }}}}\n    echo ${{{{ github.event.issue.title }}}}\n- run: echo done"
            ));
            check(
                &findings(&text),
                "gha-script-injection",
                Level::High,
                &[8, 9],
            );
        }
    }

    #[test]
    fn only_step_scripts_are_checked_and_github_script_is_special() {
        let safe = workflow(
            "- name: ${{ github.head_ref }}\n  run: echo \"$VALUE\"\n  env:\n    VALUE: ${{ github.event.issue.title }}\n- uses: actions/checkout@v4\n  with:\n    script: ${{ github.head_ref }}\n- uses: actions/github-script@v7\n  with:\n    other: ${{ github.head_ref }}",
        );
        assert!(findings(&safe).is_empty());
        let text = workflow(
            "- uses: actions/github-script@v7\n  with:\n    script: |\n      // ${{ github.event.comment.body }}\n      console.log('${{ github.event.issue.body }}');",
        );
        check(
            &findings(&text),
            "gha-script-injection",
            Level::High,
            &[9, 10],
        );
        assert!(findings("env:\n  run: ${{ github.head_ref }}\njobs:\n  build:\n    run: ${{ github.head_ref }}\n").is_empty());
    }

    #[test]
    fn multiline_expression_and_unicode_keep_real_source_lines() {
        let text = workflow(
            "- run: |\n    echo привет\n    echo ${{\n      github.event.issue.title ||\n      github.head_ref\n    }}",
        );
        check(
            &findings(&text),
            "gha-script-injection",
            Level::High,
            &[9, 10],
        );
        check(
            &script("echo '🦀' ${{ github.head_ref }}"),
            "gha-script-injection",
            Level::High,
            &[6],
        );
    }

    #[test]
    fn privileged_events_in_every_on_form() {
        for event in ["pull_request_target", "workflow_run"] {
            for on in [
                format!("on: {event}"),
                format!("'on': '{event}'"),
                format!("on: [push, '{event}']"),
                format!("on:\n  - push\n  - {event}"),
                format!("on:\n- push\n- {event}"),
                format!("on:\n  {event}:\n    types: [opened, synchronize]"),
            ] {
                let reference = if event == "workflow_run" {
                    "${{ github.event.workflow_run.head_sha }}"
                } else {
                    "${{ github.event.pull_request.head.sha }}"
                };
                let text = workflow(&format!(
                    "- uses: actions/checkout@v4\n  with:\n    ref: {reference}"
                ))
                .replacen("on: push", &on, 1);
                let line = text
                    .lines()
                    .position(|s| s.trim_start().starts_with("ref:"))
                    .unwrap()
                    + 1;
                let issues = findings(&text);
                check(&issues, "gha-pwn-request", Level::High, &[line]);
                assert_eq!(
                    issues[0].message,
                    format!("{event} workflow checks out untrusted pull request code")
                );
            }
        }
    }

    #[test]
    fn checkout_ref_is_scoped_to_the_correct_step_and_trigger() {
        for reference in [
            "${{ github.head_ref }}",
            "${{ github.event.pull_request.head.ref }}",
            "refs/pull/42/head",
        ] {
            let text = workflow(&format!(
                "- uses: actions/checkout@v4\n  with:\n    ref: {reference}"
            ));
            assert!(findings(&text.replace("on: push", "on: pull_request")).is_empty());
            check(
                &findings(&text.replace("on: push", "on: pull_request_target")),
                "gha-pwn-request",
                Level::High,
                &[8],
            );
        }
        let unrelated = workflow("- uses: actions/checkout@v4\n  with:\n    ref: main\n- uses: actions/cache@v4\n  with:\n    ref: ${{ github.head_ref }}").replace("on: push", "on: pull_request_target");
        assert!(findings(&unrelated).is_empty());
        let no_ref = workflow("- uses: actions/checkout@v4\n- run: echo hi")
            .replace("on: push", "on: workflow_run");
        assert!(findings(&no_ref).is_empty());
    }

    #[test]
    fn action_pins_cover_actions_images_paths_and_reusable_workflows() {
        for action in [
            "vendor/tool@v1",
            "vendor/tool/path@main",
            "vendor/tool/.github/workflows/job.yml@v2",
            "docker://alpine:latest",
            "docker://registry.example:5000/image:tag",
        ] {
            let issues = findings(&workflow(&format!("- uses: {action}")));
            check(&issues, "gha-unpinned-action", Level::Medium, &[6]);
            assert!(issues[0].message.contains(action));
        }
        let sha = "aB12".repeat(10);
        let digest = "cD34".repeat(16);
        for action in [
            "./local/action".into(),
            "actions/checkout@v4".into(),
            "GitHub/codeql-action/init@v3".into(),
            "ACTIONS/cache@main".into(),
            format!("vendor/tool@{sha}"),
            format!("docker://image@sha256:{digest}"),
        ] {
            assert!(
                findings(&workflow(&format!("- uses: {action}"))).is_empty(),
                "{action}"
            );
        }
        check(
            &findings(
                "on: push\njobs:\n  reusable:\n    uses: vendor/repo/.github/workflows/build.yml@main",
            ),
            "gha-unpinned-action",
            Level::Medium,
            &[4],
        );
        assert!(findings(&workflow("- uses: ${{ inputs.action }}")).is_empty());
    }

    #[test]
    fn insecure_commands_only_in_env_at_supported_levels() {
        for value in ["true", "TRUE", "'TrUe'", "\"true\""] {
            let root = format!("env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: {value}");
            check(&findings(&root), "gha-insecure-commands", Level::High, &[2]);
            let job = format!(
                "jobs:\n  build:\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: {value}"
            );
            check(&findings(&job), "gha-insecure-commands", Level::High, &[4]);
            let step = workflow(&format!(
                "- run: echo hi\n  env:\n    ACTIONS_ALLOW_UNSECURE_COMMANDS: {value}"
            ));
            check(&findings(&step), "gha-insecure-commands", Level::High, &[8]);
        }
        for value in ["false", "'false'", "${{ inputs.enabled }}", "", "trueish"] {
            assert!(
                findings(&format!("env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: {value}")).is_empty()
            );
        }
        assert!(
            findings(&workflow(
                "- uses: actions/checkout@v4\n  with:\n    ACTIONS_ALLOW_UNSECURE_COMMANDS: true"
            ))
            .is_empty()
        );
        // Block scalars are not reduced to plain strings: their chomping and
        // folding semantics can change the value. Only scripts inspect bodies.
        assert!(findings("env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: |\n    true").is_empty());
    }

    #[test]
    fn permissions_only_at_workflow_and_job_level() {
        check(
            &findings("permissions: write-all\njobs:\n  build:\n    permissions: 'write-all'"),
            "gha-write-all-permissions",
            Level::Medium,
            &[1, 4],
        );
        for text in [
            "permissions: read-all",
            "permissions:\n  contents: read",
            "jobs:\n  build:\n    permissions: read-all",
            "name: no permissions",
        ] {
            assert!(findings(text).is_empty());
        }
        assert!(
            findings(&workflow(
                "- run: echo hi\n  permissions: write-all\n  env:\n    permissions: write-all"
            ))
            .is_empty()
        );
    }

    #[test]
    fn separate_sequence_markers_quoted_keys_and_composite_actions() {
        let text = "'on': [push]\n'jobs':\n  build:\n    'steps':\n    -\n      'run': echo ${{ github.head_ref }}\n    - name: next\n      run: echo hi\n";
        check(&findings(text), "gha-script-injection", Level::High, &[6]);
        let composite = "name: action\nruns:\n  using: composite\n  steps:\n    -\n      run: |\n        echo ${{ github.event.pull_request.title }}\n      shell: bash\n";
        let mut issues = Vec::new();
        inspect(composite, "action.yml", true, &mut issues);
        assert_eq!(issues.len(), 1);
        assert_eq!(
            (issues[0].id, issues[0].line, issues[0].path.as_str()),
            ("gha-script-injection", 7, "action.yml")
        );
        let mut ignored = Vec::new();
        inspect(
            &composite.replace("using: composite", "using: node20"),
            "action.yml",
            true,
            &mut ignored,
        );
        assert!(ignored.is_empty());
    }

    #[test]
    fn unknown_or_ambiguous_yaml_discards_all_findings() {
        for suffix in [
            "env: &shared\n  X: value",
            "env: *shared",
            "env:\n  <<: *shared",
            "---\nname: second",
            "...\nname: second",
            "env:\n\tX: value",
            "name: 'unterminated",
            "name: [push, &anchor target]",
            "permissions: { contents: read",
            "permissions: { contents: read } extra",
            "include: [{ os: linux }, { os: mac }",
            "name: first\nname: duplicate",
            "name: text\n  continued plain scalar",
            "name: !custom tagged",
            "name: [unclosed",
            "name: \"multiline\n  string\"",
            "name: unquoted colon: value",
        ] {
            let text = format!(
                "{}\n{suffix}\n",
                workflow("- run: echo ${{ github.head_ref }}")
            );
            assert!(findings(&text).is_empty(), "{suffix}");
        }
        let deep = (0..100)
            .map(|i| format!("{}node:\n", " ".repeat(i)))
            .collect::<String>();
        assert!(findings(&deep).is_empty());
        // YAML-looking text inside a script is not YAML structure.
        check(
            &findings(&workflow(
                "- run: |\n    ---\n    &not-an-anchor\n    echo ${{ github.head_ref }}",
            )),
            "gha-script-injection",
            Level::High,
            &[9],
        );
        let marked = format!(
            "# header\n---\n{}",
            workflow("- run: echo ${{ github.head_ref }}")
        );
        check(
            &findings(&marked),
            "gha-script-injection",
            Level::High,
            &[8],
        );
    }

    // Found on a corpus of real workflows: a third of the files were skipped
    // whole, most of them for `permissions: {}` and an apostrophe in a name.
    #[test]
    fn common_real_world_yaml_is_parsed_not_skipped() {
        let job = |extra: &str| {
            format!(
                "on: push\npermissions: {{}}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        include: [{{ os: linux, cc: \"gcc -m32\" }}, {{ os: mac }}]\n        target:\n          - {{ name: Linux, os: ubuntu-latest }}\n    permissions: {{ contents: read }}\n    steps:\n      - name: Check the PR's title # it's fine\n        if: github.event_name == 'push' && matrix.os != 'mac'\n        run: echo ${{{{ github.head_ref }}}}{extra}\n"
            )
        };
        check(
            &findings(&job("")),
            "gha-script-injection",
            Level::High,
            &[15],
        );
        // An apostrophe inside a plain scalar does not protect ` #`: as in YAML,
        // the rest of the line is a comment, so the expression is not in the script.
        check(
            &findings(&job(" # it's ${{ github.event.issue.title }}")),
            "gha-script-injection",
            Level::High,
            &[15],
        );
        // `: ` in a plain scalar is invalid YAML; the quote does not hide it.
        assert!(script("echo it's ${{ github.head_ref }}: oops").is_empty());
        // A quoted scalar still protects `#`, a quoted key is still a key.
        check(
            &script("\"echo ${{ github.head_ref }} # not a comment\""),
            "gha-script-injection",
            Level::High,
            &[6],
        );
        // Opaque flow mappings: nothing inside them is checked or reported.
        assert!(findings("permissions: { contents: write-all }\non: push\n").is_empty());
        assert!(findings("env: { ACTIONS_ALLOW_UNSECURE_COMMANDS: true }\non: push\n").is_empty());
    }

    #[test]
    fn privileged_checkout_behind_a_same_repository_guard_is_not_reported() {
        let text = |guard: &str, on: &str| {
            format!(
                "on: {on}\njobs:\n  build:\n{guard}    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n"
            )
        };
        for guard in [
            "    if: github.event.pull_request.head.repo.full_name == github.repository\n",
            "    if: ${{ github.repository == github.event.pull_request.head.repo.full_name }}\n",
            "    if: >\n      github.event_name == 'workflow_run' &&\n      github.event.workflow_run.conclusion == 'success' &&\n      github.event.workflow_run.head_repository.full_name == github.repository\n",
            "    if: github.event.pull_request.user.login == 'dependabot[bot]'\n",
            "    if: github.event.action != 'closed' && github.event.pull_request.head.repo.full_name == github.repository\n",
        ] {
            assert!(
                findings(&text(guard, "pull_request_target")).is_empty(),
                "{guard}"
            );
        }
        for bypass in [
            "    if: github.event.pull_request.head.repo.full_name == github.repository || true\n",
            "    if: \"!(github.event.pull_request.head.repo.full_name == github.repository)\"\n",
            "    if: github.event.pull_request.head.repo.full_name == github.repository_owner\n",
            "    if: github.event.pull_request.head.repo.full_name == github.repository.x\n",
            "    if: github.event.pull_request.user.login == 'dependabot[bot]-fake'\n",
        ] {
            check(
                &findings(&text(bypass, "pull_request_target")),
                "gha-pwn-request",
                Level::High,
                &[bypass.lines().count() + 8],
            );
        }
        // "Not this trigger, or a same-repository head" is the guard for that
        // trigger only; another privileged trigger still runs unguarded.
        let either = "    if: >-\n      needs.config.outputs.ok &&\n      (github.event_name != 'workflow_run' ||\n       github.event.workflow_run.head_repository.full_name == github.repository)\n";
        assert!(findings(&text(either, "workflow_run")).is_empty());
        let issues = findings(&text(either, "[workflow_run, pull_request_target]"));
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "pull_request_target workflow checks out untrusted pull request code"
        );
        let not_a_guard = "    if: github.event_name != 'workflow_run' || always()\n";
        assert_eq!(findings(&text(not_a_guard, "workflow_run")).len(), 1);
        // A guarded job does not run for forks, so its scripts see only
        // branch names and titles from people who can already push.
        let guarded = "on: pull_request\njobs:\n  perf:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - run: git fetch pr '${{ github.event.pull_request.head.ref }}'\n";
        assert!(findings(guarded).is_empty());
        assert_eq!(findings(&guarded.replace("    if: ", "    x: ")).len(), 1);
        // A guard on the checkout step itself counts too.
        let step = text("", "pull_request_target").replace(
            "      - uses: actions/checkout@v4\n",
            "      - if: github.event.pull_request.head.repo.full_name == github.repository\n        uses: actions/checkout@v4\n",
        );
        assert!(findings(&step).is_empty());
        // Both privileged triggers: one finding that names both.
        let both = findings(&text("", "[pull_request_target, workflow_run]"));
        assert_eq!(both.len(), 1);
        assert_eq!(
            both[0].message,
            "pull_request_target/workflow_run workflow checks out untrusted pull request code"
        );
    }

    #[test]
    fn reports_never_copy_script_bodies_and_bound_action_names() {
        let canary = ["private", "-script-canary"].concat();
        let text = workflow(&format!(
            "- run: |\n    echo '{canary}' ${{{{ github.head_ref }}}}\n- uses: vendor/{name}@v1",
            name = "a".repeat(150)
        ));
        let issues = findings(&text);
        assert_eq!(issues.len(), 2);
        assert!(!format!("{issues:?}").contains(&canary));
        let action = &issues[1];
        assert_eq!(
            action
                .message
                .strip_prefix("third-party action ")
                .unwrap()
                .strip_suffix(" is pinned to a mutable tag or branch")
                .unwrap()
                .chars()
                .count(),
            100
        );
        assert!(!format!("{issues:?}").contains(&"a".repeat(101)));
    }

    struct Project(PathBuf);
    impl Project {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "jetscan-workflows-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }
    impl Drop for Project {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn discovery_is_bounded_nonrecursive_read_only_and_deterministic() {
        let project = Project::new();
        assert!(run(&project.0).is_empty());
        assert!(run(&project.0.join("missing")).is_empty());
        let workflow = workflow("- run: echo ${{ github.head_ref }}");
        for name in [
            ".github/workflows/z.yml",
            ".github/workflows/a.yaml",
            ".github/workflows/nested/no.yml",
            ".github/workflows/no.txt",
            "other.yml",
        ] {
            project.write(name, &workflow);
        }
        let composite =
            "runs:\n  using: composite\n  steps:\n    - run: echo ${{ github.head_ref }}";
        project.write("action.yml", composite);
        project.write("action.yaml", composite);
        project.write(".github/workflows/invalid.yml", [255, 254]);
        project.write(
            ".github/workflows/large.yml",
            " ".repeat(MAX_BYTES as usize + 1),
        );
        fs::create_dir(project.0.join(".github/workflows/directory.yml")).unwrap();
        let issues = super::super::check(&project.0);
        assert_eq!(issues, run(&project.0));
        assert_eq!(issues, super::super::check(&project.0));
        assert_eq!(
            issues.iter().map(|i| i.path.as_str()).collect::<Vec<_>>(),
            vec![
                ".github/workflows/a.yaml",
                ".github/workflows/z.yml",
                "action.yaml",
                "action.yml"
            ]
        );
        assert_eq!(
            fs::read_to_string(project.0.join(".github/workflows/z.yml")).unwrap(),
            workflow
        );
        assert_eq!(
            fs::read_to_string(project.0.join("action.yml")).unwrap(),
            composite
        );
        assert!(read_file(&project.0.join(".github/workflows/large.yml")).is_none());
    }

    #[test]
    fn truncated_utf8_and_yaml_never_panic_or_expose_source() {
        let source = workflow(
            "- run: |\n    echo 'привет 🦀' ${{ github.head_ref }}\n- uses: vendor/tool@v1",
        );
        for end in source.char_indices().map(|(i, _)| i) {
            let issues = findings(&source[..end]);
            assert!(!format!("{issues:?}").contains("привет"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn discovery_does_not_follow_file_or_directory_symlinks() {
        use std::os::unix::fs::symlink;
        let outside = Project::new();
        outside.write(
            ".github/workflows/source.yml",
            workflow("- uses: vendor/tool@v1"),
        );
        let project = Project::new();
        fs::create_dir_all(project.0.join(".github/workflows")).unwrap();
        symlink(
            outside.0.join(".github/workflows/source.yml"),
            project.0.join(".github/workflows/link.yml"),
        )
        .unwrap();
        symlink(
            outside.0.join(".github/workflows/source.yml"),
            project.0.join("action.yml"),
        )
        .unwrap();
        assert!(run(&project.0).is_empty());
        let linked = Project::new();
        symlink(outside.0.join(".github"), linked.0.join(".github")).unwrap();
        assert!(run(&linked.0).is_empty());
    }
}
