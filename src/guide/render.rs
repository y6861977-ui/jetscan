//! The user guide's Markdown (`docs/guide/*.md`) as one self-contained offline HTML page:
//! inline CSS, no scripts, no external fonts, its own Content-Security-Policy, light/dark via
//! `prefers-color-scheme`, and a table of contents built from the `##` / `###` headings.
//!
//! Only the Markdown subset the guide uses: ATX headings, paragraphs, `-` and `1.` lists
//! (nested by indentation), pipe tables, fenced code blocks, `>` quotes, inline code (any
//! number of backticks), `[text](url)`, `<https://…>` autolinks and `**bold**`. Everything
//! else is printed as escaped text. Anchors follow GitHub's heading slugs, so the guide's
//! own `[…](#…)` links work in both places. A `<!-- toc -->` … `<!-- /toc -->` block in the
//! source is replaced by the generated table of contents.
//! Std only, like the rest of jetscan. Used by `jetscan guide` and by
//! `cargo run --example guide-html` (which regenerates the committed `docs/guide/*.html`).

use std::fmt::Write as _;

const CSS: &str = "\
:root{--bg:#ffffff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--code-bg:#f3f4f6;\
--link:#0b57d0;--accent:#0f766e;--quote:#fff8e1;--quote-line:#e0a800}
@media (prefers-color-scheme: dark){:root{--bg:#0f1115;--fg:#e6e8eb;--muted:#9aa4ae;\
--line:#30363d;--code-bg:#1b1f26;--link:#7cb4ff;--accent:#5eead4;--quote:#2a2410;\
--quote-line:#b8860b}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,\
\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif}
main{max-width:52rem;margin:0 auto;padding:1.5rem 1rem 4rem}
h1{font-size:2rem;line-height:1.2;margin:0 0 1rem}
h2{font-size:1.5rem;margin:2.5rem 0 .75rem;padding-top:.5rem;border-top:1px solid var(--line)}
h3{font-size:1.2rem;margin:1.75rem 0 .5rem}
h4{font-size:1rem;margin:1.25rem 0 .5rem}
h2,h3,h4{scroll-margin-top:1rem}
a{color:var(--link);overflow-wrap:anywhere}
a.anchor{color:var(--muted);text-decoration:none;margin-left:.35rem;font-weight:400;opacity:.5}
a.anchor:hover{opacity:1}
code{font:.9em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,\"Liberation Mono\",monospace;\
background:var(--code-bg);padding:.1em .3em;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:6px;padding:.75rem 1rem;\
overflow-x:auto;line-height:1.45}
pre code{background:none;padding:0;font-size:.85rem;overflow-wrap:normal;white-space:pre}
.table{overflow-x:auto;margin:1rem 0}
table{border-collapse:collapse;min-width:100%;font-size:.95rem}
th,td{border:1px solid var(--line);padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:var(--code-bg)}
blockquote{margin:1rem 0;padding:.5rem 1rem;background:var(--quote);\
border-left:4px solid var(--quote-line);border-radius:0 6px 6px 0}
blockquote p{margin:.4rem 0}
nav.toc{border:1px solid var(--line);border-radius:6px;padding:.5rem 1rem;margin:1rem 0 2rem}
nav.toc>strong{display:block;margin:.25rem 0}
nav.toc ul{margin:.25rem 0;padding-left:1.25rem}
nav.toc li{margin:.1rem 0}
nav.toc ul ul{font-size:.92rem}
nav.toc details>summary{cursor:pointer}
ul,ol{padding-left:1.5rem}
li{margin:.2rem 0}
li>ul,li>ol{margin:.2rem 0}
footer{color:var(--muted);font-size:.85rem;margin-top:3rem}
@media print{nav.toc{display:none}a{color:inherit}}
";

/// One heading, for the table of contents.
struct Heading {
    level: usize,
    id: String,
    html: String,
}

/// The whole page for the guide `md` in `lang` (`"en"` or `"ru"`: the `<html lang>`, the
/// table-of-contents label and the footer).
pub fn render_page(md: &str, lang: &str) -> String {
    let md = md.replace("\r\n", "\n");
    let lines: Vec<&str> = md.lines().collect();
    let mut slugs = Slugger::default();
    let mut headings = Vec::new();
    let body = render_blocks(&lines, &mut slugs, &mut headings);
    let title = headings
        .iter()
        .find(|h| h.level == 1)
        .map(|h| strip_tags(&h.html))
        .unwrap_or_else(|| "jetscan".to_string());
    let toc = render_toc(&headings, lang);
    let body = body.replace(TOC_PLACEHOLDER, &toc);
    let footer = if lang == "ru" {
        "Офлайн-версия справочника jetscan. Ничего не загружается из сети."
    } else {
        "Offline copy of the jetscan user guide. Nothing is loaded from the network."
    };
    format!(
        "<!doctype html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <title>{}</title>\n<style>\n{CSS}</style>\n</head>\n<body>\n<main>\n{body}\
         <footer>{footer}</footer>\n</main>\n</body>\n</html>\n",
        escape(&title)
    )
}

const TOC_PLACEHOLDER: &str = "\u{0}TOC\u{0}";

fn render_toc(headings: &[Heading], lang: &str) -> String {
    let label = if lang == "ru" {
        "Содержание"
    } else {
        "Contents"
    };
    let mut out = format!("<nav class=\"toc\">\n<strong>{label}</strong>\n<ul>\n");
    let mut open_sub = false;
    let mut open_item = false;
    for h in headings.iter().filter(|h| h.level == 2 || h.level == 3) {
        let link = format!("<a href=\"#{}\">{}</a>", h.id, strip_links(&h.html));
        if h.level == 2 {
            if open_sub {
                out.push_str("</ul>\n");
                open_sub = false;
            }
            if open_item {
                out.push_str("</li>\n");
            }
            let _ = write!(out, "<li>{link}");
            open_item = true;
        } else {
            if !open_sub {
                out.push_str("\n<ul>\n");
                open_sub = true;
            }
            let _ = writeln!(out, "<li>{link}</li>");
        }
    }
    if open_sub {
        out.push_str("</ul>\n");
    }
    if open_item {
        out.push_str("</li>\n");
    }
    out.push_str("</ul>\n</nav>\n");
    out
}

/// GitHub-style heading slugs: lower case, letters/digits/`-`/`_` kept, spaces become `-`,
/// everything else dropped; repeats get `-1`, `-2`, …
#[derive(Default)]
struct Slugger {
    seen: std::collections::HashMap<String, usize>,
}

impl Slugger {
    fn slug(&mut self, text: &str) -> String {
        let mut base = String::new();
        for c in text.chars().flat_map(char::to_lowercase) {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                base.push(c);
            } else if c == ' ' {
                base.push('-');
            }
        }
        let n = self.seen.entry(base.clone()).or_insert(0);
        let id = if *n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        *n += 1;
        id
    }
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// `- text` / `* text` / `12. text` → (indent, ordered, text).
fn list_marker(line: &str) -> Option<(usize, bool, &str)> {
    let indent = indent_of(line);
    let rest = &line[indent..];
    if let Some(t) = rest.strip_prefix("- ").or_else(|| rest.strip_prefix("* ")) {
        return Some((indent, false, t));
    }
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 && rest[digits..].starts_with(". ") {
        return Some((indent, true, &rest[digits + 2..]));
    }
    None
}

fn heading(line: &str) -> Option<(usize, &str)> {
    let hashes = line.bytes().take_while(|&b| b == b'#').count();
    if (1..=6).contains(&hashes) && line[hashes..].starts_with(' ') {
        Some((hashes, line[hashes + 1..].trim()))
    } else {
        None
    }
}

fn is_table_separator(line: &str) -> bool {
    let t = line.trim();
    t.starts_with('|') && t.contains('-') && t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
}

fn starts_block(lines: &[&str], i: usize) -> bool {
    let line = lines[i];
    let t = line.trim_start();
    heading(line).is_some()
        || t.starts_with("```")
        || t.starts_with("> ")
        || t == ">"
        || t.starts_with("<!--")
        || list_marker(line).is_some()
        || (t.starts_with('|') && i + 1 < lines.len() && is_table_separator(lines[i + 1]))
}

fn render_blocks(lines: &[&str], slugs: &mut Slugger, headings: &mut Vec<Heading>) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim();
        if t.is_empty() {
            i += 1;
            continue;
        }
        // The hand-written table of contents is replaced by the generated one.
        if t == "<!-- toc -->" {
            while i < lines.len() && lines[i].trim() != "<!-- /toc -->" {
                i += 1;
            }
            i += 1;
            out.push_str(TOC_PLACEHOLDER);
            continue;
        }
        if t.starts_with("<!--") {
            while i < lines.len() && !lines[i].contains("-->") {
                i += 1;
            }
            i += 1;
            continue;
        }
        if let Some((level, text)) = heading(line) {
            let html = inline(text);
            let id = slugs.slug(&strip_tags(&html));
            let _ = writeln!(
                out,
                "<h{level} id=\"{id}\">{html}<a class=\"anchor\" href=\"#{id}\" aria-hidden=\"true\">#</a></h{level}>"
            );
            headings.push(Heading { level, id, html });
            i += 1;
            continue;
        }
        if let Some(fence) = t.strip_prefix("```") {
            let lang = fence.trim();
            let indent = indent_of(line);
            let mut code = String::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with("```") {
                let l = lines[i];
                let cut = indent.min(indent_of(l));
                code.push_str(&escape(&l[cut..]));
                code.push('\n');
                i += 1;
            }
            i += 1; // closing fence
            let class = if lang.is_empty() {
                String::new()
            } else {
                format!(" class=\"language-{}\"", escape(lang))
            };
            let _ = writeln!(out, "<pre><code{class}>{code}</code></pre>");
            continue;
        }
        if t.starts_with('|') && i + 1 < lines.len() && is_table_separator(lines[i + 1]) {
            let header = cells(t);
            i += 2;
            out.push_str("<div class=\"table\"><table>\n<thead><tr>");
            for c in &header {
                let _ = write!(out, "<th>{}</th>", inline(c));
            }
            out.push_str("</tr></thead>\n<tbody>\n");
            while i < lines.len() && lines[i].trim().starts_with('|') {
                out.push_str("<tr>");
                let row = cells(lines[i].trim());
                for k in 0..header.len().max(row.len()) {
                    let c = row.get(k).map_or("", String::as_str);
                    let _ = write!(out, "<td>{}</td>", inline(c));
                }
                out.push_str("</tr>\n");
                i += 1;
            }
            out.push_str("</tbody>\n</table></div>\n");
            continue;
        }
        if t.starts_with("> ") || t == ">" {
            let mut inner = Vec::new();
            while i < lines.len() {
                let l = lines[i].trim_start();
                if let Some(rest) = l.strip_prefix("> ") {
                    inner.push(rest);
                } else if l == ">" {
                    inner.push("");
                } else {
                    break;
                }
                i += 1;
            }
            let _ = writeln!(
                out,
                "<blockquote>\n{}</blockquote>",
                render_blocks(&inner, slugs, headings)
            );
            continue;
        }
        if list_marker(line).is_some() {
            let start = i;
            let base = indent_of(line);
            i += 1;
            while i < lines.len() {
                let l = lines[i];
                if l.trim().is_empty() {
                    break;
                }
                match list_marker(l) {
                    Some((ind, _, _)) if ind >= base => {}
                    Some(_) => break,
                    None if indent_of(l) > base => {}
                    None => break,
                }
                i += 1;
            }
            out.push_str(&render_list(&lines[start..i]));
            continue;
        }
        // Paragraph: until a blank line or the start of another block.
        let mut text = vec![t];
        i += 1;
        while i < lines.len() && !lines[i].trim().is_empty() && !starts_block(lines, i) {
            text.push(lines[i].trim());
            i += 1;
        }
        let _ = writeln!(out, "<p>{}</p>", inline(&text.join(" ")));
    }
    out
}

/// A list block: items at the indentation of the first line; deeper markers are nested
/// lists, other deeper lines continue the item's text.
fn render_list(lines: &[&str]) -> String {
    let Some((base, ordered, _)) = list_marker(lines[0]) else {
        return String::new();
    };
    let tag = if ordered { "ol" } else { "ul" };
    let mut out = format!("<{tag}>\n");
    let mut i = 0;
    while i < lines.len() {
        let Some((_, _, first)) = list_marker(lines[i]) else {
            i += 1;
            continue;
        };
        let mut text = vec![first.trim()];
        i += 1;
        while i < lines.len() && list_marker(lines[i]).is_none() {
            text.push(lines[i].trim());
            i += 1;
        }
        let nested_start = i;
        while i < lines.len() && list_marker(lines[i]).is_none_or(|(ind, _, _)| ind > base) {
            i += 1;
        }
        let nested = if nested_start < i {
            render_list(&lines[nested_start..i])
        } else {
            String::new()
        };
        let _ = writeln!(out, "<li>{}{nested}</li>", inline(&text.join(" ")));
    }
    let _ = writeln!(out, "</{tag}>");
    out
}

/// Table cells; `\|` is a literal pipe inside a cell.
fn cells(row: &str) -> Vec<String> {
    let inner = row.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cur.push('|');
                chars.next();
            }
            '|' => cells.push(std::mem::take(&mut cur).trim().to_string()),
            _ => cur.push(c),
        }
    }
    cells.push(cur.trim().to_string());
    cells
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Inline Markdown: code spans first (their content is literal), then links, autolinks
/// and bold; everything else is escaped text.
fn inline(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '`' {
            let run = chars[i..].iter().take_while(|&&c| c == '`').count();
            if let Some(end) = find_run(&chars, i + run, run) {
                let mut code: String = chars[i + run..end].iter().collect();
                if code.len() > 1 && code.starts_with(' ') && code.ends_with(' ') {
                    code = code[1..code.len() - 1].to_string();
                }
                let _ = write!(out, "<code>{}</code>", escape(&code));
                i = end + run;
                continue;
            }
            out.push_str(&"`".repeat(run));
            i += run;
            continue;
        }
        if c == '['
            && let Some((text, url, next)) = link_at(&chars, i)
        {
            let _ = write!(out, "<a href=\"{}\">{}</a>", escape(&url), inline(&text));
            i = next;
            continue;
        }
        if c == '<' {
            let rest: String = chars[i + 1..].iter().collect();
            if (rest.starts_with("https://") || rest.starts_with("http://"))
                && let Some(end) = rest.find('>')
                && !rest[..end].contains(' ')
            {
                let url = &rest[..end];
                let _ = write!(out, "<a href=\"{0}\">{0}</a>", escape(url));
                i += 1 + url.chars().count() + 1;
                continue;
            }
        }
        if c == '*'
            && chars.get(i + 1) == Some(&'*')
            && let Some(end) = find_str(&chars, i + 2, &['*', '*'])
        {
            let inner: String = chars[i + 2..end].iter().collect();
            if !inner.trim().is_empty() {
                let _ = write!(out, "<strong>{}</strong>", inline(&inner));
                i = end + 2;
                continue;
            }
        }
        out.push_str(&escape(&c.to_string()));
        i += 1;
    }
    out
}

/// The next run of exactly `n` backticks at or after `from`.
fn find_run(chars: &[char], from: usize, n: usize) -> Option<usize> {
    let mut j = from;
    while j < chars.len() {
        if chars[j] == '`' {
            let run = chars[j..].iter().take_while(|&&c| c == '`').count();
            if run == n {
                return Some(j);
            }
            j += run;
        } else {
            j += 1;
        }
    }
    None
}

/// The next `pat` at or after `from`, skipping code spans.
fn find_str(chars: &[char], from: usize, pat: &[char]) -> Option<usize> {
    let mut j = from;
    while j + pat.len() <= chars.len() {
        if chars[j] == '`' {
            let run = chars[j..].iter().take_while(|&&c| c == '`').count();
            match find_run(chars, j + run, run) {
                Some(end) => j = end + run,
                None => j += run,
            }
            continue;
        }
        if chars[j..j + pat.len()] == *pat {
            return Some(j);
        }
        j += 1;
    }
    None
}

/// `[text](url)` starting at `i`: (text, url, index after the closing parenthesis).
fn link_at(chars: &[char], i: usize) -> Option<(String, String, usize)> {
    let close = find_str(chars, i + 1, &[']', '('])?;
    let text: String = chars[i + 1..close].iter().collect();
    if text.contains('[') {
        return None;
    }
    let url_start = close + 2;
    let end = chars[url_start..].iter().position(|&c| c == ')')? + url_start;
    let url: String = chars[url_start..end].iter().collect();
    if url.is_empty() || url.contains(' ') {
        return None;
    }
    Some((text, url, end + 1))
}

/// Text of rendered inline HTML without tags (for slugs and the page title).
fn strip_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

/// Heading HTML for the table of contents: links inside a link are not allowed.
fn strip_links(html: &str) -> String {
    let mut out = html.to_string();
    while let Some(start) = out.find("<a ") {
        let Some(open_end) = out[start..].find('>') else {
            break;
        };
        out.replace_range(start..start + open_end + 1, "");
        if let Some(close) = out[start..].find("</a>") {
            out.replace_range(start + close..start + close + 4, "");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_match_github() {
        let mut s = Slugger::default();
        assert_eq!(s.slug("1. What jetscan is"), "1-what-jetscan-is");
        assert_eq!(s.slug("8. AI editors (MCP)"), "8-ai-editors-mcp");
        assert_eq!(
            s.slug("4.7 resolve: fix what was found (alpha)"),
            "47-resolve-fix-what-was-found-alpha"
        );
        assert_eq!(s.slug("8. ИИ-редакторы (MCP)"), "8-ии-редакторы-mcp");
        assert_eq!(s.slug("Cursor"), "cursor");
        assert_eq!(s.slug("Cursor"), "cursor-1");
    }

    #[test]
    fn inline_code_links_bold_and_escaping() {
        assert_eq!(
            inline("run `a <b>` and **c** [d](#e) <https://x.example>"),
            "run <code>a &lt;b&gt;</code> and <strong>c</strong> <a href=\"#e\">d</a> \
             <a href=\"https://x.example\">https://x.example</a>"
        );
        assert_eq!(inline("`` `apk` is x ``"), "<code>`apk` is x</code>");
        assert_eq!(inline("a <token> b"), "a &lt;token&gt; b");
        assert_eq!(inline("**`x`**"), "<strong><code>x</code></strong>");
    }

    #[test]
    fn tables_keep_escaped_pipes() {
        assert_eq!(cells("| a | `x \\| y` | c |"), vec!["a", "`x | y`", "c"]);
    }

    #[test]
    fn nested_lists_and_toc() {
        let md = "# T\n\n<!-- toc -->\n- [x](#x)\n<!-- /toc -->\n\n## A b\n\n1. one\n   more\n2. two:\n   - **x**: y\n     z\n3. three\n\n### C\n\ntext\n";
        let html = render_page(md, "en");
        assert!(html.contains("<li>one more</li>"), "{html}");
        assert!(
            html.contains("<li>two:<ul>\n<li><strong>x</strong>: y z</li>\n</ul>\n</li>"),
            "{html}"
        );
        assert!(html.contains("<nav class=\"toc\">"), "{html}");
        assert!(html.contains("<a href=\"#a-b\">A b</a>"), "{html}");
        assert!(html.contains("<a href=\"#c\">C</a>"), "{html}");
        assert!(!html.contains("[x](#x)"), "{html}");
        assert!(!html.contains("<script"), "{html}");
    }

    #[test]
    fn code_blocks_are_escaped_and_not_parsed() {
        let html = render_page("```sh\n# not a heading\n<b>\n```\n", "en");
        assert!(html.contains(
            "<pre><code class=\"language-sh\"># not a heading\n&lt;b&gt;\n</code></pre>"
        ));
        assert!(!html.contains("<h1"));
    }
}
