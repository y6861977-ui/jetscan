//! Shared CLI output helpers: ANSI colors, terminal-safe text, and layout.
//!
//! Colors are emitted only for a terminal when `NO_COLOR` is unset. The
//! decision is cached separately for stdout and stderr for the process.

use std::io::IsTerminal;
use std::sync::OnceLock;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

const FAIL: &str = "✗";
const ARROW: &str = "→";
const PAD: &str = "  ";

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some()
}

fn stdout_colors() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !no_color() && std::io::stdout().is_terminal())
}

fn stderr_colors() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !no_color() && std::io::stderr().is_terminal())
}

fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("{code}{s}{RESET}")
    } else {
        s.to_string()
    }
}

/// Heading or other emphasized text.
pub fn bold(s: &str) -> String {
    paint(stdout_colors(), BOLD, s)
}

/// Secondary text, such as labels, hints, and paths.
pub fn dim(s: &str) -> String {
    paint(stdout_colors(), DIM, s)
}

/// Success text.
pub fn green(s: &str) -> String {
    paint(stdout_colors(), GREEN, s)
}

/// Error text.
pub fn red(s: &str) -> String {
    paint(stdout_colors(), RED, s)
}

/// Warning text.
pub fn yellow(s: &str) -> String {
    paint(stdout_colors(), YELLOW, s)
}

/// Accent text, such as commands, URLs, and values.
pub fn cyan(s: &str) -> String {
    paint(stdout_colors(), CYAN, s)
}

/// Bold green text for a final success line.
pub fn bold_green(s: &str) -> String {
    paint(stdout_colors(), &format!("{BOLD}{GREEN}"), s)
}

/// Pad a string on the right to `width` characters.
pub fn pad_right(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

/// Pad a string on the left to `width` characters.
pub fn pad_left(s: &str, width: usize) -> String {
    let len = s.chars().count();
    format!("{}{s}", " ".repeat(width.saturating_sub(len)))
}

fn unsafe_control(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Neutralize untrusted terminal text by removing control characters.
/// Newlines and tabs are retained for readable multi-line output. C1 and
/// bidirectional formatting controls are removed as well.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|&c| c == '\n' || c == '\t' || !unsafe_control(c))
        .collect()
}

/// Sanitize an untrusted value that must remain on one output line.
/// Line-breaking whitespace becomes a plain space instead of disappearing.
pub fn sanitize_line(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' => Some(' '),
            c if unsafe_control(c) => None,
            c => Some(c),
        })
        .collect()
}

/// Format a count followed by its singular or plural noun.
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Print an error heading to stderr.
pub fn eprint_error(message: &str) {
    let head = paint(
        stderr_colors(),
        &format!("{BOLD}{RED}"),
        &format!("{FAIL} Error"),
    );
    eprintln!("\n{head}  {message}");
}

/// Print a hint line to stderr.
pub fn eprint_hint(text: &str) {
    let arrow = paint(stderr_colors(), DIM, ARROW);
    let text = paint(stderr_colors(), DIM, text);
    eprintln!("{PAD}{arrow} {text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_counts_chars_not_bytes() {
        assert_eq!(pad_right("café", 6), "café  ");
        assert_eq!(pad_right("npm", 6), "npm   ");
        assert_eq!(pad_right("very-long-name", 4), "very-long-name");
        assert_eq!(pad_left("3.4 MB", 8), "  3.4 MB");
        assert_eq!(pad_left("—", 3), "  —");
        assert_eq!(pad_left("longish", 2), "longish");
    }

    #[test]
    fn english_plurals() {
        let dependency = |n| plural(n, "dependency", "dependencies");
        assert_eq!(dependency(1), "1 dependency");
        assert_eq!(dependency(2), "2 dependencies");
        assert_eq!(dependency(0), "0 dependencies");
    }

    #[test]
    fn paint_respects_the_switch() {
        assert_eq!(paint(false, BOLD, "done"), "done");
        assert_eq!(paint(false, RED, "error"), "error");

        let styled = paint(true, GREEN, "ok");
        assert_eq!(styled, "\x1b[32mok\x1b[0m");
        assert!(styled.ends_with(RESET));
    }

    #[test]
    fn sanitize_removes_ansi_and_control_characters() {
        let sanitized = sanitize("safe\x1b[31mRED\x1b[0m\0\u{7f}\r\n\ttext");

        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\0'));
        assert!(!sanitized.contains('\u{7f}'));
        assert!(!sanitized.contains('\r'));
        assert_eq!(sanitized, "safe[31mRED[0m\n\ttext");
    }

    #[test]
    fn sanitize_removes_c1_controls_including_csi() {
        let sanitized = sanitize("a\u{0080}b\u{009b}31mred\u{009f}c");

        assert_eq!(sanitized, "ab31mredc");
    }

    #[test]
    fn sanitize_removes_every_bidi_formatting_control() {
        let bidi = [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}',
        ];

        for control in bidi {
            let input = format!("left{control}right");
            assert_eq!(
                sanitize(&input),
                "leftright",
                "failed for U+{:04X}",
                control as u32
            );
        }
    }

    #[test]
    fn sanitize_line_replaces_line_breaking_whitespace() {
        assert_eq!(sanitize_line("one\ntwo\rthree\tfour"), "one two three four");
    }

    #[test]
    fn sanitizers_preserve_normal_unicode() {
        let text = "кириллица, emoji 🚀, café";

        assert_eq!(sanitize(text), text);
        assert_eq!(sanitize_line(text), text);
    }
}
