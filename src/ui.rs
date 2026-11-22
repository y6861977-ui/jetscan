//! Shared CLI output helpers: ANSI colors, terminal-safe text, and layout.
//!
//! Colors are emitted only for a terminal when `NO_COLOR` is unset. The
//! decision is cached separately for stdout and stderr for the process.
//!
//! Windows consoles (the classic conhost window a double-clicked jetscan.exe opens) show
//! escape codes as text (`←[1m`) unless virtual terminal processing is switched on for
//! that window. `init_console` switches it on; a console where that fails gets no colors.
//! Text needs nothing extra: when stdout is a console, Rust's std writes it with
//! `WriteConsoleW` (UTF-16), so `→`, `—`, `✓` do not depend on the console code page.

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
    *ON.get_or_init(|| {
        let out = std::io::stdout();
        colors_on(no_color(), out.is_terminal(), || console::enable_vt(&out))
    })
}

fn stderr_colors() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        let err = std::io::stderr();
        colors_on(no_color(), err.is_terminal(), || console::enable_vt(&err))
    })
}

/// Prepares this terminal for jetscan's output: on Windows, escape-code colors for stdout
/// and stderr (see the module comment). Call once at startup, before any output; calling it
/// again does nothing. Without it, the first colored text does the same.
pub fn init_console() {
    stdout_colors();
    stderr_colors();
}

/// Whether to color a stream. `vt` is asked only for a terminal without `NO_COLOR`.
fn colors_on(no_color: bool, terminal: bool, vt: impl FnOnce() -> console::Vt) -> bool {
    // `NotConsole` with `terminal`: a Git Bash (mintty) or Cygwin terminal on Windows. Those
    // are pipes that render escape codes themselves.
    !no_color && terminal && vt() != console::Vt::Unsupported
}

/// Escape-code support of a Windows console. Other systems: terminals render them already.
mod console {
    // Outside Windows only the tests drive `enable`.
    #![cfg_attr(not(windows), allow(dead_code))]

    /// What enabling escape codes on one output stream found.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum Vt {
        /// Not a Windows console (a pipe, a file, or any non-Windows terminal).
        NotConsole,
        /// A console that renders escape codes (already did, or does now).
        On,
        /// A console that cannot: older Windows, or the mode could not be changed.
        Unsupported,
    }

    pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
    pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    /// Read and write the console mode of one stream (Win32 on Windows; a fake in tests).
    pub trait Mode {
        /// The current mode; `None` if the stream is not a console.
        fn get(&mut self) -> Option<u32>;
        /// Sets the mode; `false` if the console refused it.
        fn set(&mut self, mode: u32) -> bool;
    }

    /// Switches escape-code processing on, keeping the other mode bits, and checks that it
    /// stuck. Repeating it is harmless: an enabled console is left as it is.
    pub fn enable(console: &mut impl Mode) -> Vt {
        let Some(mode) = console.get() else {
            return Vt::NotConsole;
        };
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return Vt::On;
        }
        let wanted = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
        if !console.set(wanted) {
            return Vt::Unsupported;
        }
        match console.get() {
            Some(now) if now & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 => Vt::On,
            _ => Vt::Unsupported,
        }
    }

    #[cfg(windows)]
    pub fn enable_vt(stream: &impl std::os::windows::io::AsRawHandle) -> Vt {
        enable(&mut Win32(stream.as_raw_handle()))
    }

    #[cfg(not(windows))]
    pub fn enable_vt<T>(_stream: &T) -> Vt {
        Vt::NotConsole
    }

    #[cfg(windows)]
    struct Win32(std::os::windows::io::RawHandle);

    #[cfg(windows)]
    impl Mode for Win32 {
        fn get(&mut self) -> Option<u32> {
            console_mode(self.0, None)
        }
        fn set(&mut self, mode: u32) -> bool {
            console_mode(self.0, Some(mode)).is_some()
        }
    }

    /// `GetConsoleMode` (`set` = `None`) or `SetConsoleMode`. `None`: the call failed (for
    /// example, the handle is a pipe or a file). jetscan's only `unsafe` code.
    #[cfg(windows)]
    fn console_mode(handle: std::os::windows::io::RawHandle, set: Option<u32>) -> Option<u32> {
        use std::os::windows::io::RawHandle;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetConsoleMode(console: RawHandle, mode: *mut u32) -> i32;
            fn SetConsoleMode(console: RawHandle, mode: u32) -> i32;
        }
        // No standard handle (null) or INVALID_HANDLE_VALUE (-1): nothing to ask.
        if handle.is_null() || handle.addr() == usize::MAX {
            return None;
        }
        let mut mode = 0u32;
        // SAFETY: both functions only read `handle`, a standard handle that std holds for the
        // whole process (or a handle borrowed for this call); for a handle that is not a
        // console Windows returns an error, it does not misbehave. `&mut mode` is a valid,
        // aligned, writable u32 for the whole GetConsoleMode call, which writes only that.
        let ok = unsafe {
            match set {
                None => GetConsoleMode(handle, &mut mode),
                Some(m) => {
                    mode = m;
                    SetConsoleMode(handle, m)
                }
            }
        };
        (ok != 0).then_some(mode)
    }
}

fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("{code}{s}{RESET}")
    } else {
        s.to_string()
    }
}

/// Whether stdout gets escape codes (a color terminal without `NO_COLOR`).
pub fn colors() -> bool {
    stdout_colors()
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

    /// A console whose mode reads and writes can be scripted to fail.
    struct FakeConsole {
        mode: Option<u32>,
        accepts: bool,
        /// Whether an accepted `set` really changes the mode (some old consoles do not).
        sticks: bool,
        sets: Vec<u32>,
    }

    impl console::Mode for FakeConsole {
        fn get(&mut self) -> Option<u32> {
            self.mode
        }
        fn set(&mut self, mode: u32) -> bool {
            self.sets.push(mode);
            if self.accepts && self.sticks {
                self.mode = Some(mode);
            }
            self.accepts
        }
    }

    fn fake(mode: Option<u32>, accepts: bool, sticks: bool) -> FakeConsole {
        FakeConsole {
            mode,
            accepts,
            sticks,
            sets: Vec::new(),
        }
    }

    #[test]
    fn console_mode_enables_escape_codes_and_keeps_other_bits() {
        use console::{ENABLE_PROCESSED_OUTPUT as P, ENABLE_VIRTUAL_TERMINAL_PROCESSING as VT};
        let mut c = fake(Some(0x0002), true, true);
        assert_eq!(console::enable(&mut c), console::Vt::On);
        assert_eq!(c.sets, vec![0x0002 | P | VT]);
        // Again: already on, nothing is written.
        assert_eq!(console::enable(&mut c), console::Vt::On);
        assert_eq!(c.sets.len(), 1);
    }

    #[test]
    fn console_mode_failures_turn_colors_off() {
        // Old Windows: SetConsoleMode rejects the flag.
        let mut refused = fake(Some(0x0003), false, false);
        assert_eq!(console::enable(&mut refused), console::Vt::Unsupported);
        // It reports success but the flag does not stick.
        let mut ignored = fake(Some(0x0003), true, false);
        assert_eq!(console::enable(&mut ignored), console::Vt::Unsupported);
        // Not a console (a pipe or a file): nothing is set.
        let mut pipe = fake(None, true, true);
        assert_eq!(console::enable(&mut pipe), console::Vt::NotConsole);
        assert!(pipe.sets.is_empty());

        let on = || console::Vt::On;
        assert!(colors_on(false, true, on));
        assert!(!colors_on(false, true, || console::Vt::Unsupported));
        assert!(!colors_on(true, true, on), "NO_COLOR");
        assert!(!colors_on(false, false, on), "not a terminal");
        // A terminal that is not a Windows console (mintty, Unix) keeps its colors.
        assert!(colors_on(false, true, || console::Vt::NotConsole));
        // The console is not touched for NO_COLOR or redirected output.
        assert!(!colors_on(true, true, || panic!("asked the console")));
        assert!(!colors_on(false, false, || panic!("asked the console")));
    }

    #[cfg(windows)]
    #[test]
    fn a_file_is_not_a_console() {
        let path = std::env::temp_dir().join(format!("jetscan-ui-vt-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        assert_eq!(console::enable_vt(&file), console::Vt::NotConsole);
        drop(file);
        let _ = std::fs::remove_file(&path);
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
