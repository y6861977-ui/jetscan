//! CL-WEB-03: позиции `file:line:column` и безопасные фрагменты.
//!
//! - Строка и колонка — с 1, колонка в символах Unicode (как у `jetscan secrets`).
//! - Позиция считается только из реального байтового смещения внутри текста; если смещение
//!   не на границе символа или вне текста — позиции нет (`None`), а не «примерно здесь».
//! - Фрагмент (`redacted_excerpt`) никогда не содержит значений литералов: каждая строка,
//!   шаблон и регулярка на строке заменяются на `"…"`, а литерал с находкой — на маску.
//!   Комментарии выбрасываются. Остаются только имена и синтаксис кода.

use super::lexer::{Class, Lexed};
use crate::ui;

/// Максимальная длина фрагмента в символах.
pub const EXCERPT_MAX_CHARS: usize = 160;

pub struct LineIndex {
    /// Байтовые начала строк.
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(text: &str) -> LineIndex {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        LineIndex { starts }
    }

    /// `(строка, колонка)` для байтового смещения; `None`, если смещение невалидно.
    pub fn line_col(&self, text: &str, byte: usize) -> Option<(u32, u32)> {
        if byte > text.len() || !text.is_char_boundary(byte) {
            return None;
        }
        let line = self.starts.partition_point(|&s| s <= byte) - 1;
        let col = text[self.starts[line]..byte].chars().count() + 1;
        Some((u32::try_from(line + 1).ok()?, u32::try_from(col).ok()?))
    }

    /// Байтовый диапазон строки `line` (с 1) без `\n` и `\r`.
    pub fn line_range(&self, text: &str, line: usize) -> Option<(usize, usize)> {
        let start = *self.starts.get(line.checked_sub(1)?)?;
        let mut end = self.starts.get(line).map_or(text.len(), |next| next - 1);
        if end > start && text.as_bytes()[end - 1] == b'\r' {
            end -= 1;
        }
        Some((start, end))
    }

    /// Байт, на котором стоит символ `col` (с 1) строки `line` (с 1).
    pub fn byte_at(&self, text: &str, line: usize, col: usize) -> Option<usize> {
        let (start, end) = self.line_range(text, line)?;
        if col == 0 {
            return None;
        }
        let offset = text[start..end]
            .char_indices()
            .nth(col - 1)
            .map(|(i, _)| i)?;
        Some(start + offset)
    }
}

/// Фрагмент строки кода вокруг находки `[hit_start, hit_end)`, где сама находка — `masked`.
/// Если находка не внутри литерала (например, JSX-текст), фрагмент — только маска:
/// без литерала мы не знаем, где кончается «код» и начинаются данные.
pub fn code_excerpt(
    text: &str,
    lexed: &Lexed,
    index: &LineIndex,
    hit_start: usize,
    hit_end: usize,
    masked: &str,
) -> String {
    let Some(hit_literal) = lexed.literal_at(hit_start).copied() else {
        return ui::sanitize_line(masked);
    };
    let Some((line, _)) = index.line_col(text, hit_start) else {
        return ui::sanitize_line(masked);
    };
    let Some((line_start, line_end)) = index.line_range(text, line as usize) else {
        return ui::sanitize_line(masked);
    };
    let (out, mut mask_at) = render(
        text,
        lexed,
        line_start,
        line_end,
        Some((hit_literal, hit_start, hit_end, masked)),
    );
    window(&collapse_spaces(&out, &mut mask_at), mask_at, masked)
}

/// Строка кода, на которой стоит байт `at` (в коде, не в литерале): все литералы — `…`,
/// комментарии выброшены. Для находок без секрета (синк XSS и т. п.).
pub fn redacted_line(text: &str, lexed: &Lexed, index: &LineIndex, at: usize) -> String {
    let Some((line, _)) = index.line_col(text, at) else {
        return String::new();
    };
    let Some((line_start, line_end)) = index.line_range(text, line as usize) else {
        return String::new();
    };
    let (out, _) = render(text, lexed, line_start, line_end, None);
    let (before, _) = render(text, lexed, line_start, at.min(line_end), None);
    let mut anchor = before.chars().count();
    window(&collapse_spaces(&out, &mut anchor), anchor, "")
}

/// Рисует `[line_start, line_end)`: код как есть, комментарии — пробел, литералы — `…`,
/// литерал с находкой — маска. Возвращает текст и позицию маски (в символах).
fn render(
    text: &str,
    lexed: &Lexed,
    line_start: usize,
    line_end: usize,
    hit: Option<(super::lexer::Literal, usize, usize, &str)>,
) -> (String, usize) {
    let mut out = String::new();
    let mut mask_at = 0;
    let mut i = line_start;
    while i < line_end {
        match lexed.class_at(i) {
            Class::Comment => {
                while i < line_end && lexed.class_at(i) == Class::Comment {
                    i += 1;
                }
                out.push(' ');
            }
            Class::Code => {
                let start = i;
                while i < line_end && lexed.class_at(i) == Class::Code {
                    i += 1;
                }
                out.push_str(&text[start..i]);
            }
            _ => {
                let Some(literal) = lexed.literal_at(i).copied() else {
                    i += 1;
                    continue;
                };
                let seg_end = literal.end.min(line_end);
                let seg = &text[i..seg_end];
                let open = if i == literal.start { opening(seg) } else { "" };
                let close = if seg_end == literal.end {
                    closing(seg, literal.kind)
                } else {
                    ""
                };
                out.push_str(open);
                match hit {
                    Some((hit_literal, hit_start, hit_end, masked)) if literal == hit_literal => {
                        if hit_start > literal.start + open.len() {
                            out.push('…');
                        }
                        mask_at = out.chars().count();
                        out.push_str(masked);
                        if hit_end + close.len() < literal.end {
                            out.push('…');
                        }
                    }
                    _ if seg.len() > open.len() + close.len() => out.push('…'),
                    _ => {}
                }
                out.push_str(close);
                i = seg_end;
            }
        }
    }
    (out, mask_at)
}

fn opening(seg: &str) -> &'static str {
    match seg.as_bytes().first() {
        Some(b'"') => "\"",
        Some(b'\'') => "'",
        Some(b'`') => "`",
        Some(b'}') => "}",
        Some(b'/') => "/",
        _ => "",
    }
}

fn closing(seg: &str, kind: Class) -> &'static str {
    if seg.len() < 2 {
        return "";
    }
    match kind {
        Class::Template if seg.ends_with("${") => "${",
        Class::Template if seg.ends_with('`') => "`",
        Class::Str if seg.ends_with('"') => "\"",
        Class::Str if seg.ends_with('\'') => "'",
        Class::Regex => "/",
        _ => "",
    }
}

/// Схлопывает пробелы и обрезает края; сдвигает позицию маски (в символах).
fn collapse_spaces(s: &str, mask_at: &mut usize) -> String {
    let mut out = String::new();
    let mut removed_before_mask = 0;
    let mut last_space = true;
    for (n, c) in s.chars().enumerate() {
        let space = c.is_whitespace();
        if space && last_space {
            if n < *mask_at {
                removed_before_mask += 1;
            }
            continue;
        }
        out.push(if space { ' ' } else { c });
        last_space = space;
    }
    *mask_at -= removed_before_mask.min(*mask_at);
    out.trim_end().to_string()
}

/// Обрезает до `EXCERPT_MAX_CHARS`, оставляя маску видимой.
fn window(s: &str, mask_at: usize, masked: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= EXCERPT_MAX_CHARS {
        return ui::sanitize_line(s);
    }
    let mask_len = masked.chars().count();
    let room = EXCERPT_MAX_CHARS.saturating_sub(mask_len + 2) / 2;
    let start = mask_at.saturating_sub(room);
    let end = (mask_at + mask_len + room).min(chars.len());
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.extend(&chars[start..end]);
    if end < chars.len() {
        out.push('…');
    }
    ui::sanitize_line(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::lexer::lex;

    #[test]
    fn line_col_counts_chars_and_rejects_bad_offsets() {
        let text = "ab\r\nпривет x\nlast";
        let index = LineIndex::new(text);
        assert_eq!(index.line_col(text, 0), Some((1, 1)));
        let x = text.find('x').unwrap();
        assert_eq!(index.line_col(text, x), Some((2, 8)));
        // Середина кириллического символа — не позиция.
        assert_eq!(index.line_col(text, "ab\r\nп".len() - 1), None);
        assert_eq!(index.line_col(text, text.len() + 1), None);
        assert_eq!(index.line_col(text, text.len()), Some((3, 5)));
    }

    #[test]
    fn line_range_and_byte_at_round_trip() {
        let text = "ab\r\nпривет x\nlast";
        let index = LineIndex::new(text);
        let (s, e) = index.line_range(text, 1).unwrap();
        assert_eq!(&text[s..e], "ab");
        let (s, e) = index.line_range(text, 2).unwrap();
        assert_eq!(&text[s..e], "привет x");
        let x = index.byte_at(text, 2, 8).unwrap();
        assert_eq!(&text[x..x + 1], "x");
        assert_eq!(index.line_col(text, x), Some((2, 8)));
        assert!(index.byte_at(text, 2, 99).is_none());
        assert!(index.line_range(text, 4).is_none());
    }

    fn excerpt_for(text: &str, needle: &str) -> String {
        let lexed = lex(text);
        let index = LineIndex::new(text);
        let start = text.find(needle).unwrap();
        code_excerpt(text, &lexed, &index, start, start + needle.len(), "MASKED")
    }

    #[test]
    fn excerpt_hides_every_literal_value_and_comment() {
        let text = "const a = {pw: \"hunter22\", key: \"SECRETVALUE\"}; // note: other\n";
        let e = excerpt_for(text, "SECRETVALUE");
        assert_eq!(e, "const a = {pw: \"…\", key: \"MASKED\"};");
        assert!(!e.contains("hunter22") && !e.contains("note"));
    }

    #[test]
    fn excerpt_marks_partial_literal_and_template_chunks() {
        let text = "fetch(u, { headers: { a: `Bearer SECRETVALUE ${x}` } })";
        let e = excerpt_for(text, "SECRETVALUE");
        assert_eq!(e, "fetch(u, { headers: { a: `…MASKED…${x}` } })");
    }

    #[test]
    fn excerpt_outside_literal_is_mask_only() {
        let text = "<p>SECRETVALUE and other words</p>";
        assert_eq!(excerpt_for(text, "SECRETVALUE"), "MASKED");
    }

    #[test]
    fn long_lines_are_windowed_around_the_mask() {
        let text = format!(
            "{} k = \"SECRETVALUE\"; {}",
            "a".repeat(300),
            "b".repeat(300)
        );
        let e = excerpt_for(&text, "SECRETVALUE");
        assert!(e.chars().count() <= EXCERPT_MAX_CHARS + 2);
        assert!(e.contains("MASKED"));
        assert!(e.starts_with('…') && e.ends_with('…'));
    }

    #[test]
    fn excerpt_strips_terminal_controls() {
        let text = "const \u{1b}[31mx = \"SECRETVALUE\"";
        let e = excerpt_for(text, "SECRETVALUE");
        assert!(!e.chars().any(|c| c.is_control()));
    }
}
