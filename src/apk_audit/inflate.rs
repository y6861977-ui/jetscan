//! Inflate (RFC 1951) — порт `puff.c` Марка Адлера на Rust.
//!
//! Это ИЗМЕНЁННАЯ версия (altered source version в смысле лицензии ниже): переписана с C на Rust
//! для jetscan в 2026 году, не оригинальная программа. Отличия от оригинала:
//! - нет `setjmp`/`longjmp`: нехватка входа — `Err(InflateError::InputTruncated)`;
//! - выход — `Vec<u8>` с жёстким потолком `max_out` (защита от zip-бомб): превышение —
//!   `Err(InflateError::OutputLimit)`, а не запись за край буфера;
//! - нет режима «только посчитать размер» (`NIL`);
//! - используется простой (`SLOW`) вариант `decode()` — его проще сверить с оригиналом;
//! - таблицы фиксированных кодов строятся один раз через `OnceLock` (потокобезопасно);
//! - коды ошибок оригинала стали вариантами `InflateError` (соответствие — в комментариях).
//!
//! Оригинальные заголовки и лицензия (сохранены дословно):
//!
//! ```text
//! puff.c
//! Copyright (C) 2002-2013 Mark Adler
//! For conditions of distribution and use, see copyright notice in puff.h
//! version 2.3, 21 Jan 2013
//! ```
//!
//! ```text
//! /* puff.h
//!   Copyright (C) 2002-2013 Mark Adler, all rights reserved
//!   version 2.3, 21 Jan 2013
//!
//!   This software is provided 'as-is', without any express or implied
//!   warranty.  In no event will the author be held liable for any damages
//!   arising from the use of this software.
//!
//!   Permission is granted to anyone to use this software for any purpose,
//!   including commercial applications, and to alter it and redistribute it
//!   freely, subject to the following restrictions:
//!
//!   1. The origin of this software must not be misrepresented; you must not
//!      claim that you wrote the original software. If you use this software
//!      in a product, an acknowledgment in the product documentation would be
//!      appreciated but is not required.
//!   2. Altered source versions must be plainly marked as such, and must not be
//!      misrepresented as being the original software.
//!   3. This notice may not be removed or altered from any source distribution.
//!
//!   Mark Adler    madler@alumni.caltech.edu
//!  */
//! ```

use std::sync::OnceLock;

/// Максимумы формата deflate (менять бессмысленно).
const MAXBITS: usize = 15;
const MAXLCODES: usize = 286;
const MAXDCODES: usize = 30;
const MAXCODES: usize = MAXLCODES + MAXDCODES;
const FIXLCODES: usize = 288;

/// Ошибки. В скобках — код возврата `puff()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InflateError {
    /// (2) входные данные кончились раньше последнего блока.
    InputTruncated,
    /// (1) распакованное превысило `max_out`.
    OutputLimit,
    /// (-1) тип блока 3.
    InvalidBlockType,
    /// (-2) длина stored-блока не совпала с дополнением.
    StoredLengthMismatch,
    /// (-3) слишком много кодов длин или расстояний.
    TooManyCodes,
    /// (-4) неполный набор длин для кодов длин.
    IncompleteCodeLengthCodes,
    /// (-5) повтор длины без предыдущей длины.
    RepeatWithoutLength,
    /// (-6) повтор вышел за число длин.
    TooManyLengths,
    /// (-7) неверные длины кодов литералов/длин.
    InvalidLiteralLengths,
    /// (-8) неверные длины кодов расстояний.
    InvalidDistanceLengths,
    /// (-9) нет кода конца блока.
    MissingEndOfBlock,
    /// (-10) неверный код литерала/длины или расстояния.
    InvalidCode,
    /// (-11) расстояние указывает раньше начала вывода.
    DistanceTooFar,
}

impl InflateError {
    pub fn label(self) -> &'static str {
        match self {
            InflateError::InputTruncated => "deflate data ends before the last block",
            InflateError::OutputLimit => "inflated size exceeds the limit",
            InflateError::InvalidBlockType => "invalid deflate block type",
            InflateError::StoredLengthMismatch => "stored block length check failed",
            InflateError::TooManyCodes => "too many length or distance codes",
            InflateError::IncompleteCodeLengthCodes => "incomplete code length codes",
            InflateError::RepeatWithoutLength => "length repeat with no previous length",
            InflateError::TooManyLengths => "length repeat beyond the declared count",
            InflateError::InvalidLiteralLengths => "invalid literal/length code lengths",
            InflateError::InvalidDistanceLengths => "invalid distance code lengths",
            InflateError::MissingEndOfBlock => "dynamic block has no end-of-block code",
            InflateError::InvalidCode => "invalid literal/length or distance code",
            InflateError::DistanceTooFar => "distance too far back",
        }
    }
}

/// Сколько блоков каждого типа встретилось (для тестов и диагностики).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockStats {
    pub stored: usize,
    pub fixed: usize,
    pub dynamic: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Сколько байт входа съедено (до конца последнего блока, с неполным последним байтом).
    pub consumed: usize,
    pub blocks: BlockStats,
}

/// Таблицы канонического кода Хаффмана: `count[len]` — число символов длины `len`,
/// `symbol` — символы по возрастанию длины, внутри длины — по порядку.
struct Huffman {
    count: [u16; MAXBITS + 1],
    symbol: [u16; FIXLCODES],
}

impl Huffman {
    fn new() -> Huffman {
        Huffman {
            count: [0; MAXBITS + 1],
            symbol: [0; FIXLCODES],
        }
    }
}

struct State<'a> {
    input: &'a [u8],
    incnt: usize,
    bitbuf: u32,
    bitcnt: u32,
    out: Vec<u8>,
    max_out: usize,
}

impl State<'_> {
    /// `need` бит из потока (младшие биты байта — первыми). Оставляет в буфере < 8 бит.
    fn bits(&mut self, need: u32) -> Result<u32, InflateError> {
        let mut val = u64::from(self.bitbuf);
        while self.bitcnt < need {
            let byte = *self
                .input
                .get(self.incnt)
                .ok_or(InflateError::InputTruncated)?;
            self.incnt += 1;
            val |= u64::from(byte) << self.bitcnt;
            self.bitcnt += 8;
        }
        self.bitbuf = (val >> need) as u32;
        self.bitcnt -= need;
        Ok((val & ((1u64 << need) - 1)) as u32)
    }

    fn push(&mut self, byte: u8) -> Result<(), InflateError> {
        if self.out.len() >= self.max_out {
            return Err(InflateError::OutputLimit);
        }
        self.out.push(byte);
        Ok(())
    }

    /// Stored-блок: длина и её дополнение выровнены по байту, дальше — байты как есть.
    fn stored(&mut self) -> Result<(), InflateError> {
        self.bitbuf = 0;
        self.bitcnt = 0;
        let header = self
            .input
            .get(self.incnt..self.incnt + 4)
            .ok_or(InflateError::InputTruncated)?;
        let len = usize::from(header[0]) | (usize::from(header[1]) << 8);
        if usize::from(header[2]) != (!len & 0xff) || usize::from(header[3]) != ((!len >> 8) & 0xff)
        {
            return Err(InflateError::StoredLengthMismatch);
        }
        self.incnt += 4;
        let data = self
            .input
            .get(self.incnt..self.incnt + len)
            .ok_or(InflateError::InputTruncated)?;
        if self.out.len() + len > self.max_out {
            return Err(InflateError::OutputLimit);
        }
        self.out.extend_from_slice(data);
        self.incnt += len;
        Ok(())
    }

    /// Простой (`SLOW`) вариант `decode()` из puff.c: по биту, сравнивая с первым кодом длины.
    fn decode(&mut self, h: &Huffman) -> Result<u16, InflateError> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAXBITS {
            code |= self.bits(1)? as i32;
            let count = i32::from(h.count[len]);
            if code - count < first {
                return Ok(h.symbol[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(InflateError::InvalidCode)
    }

    /// Литералы и пары длина/расстояние до кода конца блока.
    fn codes(&mut self, lencode: &Huffman, distcode: &Huffman) -> Result<(), InflateError> {
        const LENS: [u16; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
            115, 131, 163, 195, 227, 258,
        ];
        const LEXT: [u32; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        const DISTS: [u32; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        const DEXT: [u32; 30] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13, 13,
        ];
        loop {
            let symbol = self.decode(lencode)?;
            if symbol < 256 {
                self.push(symbol as u8)?;
            } else if symbol > 256 {
                let symbol = usize::from(symbol - 257);
                if symbol >= 29 {
                    return Err(InflateError::InvalidCode);
                }
                let len = usize::from(LENS[symbol]) + self.bits(LEXT[symbol])? as usize;
                let dsym = usize::from(self.decode(distcode)?);
                if dsym >= 30 {
                    return Err(InflateError::InvalidCode);
                }
                let dist = (DISTS[dsym] + self.bits(DEXT[dsym])?) as usize;
                if dist > self.out.len() {
                    return Err(InflateError::DistanceTooFar);
                }
                if self.out.len() + len > self.max_out {
                    return Err(InflateError::OutputLimit);
                }
                // Перекрывающееся копирование (len > dist) — побайтно вперёд, как в оригинале.
                for _ in 0..len {
                    let byte = self.out[self.out.len() - dist];
                    self.out.push(byte);
                }
            } else {
                return Ok(());
            }
        }
    }

    fn fixed(&mut self) -> Result<(), InflateError> {
        let (lencode, distcode) = fixed_tables();
        self.codes(lencode, distcode)
    }

    fn dynamic(&mut self) -> Result<(), InflateError> {
        const ORDER: [usize; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let mut lengths = [0u16; MAXCODES];
        let mut lencode = Huffman::new();
        let mut distcode = Huffman::new();

        let nlen = self.bits(5)? as usize + 257;
        let ndist = self.bits(5)? as usize + 1;
        let ncode = self.bits(4)? as usize + 4;
        if nlen > MAXLCODES || ndist > MAXDCODES {
            return Err(InflateError::TooManyCodes);
        }
        for &slot in &ORDER[..ncode] {
            lengths[slot] = self.bits(3)? as u16;
        }
        for &slot in &ORDER[ncode..] {
            lengths[slot] = 0;
        }
        if construct(&mut lencode, &lengths[..19]) != 0 {
            return Err(InflateError::IncompleteCodeLengthCodes);
        }

        let mut index = 0;
        while index < nlen + ndist {
            let symbol = self.decode(&lencode)?;
            if symbol < 16 {
                lengths[index] = symbol;
                index += 1;
            } else {
                let mut len = 0;
                let repeat = if symbol == 16 {
                    if index == 0 {
                        return Err(InflateError::RepeatWithoutLength);
                    }
                    len = lengths[index - 1];
                    3 + self.bits(2)? as usize
                } else if symbol == 17 {
                    3 + self.bits(3)? as usize
                } else {
                    11 + self.bits(7)? as usize
                };
                if index + repeat > nlen + ndist {
                    return Err(InflateError::TooManyLengths);
                }
                for slot in &mut lengths[index..index + repeat] {
                    *slot = len;
                }
                index += repeat;
            }
        }
        if lengths[256] == 0 {
            return Err(InflateError::MissingEndOfBlock);
        }
        let err = construct(&mut lencode, &lengths[..nlen]);
        if err != 0 && (err < 0 || nlen != usize::from(lencode.count[0] + lencode.count[1])) {
            return Err(InflateError::InvalidLiteralLengths);
        }
        let err = construct(&mut distcode, &lengths[nlen..nlen + ndist]);
        if err != 0 && (err < 0 || ndist != usize::from(distcode.count[0] + distcode.count[1])) {
            return Err(InflateError::InvalidDistanceLengths);
        }
        self.codes(&lencode, &distcode)
    }
}

/// Строит таблицы по длинам кодов. 0 — полный набор, < 0 — переподписанный, > 0 — неполный.
/// Как и в оригинале, длины обязаны быть в 0..=MAXBITS (это гарантируют вызывающие).
fn construct(h: &mut Huffman, length: &[u16]) -> i32 {
    h.count = [0; MAXBITS + 1];
    for &len in length {
        h.count[usize::from(len)] += 1;
    }
    if usize::from(h.count[0]) == length.len() {
        return 0;
    }
    let mut left: i32 = 1;
    for len in 1..=MAXBITS {
        left <<= 1;
        left -= i32::from(h.count[len]);
        if left < 0 {
            return left;
        }
    }
    let mut offs = [0u16; MAXBITS + 1];
    for len in 1..MAXBITS {
        offs[len + 1] = offs[len] + h.count[len];
    }
    for (symbol, &len) in length.iter().enumerate() {
        if len != 0 {
            h.symbol[usize::from(offs[usize::from(len)])] = symbol as u16;
            offs[usize::from(len)] += 1;
        }
    }
    left
}

fn fixed_tables() -> &'static (Huffman, Huffman) {
    static TABLES: OnceLock<(Huffman, Huffman)> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut lengths = [0u16; FIXLCODES];
        for (symbol, slot) in lengths.iter_mut().enumerate() {
            *slot = match symbol {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let mut lencode = Huffman::new();
        construct(&mut lencode, &lengths);
        let mut distcode = Huffman::new();
        construct(&mut distcode, &[5u16; MAXDCODES]);
        (lencode, distcode)
    })
}

/// Распаковывает поток deflate. Выход не больше `max_out` байт — иначе `OutputLimit`
/// (распаковка останавливается на потолке, а не после него). Время — O(вход + выход).
pub fn inflate(input: &[u8], max_out: usize) -> Result<Inflated, InflateError> {
    let mut s = State {
        input,
        incnt: 0,
        bitbuf: 0,
        bitcnt: 0,
        out: Vec::new(),
        max_out,
    };
    let mut blocks = BlockStats::default();
    loop {
        let last = s.bits(1)?;
        match s.bits(2)? {
            0 => {
                blocks.stored += 1;
                s.stored()?;
            }
            1 => {
                blocks.fixed += 1;
                s.fixed()?;
            }
            2 => {
                blocks.dynamic += 1;
                s.dynamic()?;
            }
            _ => return Err(InflateError::InvalidBlockType),
        }
        if last == 1 {
            break;
        }
    }
    Ok(Inflated {
        consumed: s.incnt,
        data: s.out,
        blocks,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Писатель битов для ручной сборки блоков (младший бит первым, как в deflate).
    pub(crate) struct BitWriter {
        pub bytes: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl BitWriter {
        pub fn new() -> BitWriter {
            BitWriter {
                bytes: Vec::new(),
                acc: 0,
                n: 0,
            }
        }

        pub fn bits(&mut self, value: u32, count: u32) {
            for i in 0..count {
                self.acc |= ((value >> i) & 1) << self.n;
                self.n += 1;
                if self.n == 8 {
                    self.bytes.push(self.acc as u8);
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }

        /// Код Хаффмана пишется старшим битом вперёд.
        pub fn code(&mut self, code: u32, len: u32) {
            for i in (0..len).rev() {
                self.bits((code >> i) & 1, 1);
            }
        }

        pub fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.bytes.push(self.acc as u8);
            }
            self.bytes
        }

        /// Фиксированный код литерала/длины (RFC 1951, 3.2.6).
        pub fn fixed_symbol(&mut self, symbol: u32) {
            match symbol {
                0..=143 => self.code(0x30 + symbol, 8),
                144..=255 => self.code(0x190 + symbol - 144, 9),
                256..=279 => self.code(symbol - 256, 7),
                _ => self.code(0xc0 + symbol - 280, 8),
            }
        }
    }

    /// Фиксированный блок: литералы, затем пары (длина 3..=10 → символ 257..=264, расстояние 1..=4).
    pub(crate) fn fixed_block(literals: &[u8], copies: &[(u32, u32)], last: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bits(u32::from(last), 1);
        w.bits(1, 2);
        for &b in literals {
            w.fixed_symbol(u32::from(b));
        }
        for &(len, dist) in copies {
            assert!((3..=10).contains(&len) && (1..=4).contains(&dist));
            w.fixed_symbol(257 + len - 3);
            w.code(dist - 1, 5);
        }
        w.fixed_symbol(256);
        w.finish()
    }

    /// Фиксированный блок «бомба»: один литерал и `n` копий длиной 258 с расстоянием 1.
    pub(crate) fn fixed_bomb(n: usize) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bits(1, 1);
        w.bits(1, 2);
        w.fixed_symbol(u32::from(b'A'));
        for _ in 0..n {
            w.fixed_symbol(285);
            w.code(0, 5);
        }
        w.fixed_symbol(256);
        w.finish()
    }

    fn stored_block(data: &[u8], last: bool) -> Vec<u8> {
        let len = data.len() as u16;
        let mut out = vec![u8::from(last)];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn stored_blocks() {
        assert_eq!(inflate(&stored_block(b"", true), 10).unwrap().data, b"");
        let mut two = stored_block(b"Hello, ", false);
        two.extend(stored_block(b"world", true));
        let out = inflate(&two, 100).unwrap();
        assert_eq!(out.data, b"Hello, world");
        assert_eq!(out.blocks.stored, 2);
        assert_eq!(out.consumed, two.len());
    }

    #[test]
    fn fixed_block_literals_and_overlapping_copy() {
        // "abc" + копия длины 9 с расстояния 3 → "abcabcabcabc" (перекрытие len > dist).
        let data = fixed_block(b"abc", &[(9, 3)], true);
        let out = inflate(&data, 100).unwrap();
        assert_eq!(out.data, b"abcabcabcabc");
        assert_eq!(out.blocks.fixed, 1);
        // Пустой фиксированный блок (только EOB) — 10 бит: 0x03 0x00.
        assert_eq!(inflate(&[0x03, 0x00], 10).unwrap().data, b"");
    }

    #[test]
    fn fixed_high_literals_use_nine_bit_codes() {
        let bytes: Vec<u8> = (0..=255).collect();
        let out = inflate(&fixed_block(&bytes, &[], true), 300).unwrap();
        assert_eq!(out.data, bytes);
    }

    /// Ручной динамический блок: коды длин заданы явно, всё по RFC 1951 3.2.7.
    /// Алфавит: 'a', 'b', EOB (256) по 2 бита (а 4-й код — 'c'); расстояния не используются (1 код длины 1).
    fn hand_dynamic() -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bits(1, 1); // BFINAL
        w.bits(2, 2); // BTYPE = dynamic
        w.bits(0, 5); // HLIT = 257 кодов
        w.bits(0, 5); // HDIST = 1 код
        w.bits(15, 4); // HCLEN = 19 длин кодов длин
        // Коды длин кодов: используем символы 0 (длина 0), 2 (длина 2), 1 (для distance),
        // 18 (повтор нулей 11..138). Даём им длины 2: {0, 1, 2, 18} — полный набор из 4 кодов.
        const ORDER: [usize; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let mut cl = [0u32; 19];
        cl[0] = 2;
        cl[1] = 2;
        cl[2] = 2;
        cl[18] = 2;
        for &slot in &ORDER {
            w.bits(cl[slot], 3);
        }
        // Канонические коды для символов {0,1,2,18} длины 2: 0→00, 1→01, 2→10, 18→11.
        let sym = |w: &mut BitWriter, s: u32| match s {
            0 => w.code(0, 2),
            1 => w.code(1, 2),
            2 => w.code(2, 2),
            _ => w.code(3, 2),
        };
        // Длины литералов: 0..96 → 0, 'a'(97) 'b'(98) 'c'(99) → 2, 100..255 → 0, 256 → 2.
        let zeros = |w: &mut BitWriter, mut n: u32| {
            while n >= 11 {
                let run = n.min(138);
                sym(w, 18);
                w.bits(run - 11, 7);
                n -= run;
            }
            for _ in 0..n {
                sym(w, 0);
            }
        };
        zeros(&mut w, 97);
        sym(&mut w, 2);
        sym(&mut w, 2);
        sym(&mut w, 2);
        zeros(&mut w, 156);
        sym(&mut w, 2); // EOB
        sym(&mut w, 1); // единственный код расстояния длины 1
        // Литералы: коды длины 2 по порядку символов: a=00, b=01, c=10, EOB=11.
        for &c in b"abcab" {
            w.code(u32::from(c - b'a'), 2);
        }
        w.code(3, 2);
        w.finish()
    }

    #[test]
    fn hand_built_dynamic_block() {
        let out = inflate(&hand_dynamic(), 100).unwrap();
        assert_eq!(out.data, b"abcab");
        assert_eq!(out.blocks.dynamic, 1);
    }

    #[test]
    fn rfc_error_cases() {
        // Тип блока 3.
        assert_eq!(inflate(&[0x07], 10), Err(InflateError::InvalidBlockType));
        // Stored: дополнение не совпадает.
        assert_eq!(
            inflate(&[0x01, 0x05, 0x00, 0x00, 0x00], 10),
            Err(InflateError::StoredLengthMismatch)
        );
        // Stored: данных меньше заявленного.
        assert_eq!(
            inflate(&[0x01, 0x05, 0x00, 0xfa, 0xff, b'a'], 10),
            Err(InflateError::InputTruncated)
        );
        // Нет последнего блока.
        assert_eq!(
            inflate(&stored_block(b"x", false), 10),
            Err(InflateError::InputTruncated)
        );
        assert_eq!(inflate(&[], 10), Err(InflateError::InputTruncated));
        // Копия с расстояния дальше начала вывода.
        assert_eq!(
            inflate(&fixed_block(b"a", &[(3, 2)], true), 10),
            Err(InflateError::DistanceTooFar)
        );
        // Dynamic: HLIT = 30 → 287 кодов > 286.
        let mut w = BitWriter::new();
        w.bits(1, 1);
        w.bits(2, 2);
        w.bits(30, 5);
        w.bits(0, 5);
        w.bits(0, 4);
        assert_eq!(inflate(&w.finish(), 10), Err(InflateError::TooManyCodes));
        // Dynamic: неполный набор длин кодов длин (один код длины 1).
        let mut w = BitWriter::new();
        w.bits(1, 1);
        w.bits(2, 2);
        w.bits(0, 5);
        w.bits(0, 5);
        w.bits(0, 4);
        for len in [1, 0, 0, 0] {
            w.bits(len, 3);
        }
        assert_eq!(
            inflate(&w.finish(), 10),
            Err(InflateError::IncompleteCodeLengthCodes)
        );
    }

    #[test]
    fn output_limit_stops_a_bomb_at_the_cap() {
        // ~6.5 КБ входа (13 бит на копию 258 байт) → ~1 МБ выхода. Потолок 64 КБ — стоп на нём.
        let bomb = fixed_bomb(4000);
        assert!(bomb.len() < 7000);
        assert_eq!(inflate(&bomb, 64 * 1024), Err(InflateError::OutputLimit));
        let out = inflate(&bomb, 2 * 1024 * 1024).unwrap();
        assert_eq!(out.data.len(), 1 + 4000 * 258);
        assert!(out.data.iter().all(|&b| b == b'A'));
    }

    /// Детерминированный xorshift — свой, без зависимостей.
    pub(crate) struct Rng(pub u64);

    impl Rng {
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    #[test]
    fn mutated_streams_never_panic_or_hang() {
        let seeds = [
            fixed_block(b"jetscan mutation seed", &[(10, 4), (5, 1)], true),
            hand_dynamic(),
            stored_block(b"stored seed data", true),
            fixed_bomb(50),
        ];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let started = std::time::Instant::now();
        for i in 0..20_000 {
            let mut data = seeds[i % seeds.len()].clone();
            for _ in 0..=rng.below(4) {
                let at = rng.below(data.len());
                data[at] ^= 1 << rng.below(8);
            }
            if rng.below(4) == 0 {
                data.truncate(rng.below(data.len() + 1));
            }
            if let Ok(out) = inflate(&data, 1 << 20) {
                assert!(out.data.len() <= 1 << 20);
                assert!(out.consumed <= data.len());
            }
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
    }
}
