//! Чтение little-endian полей с проверкой границ. Ни одно чтение не паникует:
//! выход за край — `None`, вся арифметика смещений — `checked_*`.

pub fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let b = data.get(offset..end)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let b = data.get(offset..end)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn u8_at(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

/// `len` байт с `offset`.
pub fn slice_at(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(len)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_bounds() {
        let d = [1u8, 2, 3, 4, 5];
        assert_eq!(u16_at(&d, 0), Some(0x0201));
        assert_eq!(u32_at(&d, 1), Some(0x0504_0302));
        assert_eq!(u32_at(&d, 2), None);
        assert_eq!(u16_at(&d, usize::MAX), None);
        assert_eq!(slice_at(&d, 3, 2), Some(&d[3..5]));
        assert_eq!(slice_at(&d, 3, 3), None);
        assert_eq!(slice_at(&d, usize::MAX, 2), None);
        assert_eq!(u8_at(&d, 5), None);
    }
}
