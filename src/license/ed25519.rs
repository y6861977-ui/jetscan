//! Ed25519 (RFC 8032) — подпись лицензий, без крейтов. Перенос TweetNaCl
//! (публичное достояние): поле — 16 «конечностей» по 16 бит в i64.
//!
//! Проверка подписи — у каждого пользователя; подпись — только у владельца
//! (`jetscan-keygen`), поэтому скорость и постоянное время здесь не цель.
//! В отличие от TweetNaCl, подпись с `S >= L` отвергается (иначе одну подпись
//! можно переписать в другую, тоже «верную»). Константы вычислены точной
//! арифметикой: d = -121665/121666, I = sqrt(-1), базовая точка y = 4/5.

type Gf = [i64; 16];

const GF0: Gf = [0; 16];
const GF1: Gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const D: Gf = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
];
const D2: Gf = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
];
const X: Gf = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
];
const Y: Gf = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
];
const I: Gf = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];
/// Порядок группы L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn car(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            // 2^256 = 38 (mod 2^255 - 19).
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

fn sel(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(n: &Gf) -> [u8; 32] {
    let mut t = *n;
    car(&mut t);
    car(&mut t);
    car(&mut t);
    for _ in 0..2 {
        let mut m = GF0;
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
    o
}

fn neq(a: &Gf, b: &Gf) -> bool {
    pack25519(a) != pack25519(b)
}

fn par(a: &Gf) -> u8 {
    pack25519(a)[0] & 1
}

fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o = GF0;
    for i in 0..16 {
        o[i] = n[2 * i] as i64 + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

fn add_gf(a: &Gf, b: &Gf) -> Gf {
    std::array::from_fn(|i| a[i] + b[i])
}

fn sub_gf(a: &Gf, b: &Gf) -> Gf {
    std::array::from_fn(|i| a[i] - b[i])
}

fn mul(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = GF0;
    o.copy_from_slice(&t[..16]);
    car(&mut o);
    car(&mut o);
    o
}

fn sq(a: &Gf) -> Gf {
    mul(a, a)
}

fn inv(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = sq(&c);
        if a != 2 && a != 4 {
            c = mul(&c, i);
        }
    }
    c
}

fn pow2523(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=250).rev() {
        c = sq(&c);
        if a != 1 {
            c = mul(&c, i);
        }
    }
    c
}

/// Точка в расширенных координатах (X, Y, Z, T).
type Point = [Gf; 4];

fn add(p: &mut Point, q: &Point) {
    let a = mul(&sub_gf(&p[1], &p[0]), &sub_gf(&q[1], &q[0]));
    let b = mul(&add_gf(&p[0], &p[1]), &add_gf(&q[0], &q[1]));
    let c = mul(&mul(&p[3], &q[3]), &D2);
    let d = mul(&p[2], &q[2]);
    let d = add_gf(&d, &d);
    let e = sub_gf(&b, &a);
    let f = sub_gf(&d, &c);
    let g = add_gf(&d, &c);
    let h = add_gf(&b, &a);
    p[0] = mul(&e, &f);
    p[1] = mul(&h, &g);
    p[2] = mul(&g, &f);
    p[3] = mul(&e, &h);
}

fn cswap(p: &mut Point, q: &mut Point, b: i64) {
    for i in 0..4 {
        sel(&mut p[i], &mut q[i], b);
    }
}

fn pack(p: &Point) -> [u8; 32] {
    let zi = inv(&p[2]);
    let tx = mul(&p[0], &zi);
    let ty = mul(&p[1], &zi);
    let mut r = pack25519(&ty);
    r[31] ^= par(&tx) << 7;
    r
}

fn scalarmult(q: &mut Point, s: &[u8; 32]) -> Point {
    let mut p: Point = [GF0, GF1, GF1, GF0];
    for i in (0..256).rev() {
        let b = ((s[i / 8] >> (i & 7)) & 1) as i64;
        cswap(&mut p, q, b);
        add(q, &p);
        let doubled = p;
        add(&mut p, &doubled);
        cswap(&mut p, q, b);
    }
    p
}

fn scalarbase(s: &[u8; 32]) -> Point {
    let mut q: Point = [X, Y, GF1, mul(&X, &Y)];
    scalarmult(&mut q, s)
}

fn mod_l(x: &mut [i64; 64]) -> [u8; 32] {
    for i in (32..64).rev() {
        let mut carry = 0;
        let mut j = i - 32;
        while j < i - 12 {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
            j += 1;
        }
        x[j] += carry;
        x[i] = 0;
    }
    let mut carry = 0;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    let mut r = [0u8; 32];
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
    r
}

fn reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut x: [i64; 64] = std::array::from_fn(|i| h[i] as i64);
    mod_l(&mut x)
}

/// −A по сжатой точке A, или `None`, если это не точка кривой.
fn unpack_neg(p: &[u8; 32]) -> Option<Point> {
    let mut r: Point = [GF0, unpack25519(p), GF1, GF0];
    let num = sq(&r[1]);
    let den = mul(&num, &D);
    let num = sub_gf(&num, &r[2]);
    let den = add_gf(&r[2], &den);
    let den2 = sq(&den);
    let den4 = sq(&den2);
    let den6 = mul(&den4, &den2);
    let mut t = mul(&mul(&den6, &num), &den);
    t = pow2523(&t);
    t = mul(&mul(&mul(&t, &num), &den), &den);
    r[0] = mul(&t, &den);
    if neq(&mul(&sq(&r[0]), &den), &num) {
        r[0] = mul(&r[0], &I);
    }
    if neq(&mul(&sq(&r[0]), &den), &num) {
        return None;
    }
    if par(&r[0]) == p[31] >> 7 {
        r[0] = sub_gf(&GF0, &r[0]);
    }
    r[3] = mul(&r[0], &r[1]);
    Some(r)
}

/// S < L: только каноническая запись скаляра (little-endian сравнение).
fn canonical(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        let (a, b) = (s[i] as i64, L[i]);
        if a != b {
            return a < b;
        }
    }
    false
}

fn hash(parts: &[&[u8]]) -> [u8; 64] {
    crate::hash::sha512(&parts.concat())
}

fn expand(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let d = crate::hash::sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&d[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&d[32..]);
    (a, prefix)
}

/// Публичный ключ по 32-байтному секрету (seed).
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    pack(&scalarbase(&expand(seed).0))
}

/// Подпись (только для `jetscan-keygen` у владельца).
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let (a, prefix) = expand(seed);
    let pk = pack(&scalarbase(&a));
    let r = reduce(&hash(&[&prefix, message]));
    let big_r = pack(&scalarbase(&r));
    let h = reduce(&hash(&[&big_r, &pk, message]));
    let mut x = [0i64; 64];
    for i in 0..32 {
        x[i] = r[i] as i64;
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += h[i] as i64 * a[j] as i64;
        }
    }
    let s = mod_l(&mut x);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Верна ли подпись `sig` сообщения `message` ключом `pk`.
pub fn verify(pk: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if !canonical(&s) {
        return false;
    }
    let Some(mut q) = unpack_neg(pk) else {
        return false;
    };
    let h = reduce(&hash(&[&sig[..32], pk, message]));
    let mut p = scalarmult(&mut q, &h);
    let sb = scalarbase(&s);
    add(&mut p, &sb);
    pack(&p)[..] == sig[..32]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    // (seed, message, public key, signature). The first two are RFC 8032 §7.1
    // tests 1–2; all four were produced by an independent implementation
    // (node:crypto), not typed from memory.
    type Vector = ([u8; 32], Vec<u8>, [u8; 32], [u8; 64]);

    fn vectors() -> Vec<Vector> {
        [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                Vec::new(),
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                vec![0x72],
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "e3407b9d3d82d7539b3322282c232e29a873d2a382faa8135d9d7a7e7de6b54b",
                b"jetscan license v1\norg: Acme\n".to_vec(),
                "2896f1f2373518d0dfb81819467105b68442d39cfb52eea1780303e465bd8ea8",
                "2688f9cca6e745238f85e0d1c1f7cd0feb519885a7166a000092e0a4839ba1f4cce9a2a75d3ed3f732faa84d7e573f9f1ebb2539f5d7d36ebab15f71cfaae804",
            ),
            (
                "d678432891f635fe3279c953901bb25f112cf80393331ddb79339f84acd9f82b",
                vec![7; 300],
                "93f9a1e553daf261d00b55a3c8be50e8a689aa89a619f81d58defc7432239f4d",
                "442d20e36c551cf411117f643a52859365e6e7cc12b100716fb6b365aff32a31ff22b78d71481361786a7e00d1d4b1c1821b7a0de05991e96988b76adb04400f",
            ),
        ]
        .into_iter()
        .map(|(s, m, p, g)| (bytes(s), m, bytes(p), bytes(g)))
        .collect()
    }

    #[test]
    fn matches_reference_keys_and_signatures() {
        for (seed, message, pk, sig) in vectors() {
            assert_eq!(public_key(&seed), pk);
            assert_eq!(sign(&seed, &message), sig);
            assert!(verify(&pk, &message, &sig));
        }
    }

    #[test]
    fn rejects_any_change_to_message_signature_or_key() {
        let (seed, message, pk, sig) = vectors().swap_remove(2);
        let mut other = message.clone();
        other[19] ^= 1;
        assert!(!verify(&pk, &other, &sig));
        assert!(!verify(&pk, &[message.as_slice(), b"x"].concat(), &sig));
        for i in [0, 31, 32, 63] {
            let mut bad = sig;
            bad[i] ^= 0x01;
            assert!(!verify(&pk, &message, &bad), "byte {i}");
        }
        let (_, _, other_pk, _) = vectors().swap_remove(0);
        assert!(!verify(&other_pk, &message, &sig));
        assert_eq!(sign(&seed, &message), sig);
    }

    #[test]
    fn rejects_non_canonical_s_and_points_off_the_curve() {
        let (_, message, pk, sig) = vectors().swap_remove(1);
        // S + L is the same scalar mod L: valid math, but a second encoding.
        let mut forged = sig;
        let mut carry = 0;
        for i in 0..32 {
            let v = forged[32 + i] as i64 + L[i] + carry;
            forged[32 + i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!verify(&pk, &message, &forged));
        assert!(!verify(&pk, &message, &[0xff; 64]));
        // Some y has no x on the curve; such a "key" must fail, not panic.
        let off_curve = (0..=255u8)
            .map(|b| [b; 32])
            .find(|p| unpack_neg(p).is_none());
        let off_curve = off_curve.expect("an encoding off the curve");
        assert!(!verify(&off_curve, &message, &sig));
    }
}
