//! Лицензия Teams: подписанный ключ, проверяется локально — без сети, без
//! регистрации, без «звонка домой». Бесплатная часть ключа не требует никогда.
//!
//! Ключ: `JETSCAN-1.<base64url(текст)>.<base64url(подпись Ed25519)>`. Текст —
//! строки `поле: значение` (организация, тариф, места, даты). Подпись проверяется
//! ДО разбора: разбираем только то, что подписал доверенный издатель. Каждый
//! издатель хранит свой приватный ключ; в сборке — только публичные ключи.
//!
//! Известные пределы модели на доверии (осознанно): перевод часов назад продлевает
//! ключ; досрочно отозвать ключ нельзя (поэтому ключи — на год, не навсегда);
//! код открыт, проверку можно вырезать. Компании платят за законную лицензию и
//! поддержку, а не потому, что их заставили.

pub mod ed25519;

use std::path::PathBuf;

/// Публичные ключи доверенных издателей. Первый — ключ владельца (2026-10-29,
/// `license-keygen init`; hex d0e1c116…c42699c1), второй — сайта, который выпускает
/// ключи после оплаты (2026-11-01; hex 364e67ab…348be418). Пустой список не принимает
/// НИ ОДНОЙ подписи (ошибка закрывает, а не открывает).
const PUBLIC_KEYS: &[[u8; 32]] = &[
    [
        0xd0, 0xe1, 0xc1, 0x16, 0xfe, 0xb1, 0x53, 0x4d, 0x9d, 0x75, 0xf7, 0xa7, 0x01, 0xc1, 0x52,
        0x2c, 0x25, 0x9d, 0xa6, 0xb1, 0xfd, 0xf2, 0x22, 0x50, 0x14, 0x09, 0x30, 0x9a, 0xc4, 0x26,
        0x99, 0xc1,
    ],
    [
        0x36, 0x4e, 0x67, 0xab, 0x03, 0x3b, 0xc7, 0x55, 0x04, 0x64, 0x34, 0x5b, 0x41, 0x09, 0xec,
        0x6f, 0x83, 0xee, 0x14, 0x0a, 0x5d, 0xc4, 0x85, 0x04, 0xfc, 0x3b, 0x48, 0x9a, 0x34, 0x8b,
        0xe4, 0x18,
    ],
];

const PREFIX: &str = "JETSCAN-1.";
const HEADER: &str = "jetscan-license 1";
/// Сколько дней после срока платные функции ещё работают (оплата могла задержаться).
pub const GRACE_DAYS: i64 = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct License {
    pub id: String,
    pub org: String,
    pub plan: String,
    pub seats: u32,
    /// Дни с 1970-01-01.
    pub issued: i64,
    pub expires: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Ключа нет: бесплатная версия.
    Free,
    Active {
        license: License,
        days_left: i64,
    },
    /// Срок вышел, но идут льготные дни: платное ещё работает, с предупреждением.
    Grace {
        license: License,
        days_over: i64,
    },
    Expired {
        license: License,
        days_over: i64,
    },
    /// Ключ есть, но не принят (повреждён, чужой, не та сборка).
    Invalid(String),
}

impl Status {
    /// Включены ли платные функции.
    pub fn paid(&self) -> bool {
        matches!(self, Status::Active { .. } | Status::Grace { .. })
    }
}

// --- base64url без `=` (RFC 4648 §5) ---

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = B64.iter().position(|b| b == c)? as u32;
            n |= v << (18 - 6 * i);
        }
        let bytes = chunk.len() - 1;
        for i in 0..bytes {
            out.push((n >> (16 - 8 * i)) as u8);
        }
        // Неиспользуемые младшие биты должны быть нулями: одна строка — один ключ.
        if n & ((1 << (8 * (3 - bytes))) - 1) != 0 {
            return None;
        }
    }
    Some(out)
}

// --- даты (гражданский календарь, алгоритм Говарда Хиннанта) ---

pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

pub fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn parse_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        s.get(r)
            .filter(|p| p.bytes().all(|c| c.is_ascii_digit()))?
            .parse()
            .ok()
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let days = days_from_civil(y, m, d);
    // Отвергаем 2027-02-30 и т.п.: дата должна пережить обратное преобразование.
    (civil_from_days(days) == (y, m, d)).then_some(days)
}

/// Сегодня по системным часам (дни с 1970-01-01, UTC).
pub fn today() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs / 86_400) as i64
}

// --- ключ ---

/// Текст лицензии в каноническом виде (то, что подписывается).
pub fn payload(l: &License) -> String {
    format!(
        "{HEADER}\nid: {}\norg: {}\nplan: {}\nseats: {}\nissued: {}\nexpires: {}\n",
        l.id,
        l.org,
        l.plan,
        l.seats,
        format_date(l.issued),
        format_date(l.expires)
    )
}

/// Ключ из лицензии и 32-байтного секрета владельца.
pub fn issue(l: &License, seed: &[u8; 32]) -> String {
    let text = payload(l);
    let sig = ed25519::sign(seed, text.as_bytes());
    format!(
        "{PREFIX}{}.{}",
        b64_encode(text.as_bytes()),
        b64_encode(&sig)
    )
}

fn parse_payload(text: &str) -> Result<License, String> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err("unknown license format".into());
    }
    let mut fields = std::collections::BTreeMap::new();
    for line in lines {
        let (k, v) = line.split_once(": ").ok_or("malformed license")?;
        if fields.insert(k, v).is_some() {
            return Err("malformed license".into());
        }
    }
    let field = |k: &str| {
        fields
            .get(k)
            .copied()
            .ok_or(format!("license has no '{k}'"))
    };
    let clean = |v: &str| v.chars().all(|c| !c.is_control());
    let (id, org, plan) = (field("id")?, field("org")?, field("plan")?);
    if ![id, org, plan].iter().all(|v| clean(v) && !v.is_empty()) {
        return Err("malformed license".into());
    }
    let date = |k: &str| parse_date(field(k)?).ok_or(format!("license has a bad '{k}' date"));
    Ok(License {
        id: id.into(),
        org: org.into(),
        plan: plan.into(),
        seats: field("seats")?
            .parse()
            .map_err(|_| "license has a bad 'seats'")?,
        issued: date("issued")?,
        expires: date("expires")?,
    })
}

/// Проверка ключа любым из доверенных публичных ключей `keys` на дату `today`.
pub fn check(key: &str, keys: &[[u8; 32]], today: i64) -> Status {
    if keys.is_empty() {
        return Status::Invalid("this jetscan build has no license key built in".into());
    }
    let bad = || Status::Invalid("the license key is damaged or not a jetscan key".into());
    let Some((text, sig)) = key
        .trim()
        .strip_prefix(PREFIX)
        .and_then(|r| r.split_once('.'))
    else {
        return bad();
    };
    let (Some(text), Some(sig)) = (b64_decode(text), b64_decode(sig)) else {
        return bad();
    };
    let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
        return bad();
    };
    if !keys.iter().any(|pk| ed25519::verify(pk, &text, &sig)) {
        return Status::Invalid("the license key signature is not valid".into());
    }
    let license = match String::from_utf8(text)
        .map_err(|_| String::new())
        .and_then(|t| parse_payload(&t))
    {
        Ok(l) => l,
        Err(e) if e.is_empty() => return bad(),
        Err(e) => return Status::Invalid(e),
    };
    if license.plan != "teams" {
        return Status::Invalid(format!(
            "this jetscan version does not know the '{}' plan — update jetscan",
            crate::ui::sanitize_line(&license.plan)
        ));
    }
    let over = today - license.expires;
    if over <= 0 {
        Status::Active {
            days_left: -over,
            license,
        }
    } else if over <= GRACE_DAYS {
        Status::Grace {
            days_over: over,
            license,
        }
    } else {
        Status::Expired {
            days_over: over,
            license,
        }
    }
}

/// Файл ключа: `JETSCAN_HOME/license` или `~/.jetscan/license`.
pub fn license_file() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("JETSCAN_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h).join("license"));
    }
    crate::secrets::machine::home_dir().map(|h| h.join(".jetscan").join("license"))
}

/// Текущий статус: `JETSCAN_LICENSE` (для CI — секрет), иначе файл ключа.
pub fn load() -> Status {
    let key = std::env::var("JETSCAN_LICENSE")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .or_else(|| {
            license_file()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .filter(|k| !k.trim().is_empty())
        });
    match key {
        None => Status::Free,
        Some(k) => check(&k, PUBLIC_KEYS, today()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42; 32];

    fn license(expires: &str) -> License {
        License {
            id: "JS-0001".into(),
            org: "Acme Ltd".into(),
            plan: "teams".into(),
            seats: 25,
            issued: parse_date("2026-10-29").unwrap(),
            expires: parse_date(expires).unwrap(),
        }
    }

    #[test]
    fn base64url_round_trips_and_rejects_junk() {
        for len in 0..70 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = b64_encode(&data);
            assert!(!text.contains(['=', '+', '/']));
            assert_eq!(b64_decode(&text), Some(data));
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_encode(b"Ma"), "TWE");
        for junk in ["T", "TWE=", "TW+u", "TWF", "TWF/"] {
            assert_ne!(b64_decode(junk), Some(b"Man".to_vec()), "{junk}");
        }
        // Unused low bits must be zero: "TWF" and "TWG" would both mean "Ma".
        assert_eq!(b64_decode("TWE"), Some(b"Ma".to_vec()));
        assert_eq!(b64_decode("TWF"), None);
    }

    #[test]
    fn dates_round_trip_and_reject_impossible_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(parse_date("2000-03-01"), Some(11017));
        for days in [-1, 0, 59, 60, 11016, 20_000, 30_000, 60_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
            assert_eq!(parse_date(&format_date(days)), Some(days));
        }
        assert_eq!(
            parse_date("2028-02-29").map(format_date).as_deref(),
            Some("2028-02-29")
        );
        for bad in [
            "2027-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-1-01",
            "26-10-29",
            "2026/10/29",
            "２０２６-10-29",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_signed_key_is_active_then_in_grace_then_expired() {
        let pk = ed25519::public_key(&SEED);
        let key = issue(&license("2027-10-29"), &SEED);
        assert!(key.starts_with(PREFIX));
        let day = |s| parse_date(s).unwrap();
        let active = check(&key, &[pk], day("2027-10-29"));
        assert_eq!(
            active,
            Status::Active {
                license: license("2027-10-29"),
                days_left: 0
            }
        );
        assert!(active.paid());
        // Whitespace around a pasted key is fine.
        assert!(check(&format!("  {key}\r\n"), &[pk], day("2027-01-01")).paid());
        let grace = check(&key, &[pk], day("2027-11-12"));
        assert!(matches!(grace, Status::Grace { days_over: 14, .. }));
        assert!(grace.paid());
        let expired = check(&key, &[pk], day("2027-11-13"));
        assert!(matches!(expired, Status::Expired { days_over: 15, .. }));
        assert!(!expired.paid());
        assert!(!Status::Free.paid());
    }

    #[test]
    fn forged_edited_or_foreign_keys_are_rejected() {
        let pk = ed25519::public_key(&SEED);
        let today = parse_date("2027-01-01").unwrap();
        let key = issue(&license("2027-10-29"), &SEED);
        // Someone else's signing key.
        let foreign = issue(&license("2027-10-29"), &[7; 32]);
        assert!(matches!(check(&foreign, &[pk], today), Status::Invalid(_)));
        // Extend the date inside a valid key: the signature no longer matches.
        let (text, sig) = key[PREFIX.len()..].split_once('.').unwrap();
        let edited = String::from_utf8(b64_decode(text).unwrap())
            .unwrap()
            .replace("2027-10-29", "2099-10-29");
        let edited = format!("{PREFIX}{}.{sig}", b64_encode(edited.as_bytes()));
        assert_eq!(
            check(&edited, &[pk], today),
            Status::Invalid("the license key signature is not valid".into())
        );
        for junk in [
            "",
            "JETSCAN-1.",
            "JETSCAN-1.abc",
            "JETSCAN-1.a.b",
            "JETSCAN-2.x.y",
            &key[..key.len() - 2],
        ] {
            assert!(
                matches!(check(junk, &[pk], today), Status::Invalid(_)),
                "{junk}"
            );
        }
        // A build without the owner's public key accepts nothing.
        assert!(matches!(check(&key, &[], today), Status::Invalid(_)));
    }

    #[test]
    fn accepts_any_trusted_signer_but_never_an_empty_or_foreign_list() {
        let first = ed25519::public_key(&SEED);
        let second_seed = [17; 32];
        let second = ed25519::public_key(&second_seed);
        let today = parse_date("2027-01-01").unwrap();
        let key = issue(&license("2027-10-29"), &second_seed);
        assert!(check(&key, &[first, second], today).paid());
        assert!(check(&key, &[second, first], today).paid());
        assert!(matches!(check(&key, &[first], today), Status::Invalid(_)));
        assert!(matches!(check(&key, &[], today), Status::Invalid(_)));
        let foreign = issue(&license("2027-10-29"), &[9; 32]);
        assert!(matches!(
            check(&foreign, &[first, second], today),
            Status::Invalid(_)
        ));
        // Unsigned malformed content must fail signature verification before
        // producing any parsing error, irrespective of how many keys are tried.
        let text = b"malformed and unsigned license";
        let signature = ed25519::sign(&[9; 32], text);
        let foreign = format!("{PREFIX}{}.{}", b64_encode(text), b64_encode(&signature));
        assert_eq!(
            check(&foreign, &[first, second], today),
            Status::Invalid("the license key signature is not valid".into())
        );
    }

    #[test]
    fn signed_but_unknown_content_is_still_rejected() {
        let pk = ed25519::public_key(&SEED);
        let today = parse_date("2027-01-01").unwrap();
        let sign = |text: &str| {
            let sig = ed25519::sign(&SEED, text.as_bytes());
            format!(
                "{PREFIX}{}.{}",
                b64_encode(text.as_bytes()),
                b64_encode(&sig)
            )
        };
        let good = payload(&license("2027-10-29"));
        assert!(check(&sign(&good), &[pk], today).paid());
        for text in [
            good.replace("plan: teams", "plan: enterprise"),
            good.replace("seats: 25", "seats: many"),
            good.replace("expires: 2027-10-29", "expires: 2027-02-30"),
            good.replace("org: Acme Ltd\n", ""),
            good.replace("org: Acme Ltd", "org: Acme\u{1b}[31m"),
            format!("{good}org: Other\n"),
            good.replace(HEADER, "jetscan-license 2"),
        ] {
            assert!(!check(&sign(&text), &[pk], today).paid(), "{text}");
        }
    }
}
