//! Лицензии jetscan: подписанный ключ, проверяется локально — без сети, без
//! регистрации, без «звонка домой». Бесплатная часть ключа не требует никогда.
//!
//! Ключ: `JETSCAN-1.<base64url(текст)>.<base64url(подпись Ed25519)>`. Текст —
//! строки `поле: значение` (организация, тариф, места, даты). Подпись проверяется
//! ДО разбора: разбираем только то, что подписал доверенный издатель. Каждый
//! издатель хранит свой приватный ключ; в сборке — только публичные ключи.
//!
//! Тарифы (`plan:`), решение владельца 2026-11-16:
//! - `teams` — формат ключа не менялся ни на байт: старые ключи Teams проверяются
//!   как прежде. Teams = CI-отчёты (`--sarif`, `--sbom`, `--baseline`) И все
//!   Pro-сканы (тариф компании не слабее личного Pro). Льгота 14 дней.
//! - `pro` — личный Pro на год: все Pro-сканы, без CI-отчётов. Льгота 14 дней.
//! - `audit` — разовый аудит на 30 дней: все Pro-сканы. Без льготы.
//! - `trial` — пробный: одна область (`area:` web|apk|android|ios), `scans:` штук,
//!   короткий срок (сайт даёт 14 дней). Без льготы. Счётчик — локальный файл
//!   (`entitlement.rs`).
//!
//! Новые поля (`area`, `scans`, `features`) идут ПОСЛЕ старых строк и только у
//! новых тарифов; старый jetscan (≤ 0.3) их игнорирует и отвечает на незнакомый
//! тариф «update jetscan». Личных данных в ключе нет: `org` у Pro/аудита/пробного —
//! слово `personal`, почта в ключ не попадает никогда.
//!
//! Известные пределы модели на доверии (осознанно): перевод часов назад продлевает
//! ключ; досрочно отозвать ключ нельзя (поэтому ключи — на год, не навсегда);
//! код открыт, проверку можно вырезать. Компании платят за законную лицензию и
//! поддержку, а не потому, что их заставили.

pub mod ed25519;
mod entitlement;

pub use entitlement::{
    Entitlement, ProFeature, describe, entitlement, entitlement_for, entitlement_in,
    entitlement_of, print_status, record_trial_scan, record_trial_scan_in, trial_counter_file,
    trial_used, trial_used_for, trial_used_in,
};

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
/// Только у годовых тарифов (Teams, Pro); у аудита и пробного льготы нет.
pub const GRACE_DAYS: i64 = 14;
/// Предел `scans:` в ключе: защита от опечатки, не от издателя.
const MAX_SCANS: u32 = 1000;

/// Тариф ключа (`plan:`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    Teams,
    Pro,
    Audit,
    Trial,
}

impl Plan {
    pub const ALL: [Plan; 4] = [Plan::Teams, Plan::Pro, Plan::Audit, Plan::Trial];

    pub fn parse(s: &str) -> Option<Plan> {
        Plan::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// Как тариф записан в ключе.
    pub fn as_str(self) -> &'static str {
        match self {
            Plan::Teams => "teams",
            Plan::Pro => "pro",
            Plan::Audit => "audit",
            Plan::Trial => "trial",
        }
    }

    /// Как тариф называется людям.
    pub fn title(self) -> &'static str {
        match self {
            Plan::Teams => "jetscan Teams",
            Plan::Pro => "jetscan Pro",
            Plan::Audit => "jetscan one-time audit",
            Plan::Trial => "jetscan Pro trial",
        }
    }

    /// Льготные дни после срока: у годовых платных — 14, у разовых — ноль.
    pub fn grace_days(self) -> i64 {
        match self {
            Plan::Teams | Plan::Pro => GRACE_DAYS,
            Plan::Audit | Plan::Trial => 0,
        }
    }
}

/// Область пробного ключа (`area:`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    Web,
    Apk,
    Android,
    Ios,
}

impl Area {
    pub const ALL: [Area; 4] = [Area::Web, Area::Apk, Area::Android, Area::Ios];

    pub fn parse(s: &str) -> Option<Area> {
        Area::ALL.into_iter().find(|a| a.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Area::Web => "web",
            Area::Apk => "apk",
            Area::Android => "android",
            Area::Ios => "ios",
        }
    }
}

/// Поля ключа сверх старого формата Teams. У ключа Teams старого формата —
/// `plan: Teams`, остальное пусто.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub plan: Plan,
    /// Только у пробного (и там обязательно).
    pub area: Option<Area>,
    /// Сколько сканов даёт ключ. Только у пробного (и там обязательно).
    pub scans: Option<u32>,
    /// Необязательное СУЖЕНИЕ тарифа: если есть, работает только перечисленное
    /// (`web,apk,android,ios,url,ci`). Незнакомые слова пропускаются — сужение
    /// не может открыть то, чего тариф не даёт.
    pub features: Option<Vec<ProFeature>>,
}

impl Claims {
    pub fn plan(plan: Plan) -> Claims {
        Claims {
            plan,
            area: None,
            scans: None,
            features: None,
        }
    }

    pub fn trial(area: Area, scans: u32) -> Claims {
        Claims {
            area: Some(area),
            scans: Some(scans),
            ..Claims::plan(Plan::Trial)
        }
    }

    /// Согласованность полей. Те же правила при выпуске и при проверке.
    fn validate(&self) -> Result<(), String> {
        let trial = self.plan == Plan::Trial;
        if trial != self.area.is_some() || trial != self.scans.is_some() {
            return Err("malformed license".into());
        }
        if self.scans.is_some_and(|n| n == 0 || n > MAX_SCANS) {
            return Err("license has a bad 'scans'".into());
        }
        Ok(())
    }
}

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

/// Текст лицензии в каноническом виде (то, что подписывается): старый формат
/// Teams, байт в байт как до Pro. Новые поля добавляет `payload_with`.
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

/// Канонический текст с новыми полями — в фиксированном порядке ПОСЛЕ старых
/// строк (`area`, `scans`, `features`). У Teams без сужения — ровно `payload(l)`.
pub fn payload_with(l: &License, c: &Claims) -> String {
    let mut text = payload(l);
    if let Some(a) = c.area {
        text.push_str(&format!("area: {}\n", a.as_str()));
    }
    if let Some(n) = c.scans {
        text.push_str(&format!("scans: {n}\n"));
    }
    if let Some(f) = &c.features {
        let list: Vec<&str> = f.iter().map(|f| f.token()).collect();
        text.push_str(&format!("features: {}\n", list.join(",")));
    }
    text
}

fn sign_text(text: &str, seed: &[u8; 32]) -> String {
    let sig = ed25519::sign(seed, text.as_bytes());
    format!(
        "{PREFIX}{}.{}",
        b64_encode(text.as_bytes()),
        b64_encode(&sig)
    )
}

/// Ключ Teams старого формата из лицензии и 32-байтного секрета издателя.
pub fn issue(l: &License, seed: &[u8; 32]) -> String {
    sign_text(&payload(l), seed)
}

/// Ключ любого тарифа. Отказ — если поля не согласованы или текст не пережил бы
/// собственную проверку (перевод строки в организации и т.п.): битый ключ не
/// должен уйти покупателю.
pub fn issue_with(l: &License, c: &Claims, seed: &[u8; 32]) -> Result<String, String> {
    if l.plan != c.plan.as_str() {
        return Err(format!(
            "plan '{}' does not match the claims ({})",
            crate::ui::sanitize_line(&l.plan),
            c.plan.as_str()
        ));
    }
    c.validate()?;
    if l.expires < l.issued {
        return Err("the license expires before it is issued".into());
    }
    let text = payload_with(l, c);
    match parse_payload(&text) {
        Ok((back, claims)) if back == *l && claims == *c => Ok(sign_text(&text, seed)),
        Ok(_) => Err("the license does not survive a round trip (check id and org)".into()),
        Err(e) => Err(e),
    }
}

fn parse_payload(text: &str) -> Result<(License, Claims), String> {
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
    let license = License {
        id: id.into(),
        org: org.into(),
        plan: plan.into(),
        seats: field("seats")?
            .parse()
            .map_err(|_| "license has a bad 'seats'")?,
        issued: date("issued")?,
        expires: date("expires")?,
    };
    let Some(plan) = Plan::parse(plan) else {
        return Err(format!(
            "this jetscan version does not know the '{}' plan — update jetscan",
            crate::ui::sanitize_line(plan)
        ));
    };
    let area = match fields.get("area") {
        None => None,
        Some(a) => Some(Area::parse(a).ok_or(format!(
            "this jetscan version does not know the trial area '{}' — update jetscan",
            crate::ui::sanitize_line(a)
        ))?),
    };
    let scans = match fields.get("scans") {
        None => None,
        // Только цифры: `+2` и ` 2` — не канонический текст.
        Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            Some(n.parse().map_err(|_| "license has a bad 'scans'")?)
        }
        Some(_) => return Err("license has a bad 'scans'".into()),
    };
    let features = fields.get("features").map(|list| {
        list.split(',')
            .filter_map(|t| ProFeature::ALL.into_iter().find(|f| f.token() == t))
            .collect()
    });
    let claims = Claims {
        plan,
        area,
        scans,
        features,
    };
    claims.validate()?;
    Ok((license, claims))
}

/// Ключ проверен: состояние по сроку и, если подпись и текст приняты, его поля.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    pub status: Status,
    /// `Some` — у `Active`/`Grace`/`Expired`; `None` — у `Free`/`Invalid`.
    pub claims: Option<Claims>,
}

impl Checked {
    pub fn free() -> Checked {
        Checked {
            status: Status::Free,
            claims: None,
        }
    }
}

/// Проверка ключа любого тарифа любым из доверенных публичных ключей `keys` на
/// дату `today`. Льгота — по тарифу (`Plan::grace_days`).
pub fn verify(key: &str, keys: &[[u8; 32]], today: i64) -> Checked {
    let invalid = |reason: String| Checked {
        status: Status::Invalid(reason),
        claims: None,
    };
    if keys.is_empty() {
        return invalid("this jetscan build has no license key built in".into());
    }
    let bad = || invalid("the license key is damaged or not a jetscan key".into());
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
        return invalid("the license key signature is not valid".into());
    }
    let (license, claims) = match String::from_utf8(text)
        .map_err(|_| String::new())
        .and_then(|t| parse_payload(&t))
    {
        Ok(parsed) => parsed,
        Err(e) if e.is_empty() => return bad(),
        Err(e) => return invalid(e),
    };
    let over = today - license.expires;
    let status = if over <= 0 {
        Status::Active {
            days_left: -over,
            license,
        }
    } else if over <= claims.plan.grace_days() {
        Status::Grace {
            days_over: over,
            license,
        }
    } else {
        Status::Expired {
            days_over: over,
            license,
        }
    };
    Checked {
        status,
        claims: Some(claims),
    }
}

/// Взгляд Teams (CI-отчёты `--sarif`/`--sbom`/`--baseline`): принят только ключ
/// Teams. Ключ Pro/аудита/пробного здесь — `Invalid` с понятной причиной, так что
/// код, который знает лишь `Status`, никогда не откроет CI-отчёты не тому тарифу.
/// Pro-сканы решает `entitlement()`.
pub fn check(key: &str, keys: &[[u8; 32]], today: i64) -> Status {
    teams_view(verify(key, keys, today))
}

fn teams_view(checked: Checked) -> Status {
    match checked.claims {
        Some(c) if c.plan != Plan::Teams => Status::Invalid(format!(
            "this is a {} key: it unlocks the Pro scans, not the jetscan Teams CI reports \
             (--sarif, --sbom, --baseline)",
            c.plan.title()
        )),
        _ => checked.status,
    }
}

/// Папка jetscan: `JETSCAN_HOME` или `~/.jetscan`.
pub fn jetscan_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("JETSCAN_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    crate::secrets::machine::home_dir().map(|h| h.join(".jetscan"))
}

/// Файл ключа: `JETSCAN_HOME/license` или `~/.jetscan/license`.
pub fn license_file() -> Option<PathBuf> {
    jetscan_home().map(|h| h.join("license"))
}

/// Текст ключа: `JETSCAN_LICENSE` (для CI — секрет), иначе файл ключа.
fn read_key() -> Option<String> {
    std::env::var("JETSCAN_LICENSE")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .or_else(|| {
            license_file()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .filter(|k| !k.trim().is_empty())
        })
}

/// Ключ этой машины, любой тариф.
pub fn load_checked() -> Checked {
    match read_key() {
        None => Checked::free(),
        Some(k) => verify(&k, PUBLIC_KEYS, today()),
    }
}

/// Текущий статус во взгляде Teams (см. `check`).
pub fn load() -> Status {
    teams_view(load_checked())
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

    // --- Pro / audit / trial (2026-11-16) ---

    /// Throwaway test secret (32 × 0x2a) — the same one the site's tests use.
    const FIXTURE_SEED: [u8; 32] = [0x2a; 32];
    const FIXTURE_PUBKEY: &str = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61";
    /// Byte-for-byte cross-check with the website's key issuer: its API tests hold the
    /// same strings and its signer must produce them. The Teams one is the original
    /// reference key of the site contract, from before Pro existed.
    const FIXTURES: [(&str, &str); 4] = [
        (
            "teams",
            "JETSCAN-1.amV0c2Nhbi1saWNlbnNlIDEKaWQ6IEpTLTAwMDEKb3JnOiBBY21lIEx0ZApwbGFuOiB0ZWFtcwpzZWF0czogMjAKaXNzdWVkOiAyMDI2LTEwLTI5CmV4cGlyZXM6IDIwMjctMTAtMjkK.W4C5bn_xT-yENxqw4GN2yaKvQTjstN8bXk6cYeccjmq46fRGHs5Ot6GlmMe3rDGI_8-Ib06_pEeKf9ELGphTBQ",
        ),
        (
            "pro",
            "JETSCAN-1.amV0c2Nhbi1saWNlbnNlIDEKaWQ6IEpQLTAwMDEKb3JnOiBwZXJzb25hbApwbGFuOiBwcm8Kc2VhdHM6IDEKaXNzdWVkOiAyMDI2LTExLTE2CmV4cGlyZXM6IDIwMjctMTEtMTYK.uTUJHtYdim7Q_G-cidpHw70XLXlM6FvKc0ZheHtZ1KSPCG0tOO2JSeqjN7UC8V8GIwm-E6hS4duWCSUianmHDw",
        ),
        (
            "audit",
            "JETSCAN-1.amV0c2Nhbi1saWNlbnNlIDEKaWQ6IEpBLTAwMDEKb3JnOiBwZXJzb25hbApwbGFuOiBhdWRpdApzZWF0czogMQppc3N1ZWQ6IDIwMjYtMTEtMTYKZXhwaXJlczogMjAyNi0xMi0xNgo.N8tW2ofM5jDJZKse3sInIftV4UF3FCbem7yj6ZCbmlczdL4V68ClwbRDGn52FA6fMbvSszyeSVNds8UlS3z6BA",
        ),
        (
            "trial",
            "JETSCAN-1.amV0c2Nhbi1saWNlbnNlIDEKaWQ6IEpULTAwMDEKb3JnOiBwZXJzb25hbApwbGFuOiB0cmlhbApzZWF0czogMQppc3N1ZWQ6IDIwMjYtMTEtMTYKZXhwaXJlczogMjAyNi0xMS0zMAphcmVhOiBhcGsKc2NhbnM6IDIK.OA82X5R9NXObtuQKsMxa9iKLsdmE9l3HKc7S04_c16vl_rSQs-8fYlXSdcfDDhE1lwbTVVwZQi5NJ01S7fUJDw",
        ),
    ];

    fn fixture(plan: &str) -> (License, Claims) {
        let d = |s| parse_date(s).unwrap();
        let personal = |id: &str, plan: Plan, expires| License {
            id: id.into(),
            org: "personal".into(),
            plan: plan.as_str().into(),
            seats: 1,
            issued: d("2026-11-16"),
            expires: d(expires),
        };
        match plan {
            "teams" => (
                License {
                    id: "JS-0001".into(),
                    org: "Acme Ltd".into(),
                    plan: "teams".into(),
                    seats: 20,
                    issued: d("2026-10-29"),
                    expires: d("2027-10-29"),
                },
                Claims::plan(Plan::Teams),
            ),
            "pro" => (
                personal("JP-0001", Plan::Pro, "2027-11-16"),
                Claims::plan(Plan::Pro),
            ),
            "audit" => (
                personal("JA-0001", Plan::Audit, "2026-12-16"),
                Claims::plan(Plan::Audit),
            ),
            _ => (
                personal("JT-0001", Plan::Trial, "2026-11-30"),
                Claims::trial(Area::Apk, 2),
            ),
        }
    }

    #[test]
    fn site_cross_check_fixtures_verify_and_are_reproduced_exactly() {
        let pk = ed25519::public_key(&FIXTURE_SEED);
        assert_eq!(crate::hash::hex(&pk), FIXTURE_PUBKEY);
        let today = parse_date("2026-11-20").unwrap();
        for (plan, key) in FIXTURES {
            let (l, c) = fixture(plan);
            assert_eq!(
                issue_with(&l, &c, &FIXTURE_SEED).as_deref(),
                Ok(key),
                "{plan}"
            );
            let checked = verify(key, &[pk], today);
            assert!(
                matches!(checked.status, Status::Active { ref license, .. } if *license == l),
                "{plan}: {checked:?}"
            );
            assert_eq!(checked.claims, Some(c), "{plan}");
        }
        // The legacy issuer and the new one agree on Teams, byte for byte.
        let (l, _) = fixture("teams");
        assert_eq!(issue(&l, &FIXTURE_SEED), FIXTURES[0].1);
    }

    #[test]
    fn an_old_format_teams_key_keeps_todays_semantics() {
        // Built by hand exactly as jetscan ≤ 0.3 and the site wrote it — not via payload().
        let text = "jetscan-license 1\nid: JS-20261101-abcdef\norg: Old Co\nplan: teams\n\
                    seats: 20\nissued: 2026-11-01\nexpires: 2027-11-01\n";
        let sig = ed25519::sign(&SEED, text.as_bytes());
        let key = format!(
            "{PREFIX}{}.{}",
            b64_encode(text.as_bytes()),
            b64_encode(&sig)
        );
        let pk = ed25519::public_key(&SEED);
        let day = |s| parse_date(s).unwrap();
        let checked = verify(&key, &[pk], day("2027-06-01"));
        assert_eq!(checked.claims, Some(Claims::plan(Plan::Teams)));
        assert!(check(&key, &[pk], day("2027-06-01")).paid());
        assert!(matches!(
            check(&key, &[pk], day("2027-11-15")),
            Status::Grace { days_over: 14, .. }
        ));
        assert!(matches!(
            check(&key, &[pk], day("2027-11-16")),
            Status::Expired { .. }
        ));
        // Unknown extra lines were always ignored; that stays (forward compatibility).
        let newer = format!("{text}color: blue\n");
        let sig = ed25519::sign(&SEED, newer.as_bytes());
        let newer = format!(
            "{PREFIX}{}.{}",
            b64_encode(newer.as_bytes()),
            b64_encode(&sig)
        );
        assert!(check(&newer, &[pk], day("2027-06-01")).paid());
    }

    #[test]
    fn the_teams_view_never_opens_ci_reports_to_other_plans() {
        let pk = ed25519::public_key(&FIXTURE_SEED);
        let today = parse_date("2026-11-20").unwrap();
        for (plan, key) in &FIXTURES[1..] {
            match check(key, &[pk], today) {
                Status::Invalid(reason) => {
                    assert!(
                        reason.contains("not the jetscan Teams CI reports"),
                        "{plan}"
                    )
                }
                other => panic!("{plan}: {other:?}"),
            }
            assert!(verify(key, &[pk], today).status.paid(), "{plan}");
        }
    }

    #[test]
    fn grace_is_only_for_yearly_plans() {
        let pk = ed25519::public_key(&FIXTURE_SEED);
        let day = |s| parse_date(s).unwrap();
        let state = |i: usize, today| verify(FIXTURES[i].1, &[pk], day(today)).status;
        assert!(matches!(
            state(1, "2027-11-30"),
            Status::Grace { days_over: 14, .. }
        ));
        assert!(matches!(state(1, "2027-12-01"), Status::Expired { .. }));
        assert!(matches!(state(2, "2026-12-16"), Status::Active { .. }));
        assert!(matches!(
            state(2, "2026-12-17"),
            Status::Expired { days_over: 1, .. }
        ));
        assert!(matches!(state(3, "2026-11-30"), Status::Active { .. }));
        assert!(matches!(state(3, "2026-12-01"), Status::Expired { .. }));
    }

    #[test]
    fn tampering_with_new_fields_breaks_the_signature() {
        let pk = ed25519::public_key(&FIXTURE_SEED);
        let today = parse_date("2026-11-20").unwrap();
        let key = FIXTURES[3].1;
        let (text, sig) = key[PREFIX.len()..].split_once('.').unwrap();
        let text = String::from_utf8(b64_decode(text).unwrap()).unwrap();
        for edited in [
            text.replace("area: apk", "area: web"),
            text.replace("scans: 2", "scans: 200"),
            text.replace("plan: trial", "plan: pro"),
            text.replace("scans: 2\n", ""),
        ] {
            let forged = format!("{PREFIX}{}.{sig}", b64_encode(edited.as_bytes()));
            assert_eq!(
                verify(&forged, &[pk], today).status,
                Status::Invalid("the license key signature is not valid".into())
            );
        }
    }

    #[test]
    fn signed_but_inconsistent_new_fields_are_rejected() {
        let pk = ed25519::public_key(&SEED);
        let today = parse_date("2026-11-20").unwrap();
        let sign = |text: &str| {
            let sig = ed25519::sign(&SEED, text.as_bytes());
            format!(
                "{PREFIX}{}.{}",
                b64_encode(text.as_bytes()),
                b64_encode(&sig)
            )
        };
        let base = |plan: &str| {
            format!(
                "{HEADER}\nid: JX-1\norg: personal\nplan: {plan}\nseats: 1\n\
                 issued: 2026-11-16\nexpires: 2026-11-30\n"
            )
        };
        let trial = format!("{}area: web\nscans: 2\n", base("trial"));
        assert!(verify(&sign(&trial), &[pk], today).status.paid());
        for (text, why) in [
            (base("trial"), "malformed"),
            (format!("{}area: web\n", base("trial")), "malformed"),
            (format!("{}scans: 2\n", base("trial")), "malformed"),
            (format!("{}area: web\n", base("pro")), "malformed"),
            (format!("{}scans: 5\n", base("audit")), "malformed"),
            (
                trial.replace("area: web", "area: desktop"),
                "update jetscan",
            ),
            (trial.replace("scans: 2", "scans: 0"), "'scans'"),
            (trial.replace("scans: 2", "scans: +2"), "'scans'"),
            (trial.replace("scans: 2", "scans: 1001"), "'scans'"),
            (trial.replace("scans: 2", "scans: 99999999999"), "'scans'"),
            (format!("{trial}area: apk\n"), "malformed"),
            (base("enterprise"), "update jetscan"),
        ] {
            match verify(&sign(&text), &[pk], today).status {
                Status::Invalid(reason) => assert!(reason.contains(why), "{reason} / {text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
        // Unknown feature words are skipped: a narrowing list can never widen a plan.
        let narrowed = format!("{}features: web,warp-drive\n", base("pro"));
        let checked = verify(&sign(&narrowed), &[pk], today);
        assert_eq!(
            checked.claims.unwrap().features,
            Some(vec![ProFeature::WebSource])
        );
    }

    #[test]
    fn issue_with_refuses_keys_that_would_not_verify() {
        let ok = fixture("trial");
        assert!(issue_with(&ok.0, &ok.1, &SEED).is_ok());
        let mut mismatch = ok.0.clone();
        mismatch.plan = "pro".into();
        let mut newline = fixture("pro").0;
        newline.org = "Evil\nplan: teams".into();
        let mut backwards = fixture("audit").0;
        backwards.expires = backwards.issued - 1;
        let pro_with_area = Claims {
            area: Some(Area::Web),
            ..Claims::plan(Plan::Pro)
        };
        for (l, c) in [
            (mismatch, ok.1.clone()),
            (newline, Claims::plan(Plan::Pro)),
            (backwards, Claims::plan(Plan::Audit)),
            (fixture("pro").0, pro_with_area),
            (ok.0.clone(), Claims::trial(Area::Web, 0)),
            (
                ok.0.clone(),
                Claims {
                    scans: None,
                    ..Claims::trial(Area::Web, 2)
                },
            ),
        ] {
            assert!(issue_with(&l, &c, &SEED).is_err(), "{l:?} {c:?}");
        }
    }
}
