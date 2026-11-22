use super::*;
use crate::license::{License, days_from_civil, ed25519, issue, issue_with, verify};

const SEED: [u8; 32] = [42; 32];

fn day(s: &str) -> i64 {
    let p: Vec<i64> = s.split('-').map(|x| x.parse().unwrap()).collect();
    days_from_civil(p[0], p[1], p[2])
}

fn key(id: &str, claims: &Claims, expires: &str) -> String {
    let l = License {
        id: id.into(),
        org: if claims.plan == Plan::Teams {
            "Acme Ltd".into()
        } else {
            "personal".into()
        },
        plan: claims.plan.as_str().into(),
        seats: if claims.plan == Plan::Teams { 20 } else { 1 },
        issued: day("2026-11-16"),
        expires: day(expires),
    };
    issue_with(&l, claims, &SEED).unwrap()
}

fn checked(id: &str, claims: &Claims, expires: &str, today: &str) -> Checked {
    verify(
        &key(id, claims, expires),
        &[ed25519::public_key(&SEED)],
        day(today),
    )
}

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "jetscan-license-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Temp(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const SCANS: [ProFeature; 5] = [
    ProFeature::WebSource,
    ProFeature::Apk,
    ProFeature::AndroidSource,
    ProFeature::IosSource,
    ProFeature::UrlAudit,
];

#[test]
fn each_plan_unlocks_exactly_its_features() {
    let today = "2026-11-20";
    let teams = checked("JS-1", &Claims::plan(Plan::Teams), "2027-11-16", today);
    let pro = checked("JP-1", &Claims::plan(Plan::Pro), "2027-11-16", today);
    let audit = checked("JA-1", &Claims::plan(Plan::Audit), "2026-12-16", today);
    for f in ProFeature::ALL {
        let e = entitlement_of(f, &teams, 0);
        assert!(
            matches!(e, Entitlement::Allowed { plan: Plan::Teams, ref license_id, .. } if license_id == "JS-1"),
            "teams {f:?}: {e:?}"
        );
    }
    for f in SCANS {
        assert!(matches!(
            entitlement_of(f, &pro, 0),
            Entitlement::Allowed {
                plan: Plan::Pro,
                ..
            }
        ));
        assert!(matches!(
            entitlement_of(f, &audit, 0),
            Entitlement::Allowed {
                plan: Plan::Audit,
                ..
            }
        ));
    }
    // Pro individual and the one-time audit are scans only: CI reports stay Teams.
    for c in [&pro, &audit] {
        let e = entitlement_of(ProFeature::CiReports, c, 0);
        let text = e.paywall(ProFeature::CiReports).unwrap();
        assert!(text.contains("part of jetscan Teams"), "{text}");
        assert!(text.contains("JETSCAN_LICENSE"), "{text}");
    }
    for area in Area::ALL {
        let trial = checked("JT-1", &Claims::trial(area, 2), "2026-11-30", today);
        for f in ProFeature::ALL {
            let e = entitlement_of(f, &trial, 0);
            if f.area() == Some(area) {
                assert_eq!(
                    e,
                    Entitlement::Trial {
                        area,
                        remaining: 2,
                        license_id: "JT-1".into(),
                        expires: day("2026-11-30")
                    }
                );
                assert!(e.warning().unwrap().contains("2 scans left"));
            } else {
                assert!(!e.allowed(), "{area:?} {f:?}");
            }
        }
    }
}

#[test]
fn the_trial_counter_closes_the_trial() {
    let trial = checked(
        "JT-1",
        &Claims::trial(Area::Apk, 2),
        "2026-11-30",
        "2026-11-20",
    );
    assert!(matches!(
        entitlement_of(ProFeature::Apk, &trial, 1),
        Entitlement::Trial { remaining: 1, .. }
    ));
    for used in [2, 3, u32::MAX] {
        let e = entitlement_of(ProFeature::Apk, &trial, used);
        let text = e.paywall(ProFeature::Apk).unwrap();
        assert!(text.contains("2 scans are used up"), "{text}");
        assert!(
            text.starts_with("A static security audit of an Android APK — part of jetscan Pro.")
        );
        assert!(
            text.contains("Free trial or buy: https://jetscan.jet.kim"),
            "{text}"
        );
    }
    let web = entitlement_of(ProFeature::WebSource, &trial, 0);
    assert!(
        web.paywall(ProFeature::WebSource)
            .unwrap()
            .contains("covers the apk scan only")
    );
}

#[test]
fn expiry_and_grace_follow_the_plan() {
    // Teams and Pro: 14 days of grace with a warning, like Teams always had.
    for (id, plan) in [("JS-1", Plan::Teams), ("JP-1", Plan::Pro)] {
        let grace = checked(id, &Claims::plan(plan), "2027-11-16", "2027-11-30");
        let e = entitlement_of(ProFeature::WebSource, &grace, 0);
        let warning = e.warning().unwrap();
        assert!(e.allowed() && warning.contains("0 days more"), "{warning}");
        let over = checked(id, &Claims::plan(plan), "2027-11-16", "2027-12-01");
        let text = entitlement_of(ProFeature::WebSource, &over, 0)
            .paywall(ProFeature::WebSource)
            .unwrap();
        assert!(text.contains("license expired on 2027-11-16"), "{text}");
        // A month before the end: allowed, with a reminder.
        let soon = checked(id, &Claims::plan(plan), "2027-11-16", "2027-11-01");
        assert!(
            entitlement_of(ProFeature::Apk, &soon, 0)
                .warning()
                .unwrap()
                .contains("15 days left")
        );
        let far = checked(id, &Claims::plan(plan), "2027-11-16", "2027-01-01");
        assert_eq!(entitlement_of(ProFeature::Apk, &far, 0).warning(), None);
    }
    // Audit and trial: no grace at all; the last valid day is the expiry date.
    let audit = Claims::plan(Plan::Audit);
    assert!(
        entitlement_of(
            ProFeature::IosSource,
            &checked("JA-1", &audit, "2026-12-16", "2026-12-16"),
            0
        )
        .allowed()
    );
    let ended = checked("JA-1", &audit, "2026-12-16", "2026-12-17");
    assert!(matches!(ended.status, Status::Expired { days_over: 1, .. }));
    let text = entitlement_of(ProFeature::IosSource, &ended, 0)
        .paywall(ProFeature::IosSource)
        .unwrap();
    assert!(text.contains("audit access ended on 2026-12-16"), "{text}");
    let trial = checked(
        "JT-1",
        &Claims::trial(Area::Ios, 2),
        "2026-11-30",
        "2026-12-01",
    );
    let text = entitlement_of(ProFeature::IosSource, &trial, 0)
        .paywall(ProFeature::IosSource)
        .unwrap();
    assert!(text.contains("trial ended on 2026-11-30"), "{text}");
}

#[test]
fn no_key_or_a_bad_key_is_denied_with_the_way_to_get_one() {
    let pk = ed25519::public_key(&SEED);
    let foreign = verify(
        &key("JP-1", &Claims::plan(Plan::Pro), "2027-11-16"),
        &[ed25519::public_key(&[7; 32])],
        day("2026-11-20"),
    );
    let junk = verify("JETSCAN-1.bm90.c2ln", &[pk], day("2026-11-20"));
    for c in [Checked::free(), foreign, junk] {
        for f in ProFeature::ALL {
            let e = entitlement_of(f, &c, 0);
            let text = e.paywall(f).unwrap();
            assert!(
                text.contains(f.what()) && text.contains(f.product()),
                "{text}"
            );
            assert!(text.contains("https://jetscan.jet.kim"), "{text}");
            assert!(!text.contains("JETSCAN-1."), "{text}");
        }
    }
}

#[test]
fn features_only_narrow_a_plan() {
    let today = "2026-11-20";
    let narrowed = Claims {
        features: Some(vec![ProFeature::WebSource, ProFeature::CiReports]),
        ..Claims::plan(Plan::Pro)
    };
    let c = checked("JP-2", &narrowed, "2027-11-16", today);
    assert!(entitlement_of(ProFeature::WebSource, &c, 0).allowed());
    assert!(!entitlement_of(ProFeature::Apk, &c, 0).allowed());
    // Listing "ci" in a Pro key does not turn it into Teams.
    assert!(!entitlement_of(ProFeature::CiReports, &c, 0).allowed());
    let none = Claims {
        features: Some(vec![]),
        ..Claims::plan(Plan::Teams)
    };
    let c = checked("JS-2", &none, "2027-11-16", today);
    assert!(
        ProFeature::ALL
            .into_iter()
            .all(|f| !entitlement_of(f, &c, 0).allowed())
    );
}

#[test]
fn record_trial_scan_counts_down_and_fails_closed() {
    let t = Temp::new("trial");
    let trial = checked(
        "JT-0001",
        &Claims::trial(Area::Web, 2),
        "2026-11-30",
        "2026-11-20",
    );
    assert_eq!(used_in(&t.0, "JT-0001"), 0);
    assert_eq!(record_trial_scan_in(&t.0, &trial), Ok(Some(1)));
    assert_eq!(used_in(&t.0, "JT-0001"), 1);
    let file = t.0.join("trial-JT-0001.json");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
        text.contains("\"license\":\"JT-0001\"") && text.contains("\"used\":1"),
        "{text}"
    );
    assert_eq!(record_trial_scan_in(&t.0, &trial), Ok(Some(0)));
    assert_eq!(record_trial_scan_in(&t.0, &trial), Ok(Some(0)));
    assert_eq!(used_in(&t.0, "JT-0001"), 2);
    assert!(!entitlement_of(ProFeature::WebSource, &trial, used_in(&t.0, "JT-0001")).allowed());
    assert!(!t.0.join("trial-JT-0001.json.tmp").exists());

    // Damaged, edited or foreign counter files mean "used up", never "unlimited".
    for bad in [
        "",
        "{",
        "{\"license\":\"JT-0001\",\"used\":-1}",
        "{\"license\":\"JT-0001\",\"used\":0.5}",
        "{\"license\":\"JT-9999\",\"used\":0}",
        "{\"used\":0}",
    ] {
        std::fs::write(&file, bad).unwrap();
        assert_eq!(used_in(&t.0, "JT-0001"), u32::MAX, "{bad}");
    }
    // Deleting the file resets the local counter: the documented limit.
    std::fs::remove_file(&file).unwrap();
    assert_eq!(used_in(&t.0, "JT-0001"), 0);

    // Nothing to count for paid plans, expired trials or no key.
    let pro = checked("JP-1", &Claims::plan(Plan::Pro), "2027-11-16", "2026-11-20");
    let ended = checked(
        "JT-0001",
        &Claims::trial(Area::Web, 2),
        "2026-11-30",
        "2026-12-05",
    );
    for c in [pro, ended, Checked::free()] {
        assert_eq!(record_trial_scan_in(&t.0, &c), Ok(None));
    }
    assert!(!file.exists());
}

#[test]
fn counter_file_names_are_safe() {
    assert_eq!(
        counter_name("JT-20261116-ab12cd"),
        "trial-JT-20261116-ab12cd.json"
    );
    for id in ["../../etc/passwd", "a b", "x".repeat(65).as_str(), "", "Ю"] {
        let name = counter_name(id);
        assert!(
            name.starts_with("trial-") && name.ends_with(".json"),
            "{name}"
        );
        assert_eq!(name.len(), "trial-.json".len() + 16, "{name}");
        let stem = &name["trial-".len()..name.len() - ".json".len()];
        assert!(stem.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
    }
}

#[test]
fn describe_shows_plan_expiry_unlocks_and_never_the_key() {
    let today = "2026-11-20";
    let free = describe(&Checked::free(), 0).unwrap();
    assert!(
        free.contains("jetscan Free") && free.contains("free trial"),
        "{free}"
    );

    let teams_key = key("JS-1", &Claims::plan(Plan::Teams), "2027-11-16");
    let teams = verify(&teams_key, &[ed25519::public_key(&SEED)], day(today));
    let text = describe(&teams, 0).unwrap();
    assert!(text.starts_with("jetscan Teams — Acme Ltd · 20 seats · JS-1 · issued 2026-11-16"));
    assert!(
        text.contains("valid until 2027-11-16 (361 days left)"),
        "{text}"
    );
    assert!(
        text.contains("every Pro scan") && text.contains("--sarif"),
        "{text}"
    );
    assert!(!text.contains(&teams_key));

    let pro = describe(
        &checked("JP-1", &Claims::plan(Plan::Pro), "2027-11-16", today),
        0,
    )
    .unwrap();
    assert!(pro.starts_with("jetscan Pro — JP-1 · issued"), "{pro}");
    assert!(!pro.contains("personal") && pro.contains("part of jetscan Teams"));

    let trial = checked(
        "JT-1",
        &Claims::trial(Area::Android, 2),
        "2026-11-30",
        today,
    );
    let text = describe(&trial, 1).unwrap();
    assert!(
        text.starts_with("jetscan Pro trial (android) — JT-1"),
        "{text}"
    );
    assert!(text.contains("1 of 2 trial scans left"), "{text}");
    assert!(text.contains("the android scan only"), "{text}");

    let audit = describe(
        &checked(
            "JA-1",
            &Claims::plan(Plan::Audit),
            "2026-12-16",
            "2027-01-30",
        ),
        0,
    )
    .unwrap();
    assert!(audit.contains("expired on 2026-12-16"), "{audit}");

    let bad = verify(&teams_key, &[ed25519::public_key(&[1; 32])], day(today));
    let e = describe(&bad, 0).unwrap_err();
    assert!(e.contains("not accepted") && !e.contains(&teams_key), "{e}");

    // The legacy Teams key format reads exactly like before Pro existed.
    let legacy = License {
        id: "JS-0001".into(),
        org: "Acme Ltd".into(),
        plan: "teams".into(),
        seats: 25,
        issued: day("2026-10-29"),
        expires: day("2027-10-29"),
    };
    let old = verify(
        &issue(&legacy, &SEED),
        &[ed25519::public_key(&SEED)],
        day(today),
    );
    assert!(
        describe(&old, 0)
            .unwrap()
            .starts_with("jetscan Teams — Acme Ltd · 25 seats · JS-0001")
    );
}
