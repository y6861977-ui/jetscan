use jetscan::secrets::Location;
use jetscan::secrets::scan::{ScanOptions, scan};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempCorpus(PathBuf);

impl TempCorpus {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("jetscan-fixture-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("create temporary fixture root");
        TempCorpus(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempCorpus {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("read fixture entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("read fixture file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy fixture file");
        }
    }
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn planted_multilanguage_corpus_has_exact_findings() {
    let corpus = TempCorpus::new();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    copy_tree(&fixtures, corpus.path());

    // Token-shaped values are deliberately assembled at runtime so the repository
    // itself never contains a complete credential.
    let aws = format!("{}{}", "AKIA", "Q7ZK2M4N8P3R5T6V");
    let npm = format!("{}{}", "npm_", "a1".repeat(18));
    fs::write(
        corpus.path().join("javascript/src/config.js"),
        format!("export const cloudKey = \"{aws}\";\n"),
    )
    .expect("write JavaScript secret fixture");
    fs::write(
        corpus.path().join("javascript/.npmrc"),
        format!("//registry.npmjs.org/:_authToken={npm}\n"),
    )
    .expect("write npm secret fixture");

    let database_password = format!("{}{}", "fixture-db-", "Pass9Zq7");
    let pypi_password = format!("{}{}", "upload-", "Token8Yp6");
    fs::write(
        corpus.path().join("python/.env"),
        format!("DB_PASSWORD={database_password}\n"),
    )
    .expect("write dotenv secret fixture");
    fs::write(
        corpus.path().join("python/.pypirc"),
        format!("[pypi]\nusername = __token__\npassword = {pypi_password}\n"),
    )
    .expect("write PyPI secret fixture");

    let github = format!("{}{}", "ghp_", "Zq8".repeat(12));
    let telegram = format!("{}:{}{}", "73918426", "A1_-".repeat(8), "AbC");
    fs::write(
        corpus.path().join("go/secrets.go"),
        format!(
            "package main\n\nconst githubToken = \"{github}\"\nconst telegramToken = \"{telegram}\"\n"
        ),
    )
    .expect("write Go secret fixture");

    let report = scan(
        corpus.path(),
        &ScanOptions {
            history: false,
            ..ScanOptions::default()
        },
    )
    .expect("scan generated fixture corpus");

    let actual: Vec<(String, usize, &'static str)> = report
        .findings
        .iter()
        .map(|finding| {
            let Location::File { path } = &finding.location else {
                panic!("fixture scan must only contain file findings");
            };
            (slash_path(path), finding.line, finding.rule.id)
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            ("go/secrets.go".into(), 3, "github-token"),
            ("go/secrets.go".into(), 4, "telegram-bot"),
            ("javascript/.npmrc".into(), 1, "npm-token"),
            ("javascript/src/config.js".into(), 1, "aws-access-key"),
            ("python/.env".into(), 1, "env-secret"),
            ("python/.pypirc".into(), 3, "pypi-password"),
        ]
    );
    assert_eq!(report.total(), 6);
    for finding in &report.findings {
        assert!(!finding.masked.contains("fixture-db"));
        assert_eq!(finding.fingerprint.len(), 16);
    }
}
