# jetscan vs Gitleaks and Trivy

A comparison we ran ourselves, with the scripts to repeat it (`bench/run.sh`). We publish all
of it, including where jetscan loses. The author of jetscan wrote this benchmark, so read
test 1 with that in mind; tests 2–4 use data we did not make.

**Versions:** jetscan 0.1.0 (the release binary), Gitleaks 8.30.1, Trivy 0.76.1 (vulnerability
DB of 2026-11-02). All three with **default settings**. Run on 2026-11-02, Windows 11.

## Summary

| | jetscan | Gitleaks / Trivy |
|---|---|---|
| Planted secrets of 23 popular services (test 1) | **21 / 23** | 20 / 23 |
| Placeholders, examples and hashes flagged (test 1) | 0 / 10 | 0 / 10 |
| leaky-repo, its own scoring (test 2) | 12 / 175 | **22 / 175** |
| Findings that are not secrets at all, 10 popular repos (test 3) | **0** | 10 |
| Known vulnerabilities in 7 projects' lockfiles (test 4) | 849 | 852 (837 found by both) |

In short: jetscan is quieter — it did not flag a single non-secret — but with default settings
it finds less than Gitleaks in the kind of credential files leaky-repo is full of (weak
passwords in `.netrc`, `.pgpass`, FTP and database configs). For dependencies the two tools
agree on 98% of advisories (837 of 849 and of 852); the differences come from the databases (OSV vs Trivy's).

## 1. Planted secrets

`planted.mjs` makes a git repository with 23 fake secrets of popular services — random values
in each service's real format, with the real checksum where the format has one (GitHub, npm).
12 stay in the files, 11 exist only in git history (committed, then removed). It also adds 10
things that are **not** secrets: AWS's documented example key, `ghp_xxxx…` and
`sk_live_your_key_here` placeholders, `${{ secrets.X }}` references, a SHA-256, a UUID, an npm
integrity hash, a git commit id, a base64 image, a password prompt. jetscan: `jetscan secrets .`;
Gitleaks: `gitleaks git .` (both read the history).

| Secret | Only in history | jetscan | Gitleaks |
|---|---|---|---|
| AWS access key ID |  | ✓ | ✓ |
| AWS secret access key | yes | ✓ | ✓ |
| GitHub token (`ghp_`) |  | ✓ | ✓ |
| GitHub fine-grained token | yes | ✓ | ✓ |
| GitLab token |  | ✓ | ✓ |
| Slack bot token | yes | ✓ | ✓ |
| Slack webhook URL |  | ✓ | ✓ |
| Stripe live secret key | yes | ✓ | ✓ |
| Google API key |  | ✓ | ✓ |
| OpenAI API key | yes | ✓ | ✓ |
| Anthropic API key |  | ✓ | ✓ |
| npm token | yes | ✓ | ✓ |
| PyPI token |  | ✓ | ✓ |
| SendGrid API key | yes | ✓ | ✓ |
| Twilio API key SID |  | ✓ | ✓ |
| Shopify access token | yes | ✓ | ✓ |
| DigitalOcean token |  | **✗** | ✓ |
| Hugging Face token | yes | ✓ | ✓ |
| Telegram bot token |  | ✓ | ✗ |
| Discord bot token | yes | ✗ | ✗ |
| RSA private key |  | ✓ | ✓ |
| Database URL with password | yes | ✓ | ✗ |
| Password in `.env` |  | ✓ | ✓ |

Neither tool flagged any of the 10 non-secrets. Gitleaks missed the Telegram token because its
rule wants "telegr" in the variable name (`TOKEN = …` in `bot/telegram.py` does not count), and the database URL because it has no rule
for passwords in connection strings. jetscan has no DigitalOcean rule yet. The Discord token
format we generated matched neither tool.

The list of services is ours, so this test can favour jetscan. Gitleaks ships with 222 rules, for
many more services than jetscan covers; a service missing from this list is more likely to be
missing from jetscan than from Gitleaks.

## 2. leaky-repo

[Plazmaz/leaky-repo](https://github.com/Plazmaz/leaky-repo) was built as a benchmark for secret
scanners. Its answer key (`.leaky-meta/secrets.csv`) counts 175 lines in 44 files: 96 "risk"
lines (passwords, keys) and 79 "informative" ones (user names, hosts). We used its own scoring
method (`.leaky-meta/benchmark.py`): per file, findings up to the expected count are finds,
findings above it are false positives. Both tools scanned the files at HEAD.

| | Files covered | Finds | False positives |
|---|---|---|---|
| jetscan | 7 / 44 | 12 / 175 (6.9%) | 0 |
| Gitleaks | 13 / 44 | 22 / 175 (12.6%) | 0 |

Both score low, partly because no secret scanner looks for user names and host names (79 of the
175). The rest is a real gap in jetscan: it treats passwords like `password` or `pass123` as
placeholders and stays silent, and that also silences them inside files whose only purpose is
to store credentials — `.netrc`, `.pgpass`, `.git-credentials`, FileZilla and FTP-plugin
configs. Gitleaks found more there (`cloud/.credentials`, `.s3cfg`, `secrets.yml`, `.bashrc`).
jetscan found things Gitleaks did not in `web/var/www/.env` (4 vs 0) and `db/mongoid.yml`.

## 3. Ten popular repositories

Files at HEAD of express, flask, requests, fastapi, axios, gin, laravel, axum, django and
spring-petclinic (commits in `run.sh`). jetscan: `secrets --no-history`; Gitleaks: `dir`. We
looked at every finding by hand.

| | jetscan | Gitleaks |
|---|---|---|
| Live secrets | 0 | 0 |
| Private keys of test certificates | 12 | 12 |
| Credentials in test data | 2 | 8 |
| Example secrets in documentation and tutorials | 0 | 24 |
| **Not a secret at all** | **0** | **10** |
| Total | 14 | 54 |

The ten non-secrets Gitleaks flagged: `key := "float32-slice"` and `"float64-slice"` (gin),
`key='Asia/Singapore'` and `key='Europe/Helsinki'` (django docs), `token, since_days=365` (two,
django), `"auth.add_user"` (django), two `Sec-WebSocket-Key` sample nonces (gin, axum) and a
commented curl command (axum).

Time, files only, best of 3 runs, warm disk cache, in milliseconds:

| repo | files | jetscan | Gitleaks |
|---|---|---|---|
| laravel | 66 | 58 | 546 |
| spring-petclinic | 132 | 118 | 579 |
| express | 216 | 120 | 536 |
| flask | 236 | 155 | 616 |
| requests | 130 | 180 | 617 |
| gin | 130 | 178 | 632 |
| axum | 508 | 302 | 616 |
| axios | 522 | 392 | 748 |
| fastapi | 3 235 | 1 420 | 1 138 |
| django | 7 085 | 3 243 | 1 846 |

jetscan is faster on small and medium repositories and slower on large ones.

## 4. Vulnerable dependencies (jetscan vs Trivy)

`jetscan deps` (asks OSV.dev) against `trivy fs --scanners vuln --include-dev-deps` (Trivy's
local database), on two deliberately outdated apps (OWASP NodeGoat, pygoat) and the lockfiles of
five current projects. The same vulnerability = same package, version and advisory (by id or
alias).

| repo | jetscan | Trivy | both | only jetscan | only Trivy |
|---|---|---|---|---|---|
| NodeGoat (npm) | 320 | 334 | 319 | 1 | 13 |
| pygoat (PyPI) | 365 | 356 | 356 | 9 | 0 |
| axios (npm) | 37 | 37 | 37 | 0 | 0 |
| flask (PyPI, uv.lock) | 52 | 52 | 52 | 0 | 0 |
| fastapi (PyPI, uv.lock) | 65 | 65 | 65 | 0 | 0 |
| gin (Go) | 8 | 8 | 8 | 0 | 0 |
| axum (crates) | 2 | 0 | 0 | 2 | 0 |

- Only Trivy: 13 old Node Security Working Group advisories (`NSWG-ECO-*`) that OSV does not carry.
- Only jetscan: a malicious-package record (`fsevents@1.2.9`, `MAL-2023-462`); PyPI advisories that
  Trivy leaves out (some disputed, e.g. CVE-2022-29361 in werkzeug, CVE-2025-45768 in pyjwt);
  two RustSec advisories for unmaintained crates (`bincode`, `proc-macro-error2`).
- Trivy covers far more than lockfiles — container images, OS packages, Maven, Composer, NuGet,
  IaC. jetscan reads npm, yarn, pnpm, PyPI, Cargo and Go lockfiles only.
- jetscan sends package names and versions to api.osv.dev; Trivy downloads its database first and
  then works offline.

## Known gaps this showed (to fix)

1. Credential files (`.netrc`, `.pgpass`, `.git-credentials`, FTP and database client configs):
   report any stored password there, however weak it looks.
2. No rules yet for DigitalOcean and Discord tokens.
3. Large repositories (thousands of files): jetscan is up to ~1.8× slower than Gitleaks.
