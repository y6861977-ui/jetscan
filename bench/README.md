# jetscan vs Gitleaks and Trivy

A comparison we ran ourselves, with the scripts to repeat it (`bench/run.sh`). We publish all
of it, including where jetscan loses. The author of jetscan wrote this benchmark, so read
test 1 with that in mind; tests 2–4 use data we did not make.

**Versions:** jetscan 0.1.1 (release build), Gitleaks 8.30.1, Trivy 0.76.1 (vulnerability DB of
2026-11-02). All three with **default settings**. Run on 2026-11-02, Windows 11.

**History of this page.** The first version (jetscan 0.1.0) showed two gaps in jetscan: no
DigitalOcean rule, and silence on weak passwords in credential files. 0.1.1 fixes both, and the
numbers below are re-measured. The first version also had a mistake of ours: the test generator
made Discord tokens in a shape real tokens never have, so both tools "missed" them. Fixed.

## Summary

| | jetscan | Gitleaks / Trivy |
|---|---|---|
| Planted secrets of 23 popular services, 10 random sets (test 1) | **230 / 230** | 191 / 230 |
| Placeholders, examples and hashes flagged (test 1) | 0 / 100 | 0 / 100 |
| leaky-repo, its own scoring (test 2) | **27 / 175** | 22 / 175 |
| Findings that are not secrets at all, 10 popular repos (test 3) | **0** | 10 |
| Known vulnerabilities in 7 projects' lockfiles (test 4) | 849 | 852 (837 found by both) |

In short: jetscan did not flag a single non-secret and found more in both secret tests. Gitleaks
covers many more services (222 rules), and on leaky-repo it still finds things jetscan does not
(secrets exported in `.bashrc`, AWS credential files, Rails `secrets.yml`). For dependencies
the two tools agree on 98% of advisories; the differences come from the databases (OSV vs Trivy's).

## 1. Planted secrets

`planted.mjs` makes a git repository with 23 fake secrets of popular services — random values
in each service's real format, with the real checksum where the format has one (GitHub, npm).
12 stay in the files, 11 exist only in git history (committed, then removed). It also adds 10
things that are **not** secrets: AWS's documented example key, `ghp_xxxx…` and
`sk_live_your_key_here` placeholders, `${{ secrets.X }}` references, a SHA-256, a UUID, an npm
integrity hash, a git commit id, a base64 image, a password prompt. We ran it with 10 seeds
(1–10), so every row is 10 different random values. jetscan: `jetscan secrets .`; Gitleaks:
`gitleaks git .` (both read the history).

| Secret | jetscan | Gitleaks |
|---|---|---|
| AWS access key ID | 10/10 | 10/10 |
| AWS secret access key | 10/10 | 9/10 |
| GitHub token (`ghp_`) | 10/10 | 10/10 |
| GitHub fine-grained token | 10/10 | 10/10 |
| GitLab token | 10/10 | 10/10 |
| Slack bot token | 10/10 | 10/10 |
| Slack webhook URL | 10/10 | 10/10 |
| Stripe live secret key | 10/10 | 10/10 |
| Google API key | 10/10 | 10/10 |
| OpenAI API key | 10/10 | 10/10 |
| Anthropic API key | 10/10 | 10/10 |
| npm token | 10/10 | 10/10 |
| PyPI token | 10/10 | 10/10 |
| SendGrid API key | 10/10 | 10/10 |
| Twilio API key SID | 10/10 | 10/10 |
| Shopify access token | 10/10 | 10/10 |
| DigitalOcean token | 10/10 | 10/10 |
| Hugging Face token | 10/10 | 10/10 |
| Telegram bot token | 10/10 | 0/10 |
| Discord bot token | 10/10 | 0/10 |
| RSA private key | 10/10 | 10/10 |
| Database URL with password | 10/10 | 0/10 |
| Password in `.env` | 10/10 | 2/10 |

Neither tool flagged any of the non-secrets. Gitleaks' Telegram and Discord rules want the
service name in the variable name (`TOKEN = …` in `bot/telegram.py` and `client.login(…)` do not
count); it has no rule for passwords in connection strings; its generic rule passes or drops a
`.env` password depending on the value's entropy.

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
| jetscan | 19 / 44 | 27 / 175 (15.4%) | 0 |
| Gitleaks | 13 / 44 | 22 / 175 (12.6%) | 0 |

Both score low, partly because no secret scanner looks for user names and host names (79 of the
175). jetscan 0.1.1 reports any stored password in files whose only purpose is to store
credentials (`.netrc`, `.pgpass`, `.git-credentials`, `.esmtprc`, FileZilla, SFTP/FTP plugin
configs, IDEA `WebServers.xml`), however weak it looks; 0.1.0 found 12 here. Gitleaks still finds
what jetscan does not in `.bashrc` and `.bash_profile` (exported keys), `cloud/.credentials` and
`.s3cfg` (AWS keys not in the `AKIA…` format), `web/ruby/secrets.yml`, `hub`, `.dockercfg`.

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

jetscan 0.1.0 and 0.1.1 gave the same findings on all ten. Time, files only, best of 3 runs,
warm disk cache, in milliseconds (jetscan 0.1.1):

| repo | files | jetscan | Gitleaks |
|---|---|---|---|
| laravel | 66 | 61 | 541 |
| spring-petclinic | 132 | 121 | 619 |
| express | 216 | 130 | 564 |
| flask | 236 | 167 | 626 |
| requests | 130 | 196 | 632 |
| gin | 130 | 184 | 617 |
| axum | 508 | 322 | 637 |
| axios | 522 | 408 | 747 |
| fastapi | 3 235 | 1 508 | 1 162 |
| django | 7 085 | 3 487 | 1 849 |

jetscan is faster on small and medium repositories and slower on large ones.

## 4. Vulnerable dependencies (jetscan vs Trivy)

`jetscan deps` (0.1.0 — the dependency check did not change in 0.1.1; asks OSV.dev) against `trivy fs --scanners vuln --include-dev-deps` (Trivy's
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

## Known gaps (to fix)

1. Secrets exported in shell profiles (`.bashrc`, `.bash_profile`) and AWS credential files with
   keys outside the `AKIA…` format; Rails `secrets.yml`.
2. Large repositories (thousands of files): jetscan is up to ~1.9× slower than Gitleaks.
3. Fewer services than Gitleaks overall.
