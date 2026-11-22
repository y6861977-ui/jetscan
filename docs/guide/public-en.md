# jetscan user guide

This guide covers the free jetscan 0.4.0, with a short overview of jetscan Pro. Every command, option and
message below was checked against the program itself. The example outputs are real runs on
small demo projects, shortened where marked with `…`. If this guide and `jetscan --help`
ever disagree, trust `--help` and tell us.

Plain-language rule of thumb: you can read this guide top to bottom, or jump to the part you
need. Words that may be new are explained in the [glossary](#10-glossary).

<!-- toc -->
- [1. What jetscan is](#1-what-jetscan-is)
- [2. Install and first run](#2-install-and-first-run)
- [3. The menu and the console](#3-the-menu-and-the-console)
- [4. Free checks](#4-free-checks)
- [5. Reading the results](#5-reading-the-results)
- [6. jetscan Pro](#6-jetscan-pro)
- [7. AI editors (MCP)](#7-ai-editors-mcp)
- [8. CI (GitHub Actions and others)](#8-ci-github-actions-and-others)
- [9. Troubleshooting and FAQ](#9-troubleshooting-and-faq)
- [10. Glossary](#10-glossary)
<!-- /toc -->

## 1. What jetscan is

jetscan is a security scanner that runs **on your own computer**. It looks for problems that
have a definite answer:

- **Leaked secrets**: API keys, tokens, private keys and passwords in your files and in your
  git history (including keys you deleted long ago that are still in old commits).
- **Known vulnerabilities** in the packages your project uses (checked against the public
  OSV.dev database), and packages that are known malware.
- **Risky GitHub Actions workflows** that a stranger could abuse with a pull request.
- **Your whole machine**: tokens stored as plain text, SSH keys without a passphrase,
  secrets in shell history, every repository in your home folder.
- With **jetscan Pro** (a separate build): website source code (Next.js / Vite React),
  Android APK files, Android and iOS source projects, and a passive check of a live website.

jetscan does not judge code style and does not guess. It reports facts it can show you: the
file, the line, the rule, and what to do.

### Your code stays on your machine

jetscan never uploads your code, never sends anything to a jetscan server and needs no
account. There is no telemetry. A few checks do use the network, and only for this:

| What you run | What goes over the network |
|---|---|
| `jetscan secrets`, `machine`, `hook`, the GitHub Actions check, `resolve`, the menu | nothing |
| `jetscan deps`, and the dependency part of `jetscan scan` | package **names and versions** to `api.osv.dev` (never code, file paths or project names). `--offline` sends nothing. Results are cached for 24 hours. |
| `jetscan secrets --verify` (off by default) | each found key goes **only to its own provider** (for example a GitHub token to GitHub) in one read-only "who am I" request |
| `jetscan machine --deps` | the same as `jetscan deps`, for every repository |
| `jetscan mcp` (AI editors) | nothing by default; the dependency tool goes online only if the AI asks for `offline: false` |
| Pro: `web source`, `apk`, `android`, `ios` | nothing |
| Pro: `url <site>` | only the requests a browser makes, to **that site only** |
| License keys (`jetscan license`, Pro, Teams) | nothing: the key is checked on your machine |

jetscan needs two standard programs: **git** (to read history and know which files are
committed) and **curl** (for every network request above). curl ships with Windows 10 and
later, macOS and most Linux distributions. Without git, jetscan still scans files and says
clearly that history was not checked.

## 2. Install and first run

jetscan is one small file with no runtime and no dependencies. No administrator rights are
needed.

### Windows

Open PowerShell and run:

```powershell
irm https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.ps1 | iex
```

It downloads the latest release, checks it against the release's `SHA256SUMS` file, refuses
to install on a mismatch, puts `jetscan.exe` into `%LOCALAPPDATA%\jetscan\bin` and adds that
folder to your user `PATH`. Open a **new** terminal afterwards so the new `PATH` is used.

### macOS and Linux

```sh
curl -fsSL https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.sh | sh
```

It installs to `~/.local/bin/jetscan`, also after checking `SHA256SUMS`. Make sure
`~/.local/bin` is on your `PATH`. Supported: Linux x64 and arm64 (static builds), macOS on
Apple silicon and Intel.

Options for both installers (environment variables):

| Variable | Meaning |
|---|---|
| `JETSCAN_VERSION` | install a specific version, for example `JETSCAN_VERSION=v0.4.0` (default: latest) |
| `JETSCAN_INSTALL_DIR` | macOS/Linux only: where to put the file (default `~/.local/bin`) |

### Manual download and checking SHA256 yourself

On the releases page of `github.com/y6861977-ui/jetscan` each release has one archive per
system plus `SHA256SUMS`:

| System | Archive |
|---|---|
| Windows x64 | `jetscan-<version>-x86_64-pc-windows-msvc.zip` |
| Linux x64 | `jetscan-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `jetscan-<version>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon | `jetscan-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `jetscan-<version>-x86_64-apple-darwin.tar.gz` |

Compare the archive's SHA-256 with its line in `SHA256SUMS`:

```powershell
# Windows (PowerShell)
Get-FileHash .\jetscan-v0.4.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

```sh
# Linux
sha256sum -c SHA256SUMS --ignore-missing
# macOS
shasum -a 256 jetscan-v0.4.0-aarch64-apple-darwin.tar.gz
```

If the two values differ, do not run the file.

### The jetscan Pro build

jetscan Pro is a **separate, closed-source build** (the free build cannot run Pro checks,
even with a key). See [6. jetscan Pro](#6-jetscan-pro) and <https://jetscan.jet.kim>.
`jetscan --version` prints `jetscan 0.4.0 (Pro)` for the Pro build and `jetscan 0.4.0` for
the free one.

### Building from source

```sh
cargo build --release      # target/release/jetscan(.exe)
cargo test
```

### First run

- **Double-click** `jetscan.exe` (Windows), or type `jetscan` with no arguments in a
  terminal: a numbered menu opens. No commands to learn. See [section 3](#3-the-menu-and-the-console).
- Or type a command, for example `jetscan scan .` in your project folder (`.` means "this
  folder").
- `jetscan --help` lists every command and option; `jetscan --version` shows the version.

Windows may show a SmartScreen warning for a program downloaded from the internet; this is a
general Windows behaviour for new programs, not something jetscan detects. Check the SHA256
first if you are unsure.

### Files jetscan keeps

Everything lives in one folder in your home directory, `~/.jetscan`
(`%USERPROFILE%\.jetscan` on Windows). Set `JETSCAN_HOME` to use another folder.

| File | What it is |
|---|---|
| `osv-cache/` | cached OSV answers (24 hours) |
| `license` | your license key, if you put it there |

## 3. The menu and the console

Run `jetscan` with no arguments in a terminal (or double-click it) and you get this
(free build):

```
  jetscan 0.4.0  —  security scanner
  Everything runs on this computer. Your code and files are never uploaded.

  CHECK A PROJECT
     1   Leaked secrets, vulnerable packages and risky GitHub Actions
     2   Leaked secrets only

  FIX AND TOOLS
     3   Fix what was found  (plan → preview → apply → verify)    alpha
     4   Scan this whole computer for exposed credentials
     5   License status / where to buy
     6   Connect jetscan to your AI editor (Claude Code, Cursor, VS Code…)
    12   jetscan console — type jetscan commands

  JETSCAN PRO
         jetscan Pro adds website, APK, Android, iOS and live-site checks
         https://jetscan.jet.kim

     0   Quit

  Type a number and press Enter:
```

The Pro build lists its audits under JETSCAN PRO instead (see [6](#6-jetscan-pro)).

How the menu works:

- It asks a few questions. **Enter** takes the suggested answer, **0** goes back.
- When it asks for a folder or file, you can **drag it into the window** instead of typing.
- Before running, it prints `Running: jetscan …`, and afterwards `Equivalent command:` — the
  exact command, so you can type it yourself next time or put it in a script.
- Nothing is changed in your files unless you type `yes` where the menu asks for it.
- When input is not a terminal (a pipe, CI), `jetscan` with no arguments prints the help
  instead; `jetscan menu` opens the menu explicitly.

### The items

| Item | What it does | Same as |
|---|---|---|
| 1 | Asks for the project folder, "Also check the git history?" (Enter = yes) and "Look up vulnerable packages online (OSV.dev)?" (Enter = yes; no = cache only). Then runs the full check. | `jetscan scan <folder>` (+ `--no-history`, `--offline`) |
| 2 | Asks for the folder and about git history, then looks for secrets only. Fully offline. | `jetscan secrets <folder>` |
| 3 | Makes a fix plan for the project's GitHub Actions, shows the exact diff, and writes it only if you type `yes`. See [4.7](#47-resolve-fix-what-was-found-alpha). | `jetscan resolve plan/preview/apply` |
| 4 | Scans your home folder: saved passwords and tokens, SSH keys, shell history and every git repository. Asks whether to also check packages online (Enter = no). Can take several minutes. | `jetscan machine` (+ `--deps`) |
| 5 | Shows your license: plan, expiry date, what it unlocks. | `jetscan license` |
| 6 | Prints the setup for AI editors with the full path of your jetscan filled in. If Claude Code is installed, it offers to run the setup command for you (only if you type `yes`). | see [7](#7-ai-editors-mcp) |
| 12 | The jetscan console (below). | — |
| 0 | Quit. | — |

### The console (item 12)

Item 12 opens a `jetscan>` prompt where you type jetscan commands, with or without the word
`jetscan` in front. It works in the free and the Pro build.

```
jetscan> help
  Commands (type them without "jetscan" in front, or with it):
  scan [folder]               secrets + vulnerable packages + GitHub Actions
  secrets [folder]            leaked secrets only (offline)
  deps [folder]               vulnerable packages only (OSV.dev)
  machine                     exposed credentials on this whole computer
  hook install [repo]         git pre-commit hook that blocks secrets
  license                     license key: plan, expiry, what it unlocks
  resolve plan [folder]       fix plan for GitHub Actions (alpha)
    jetscan Pro adds web, apk, android, ios and url: https://jetscan.jet.kim
    help <command> = its options (e.g. help secrets). history = this session's
    commands (sensitive values omitted). clear = clear the screen. exit = back
    to the menu.
```

Examples you can type:

```
jetscan> secrets . --no-history
jetscan> jetscan scan "C:\My Projects\app"
jetscan> deps . --offline
jetscan> help secrets
jetscan> history
```

What to know:

- Only jetscan's own commands run here. **It is not a system shell**: `dir`, `ls`, `cd` and
  the like answer `That is not a jetscan command.`
- `menu`, `console` and `mcp` are refused here (you are already in the menu).
- Paths with spaces go in "double quotes". Dragging a file or folder into the window adds
  the quotes for you.
- Built-in words: `help`, `help <command>`, `history`, `clear`, `exit` / `quit` / `0` (back
  to the menu).
- History lives only in memory until the menu closes. Lines that contain a recognised
  secret, license arguments and refused lines are shown as `[refused command]` or
  `[arguments omitted]`, never in full.
- Each run ends with `done`, `found issues (exit 1)` or `error (exit 2)`.

## 4. Free checks

All of these are free, for personal and company use, with no key. Run them in your project
folder, or give a path: `jetscan scan C:\work\app`, `jetscan scan ~/code/app`.

### 4.1 scan: everything at once

`jetscan scan [path]` runs the secret scan, the dependency check and the GitHub Actions
check, and ends with one summary. A real run on a demo project (an AWS key that was deleted
but is still in a commit, a `.env` file not ignored by git, an old `minimist`, and a workflow
that pastes a pull request title into a script):

```
$ jetscan scan .

jetscan secrets .

Not ignored by git (one `git add .` away from a leak)
  ✗ .env:1:13  Secret in environment file [medium]
      Sup3**************d-x9  fp dfcc91fb832c15bc

Only in git history (deleted from files, still in commits)
  ✗ 65f13e57eb deploy.py:2  AWS Access Key ID [high]
      AKIA************AQJD  fp 0a6287585102cc5a
  ✗ 65f13e57eb deploy.py:3  AWS Secret Access Key [high]
      vlO4****************RFJI  fp 8dbb385492dd3646

Scanned 5 files and 2 commits of git history

✗ Found 3 secrets (2 high, 1 medium) — 1 not ignored, 2 only in git history

What to do
  → Rotate every key above (revoke and reissue). Deleting it from the code is not enough —
    anyone who cloned the repo or saw a CI log still has it.
  …

jetscan deps .

  package-lock.json (npm, 1 package)

  ✗ minimist 1.2.5  1 vulnerability (1 critical)  · package-lock.json
      CRITICAL  GHSA-xvch-5gv4-984h  CVE-2021-44906  Prototype Pollution in minimist

Checked 1 package (1 fresh from OSV)

✗ Found 1 known vulnerability in 1 package (1 critical)

What to do
  → minimist 1.2.5 → 1.2.6  fixes 1 vulnerability
  → upgrade in package.json / Cargo.toml / requirements and re-run jetscan deps
Only package names and versions were sent to api.osv.dev — no code, no file paths.

GitHub Actions (workflow files: known attack patterns, checked locally)
  ✗ .github/workflows/pr-title.yml:13 — untrusted ${{ github.event.pull_request.title }} is expanded into a shell script
      pass it through env (env: VALUE: ${{ github.event.pull_request.title }}) and use "$VALUE" in the script

Summary
  Secrets           ✗ 3 secrets can leak
  Dependencies      ✗ 1 known vulnerability in 1 of 1 packages, 1 critical
  GitHub Actions    ✗ 1 pattern an attacker can exploit
```

`--html report.html` also writes one self-contained HTML page (summary, malicious packages,
masked secrets, vulnerabilities with links to osv.dev, the fix plan, install scripts and
suspicious names). It loads nothing from the network, so it opens offline and is safe to
forward. If the check was incomplete, the page says so instead of looking clean.

### 4.2 secrets: leaked keys and passwords

`jetscan secrets [path]` looks for secrets in files and in git history. It is fully offline.

**How findings are grouped** (most urgent first):

1. **Committed to git**: already in the repository, every clone has it.
2. **Not ignored by git**: not committed yet, but one `git add .` away.
3. **Only in git history**: deleted from the files, still in an old commit.
4. **Local only**: the file is in `.gitignore`. Listed, but not counted as a leak and never
   fails `--exit-code`.

**What you see.** Never the full secret: only a mask (`AKIA************AQJD`) and a
fingerprint (`fp 0a6287585102cc5a`, the first 16 hex characters of a SHA-256). Text from
scanned files is cleaned before it reaches your terminal, so a file cannot inject terminal
control codes.

**What it detects**: AWS, GitHub, GitLab, Slack (tokens and webhooks), Stripe, Google API,
OpenAI, Anthropic, Hugging Face, Groq, Replicate, Perplexity, xAI, npm, PyPI, Telegram,
Resend, SendGrid, Twilio, Mailgun, Discord, Shopify and DigitalOcean keys; private keys (PEM/PGP); passwords in URLs; sensitive
keys in `.env`, `.npmrc`, `.pypirc`, `.git-credentials`, `.docker/config.json`; stored
passwords in credential files such as `.netrc` and `.pgpass` and FTP/SFTP client configs.

Useful options:

| Option | What it does |
|---|---|
| `--no-history` | skip git history (faster) |
| `--staged` | check only staged changes, what the next commit adds (used by the hook) |
| `--verify` | ask each key's own provider whether it still works (network, see below) |
| `--max-size <KB>` | skip files larger than this (default 1024) |
| `--exit-code` | exit 1 if a secret can leak (see [5](#5-reading-the-results)) |
| `--json` | machine-readable output |

**Is the key still live? (`--verify`)** Off by default, because it is network traffic. For
each key jetscan sends one read-only "who am I" request to that key's own provider (GitHub
`/user`, OpenAI `/v1/models`, Slack `auth.test`, …) and marks the finding `LIVE` or
`revoked`. The key is passed to curl through standard input (never on the command line), over
https, without redirects, only to that provider's allow-listed host. A `401` from GitLab or
Mailgun is reported as "unknown", because the key may belong to a self-hosted GitLab or an EU
Mailgun account. Supported: GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, npm, Telegram,
SendGrid, Mailgun, Discord, Resend, Hugging Face, Groq, xAI, Replicate. Not verified (there is
no harmless way, or a key pair is needed): AWS, Twilio, Shopify, Google, PyPI, Slack webhooks,
private keys.

**What to do with a found secret.** Revoke it and create a new one at the provider
**first**. Deleting the line does not help: anyone who cloned the repository or saw a CI log
still has the old value. Then move the new value out of the code (environment variable,
secret store) and, for a shared repository, consider rewriting history (git filter-repo /
BFG) as cleanup.

**False positives.** Two ways to silence a finding that is not a real secret:

```
# .jetscanignore  (in the folder you scan; # starts a comment)
dfcc91fb832c15bc        # one specific secret, wherever it is
rule:url-credentials    # a whole rule
testdata/               # a folder (path prefix)
tests/fixture.env       # one file
```

Or put `jetscan:ignore` on the line itself, for example in a comment:
`token = "…"  # jetscan:ignore`. The report then says how many were suppressed:

```
Scanned 6 files
1 suppressed by .jetscanignore

✓ No secrets found
```

### 4.3 deps: vulnerable and malicious packages

`jetscan deps [path]` reads your lockfiles and checks every exact version against OSV.dev.

| Ecosystem | Lockfiles |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5, v6, v9) |
| crates.io (Rust) | `Cargo.lock` |
| Go | `go.mod` (with `replace`) |
| PyPI (Python) | `requirements*.txt` (exact `==` pins), `poetry.lock`, `Pipfile.lock`, `uv.lock` |

- A lockfile that cannot be parsed is reported as **not checked**, never as clean. Local,
  path, git and workspace packages are skipped (they are not in any advisory database).
- For every vulnerable package you get **one version that fixes everything it can**:
  `→ minimist 1.2.5 → 1.2.6  fixes 1 vulnerability`.
- **Malicious packages** (known malware, `MAL-…` ids and advisories tagged CWE-506) get
  their own section. Upgrading does not help: remove the package and treat a machine that
  installed it as compromised.
- **Install scripts**: packages that run commands during `npm install` are listed with
  their exact commands. **Suspicious names** that look like a popular package
  (typosquatting) are listed too.

**`--fix`** prints a fix plan: the exact commands. Nothing is run or edited.

```
Fix plan (nothing is run or edited — review and apply yourself)
  package-lock.json
    minimist 1.2.5 → 1.2.6
      $ npm install minimist@1.2.6
```

A direct dependency gets `npm install x@1.2.3` (or `yarn add` / `pnpm add`); a transitive
one gets an `overrides` / `resolutions` / `pnpm.overrides` entry. Rust: `cargo update -p x
--precise …`; Go: `go get …`; Python: poetry / uv / pipenv or the pin to edit.

**Network, cache, offline.** Only package names and versions go to `api.osv.dev`. Answers
are cached in `~/.jetscan/osv-cache` for 24 hours.

| Option | What it does |
|---|---|
| `--offline` | use only the cache, send nothing |
| `--no-cache` | ask OSV again even if the cache is fresh |
| `--fail-on <severity>` | with `--exit-code`: fail only on `critical`, `high`, `medium` or `low` (default) and worse |

If OSV cannot be reached, older cache is used and the report says how old it is. Packages
with no data are listed as **not checked**, and an incomplete scan never looks clean:

```
$ jetscan deps . --offline --exit-code      (empty cache)

  package-lock.json (npm, 1 package)

Checked 0 packages
! 1 package NOT checked (offline, not in cache) — results are incomplete
                                                        (exit code 2)
```

A proxy is taken from `HTTPS_PROXY`.

**SBOM** (`--sbom cyclonedx` or `--sbom spdx`, CycloneDX 1.6 / SPDX 2.3) is part of jetscan
Teams, see [8](#8-ci-github-actions-and-others).

### 4.4 GitHub Actions checks

`jetscan scan` also reads `.github/workflows/*.yml` and a composite `action.yml`, fully
locally. These are facts about the file, not style advice:

| Check | Level | What it means |
|---|---|---|
| `gha-script-injection` | exploitable | untrusted text (`${{ github.head_ref }}`, a PR or issue title/body, a commit message…) is pasted into a `run:` script (or `github-script`) before the shell starts, so a branch named `$(curl …\|sh)` runs as code |
| `gha-pwn-request` | exploitable | a `pull_request_target` / `workflow_run` workflow (it has secrets and a write token) checks out the PR's code and so runs a stranger's code |
| `gha-insecure-commands` | exploitable | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` re-enables `set-env` / `add-path` |
| `gha-unpinned-action` | harden | a third-party action on a tag or branch; whoever controls the tag can change what runs |
| `gha-write-all-permissions` | harden | `permissions: write-all` |

Exploitable findings are marked `✗` and fail `--exit-code`; harden findings are marked `!`
and do not:

```
GitHub Actions (workflow files: known attack patterns, checked locally)
  ! .github/workflows/lint.yml:8 — third-party action tj-actions/changed-files@v45 is pinned to a mutable tag or branch
      pin it to a full commit SHA: tj-actions/changed-files@<40-hex sha> # v45
  ! .github/workflows/write-all.yml:5 — workflow or job grants write-all permissions
      grant only what the job needs, e.g. permissions: { contents: read }
```

A job that a fork cannot start (for example `if: github.event.pull_request.head.repo.full_name
== github.repository`, or a Dependabot-only job) is not reported. A workflow file that the
built-in YAML reader does not fully understand (anchors, tabs, multi-line flow collections) is
skipped rather than guessed at.

### 4.5 machine: your whole computer

`jetscan machine` looks through your home folder:

- **Credential stores** in plain text: `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`,
  `~/.netrc`, `~/.docker/config.json`, `~/.cargo/credentials.toml`, `~/.kube/config`,
  `~/.aws/credentials` and others.
- **SSH private keys without a passphrase** (the key file is parsed, not guessed from its
  header), and on Linux/macOS keys readable by other users.
- **Shell history** files.
- **Every git repository** under your home folder (`--depth <N>` controls how deep to look,
  default 6), with the normal secret scan.
- `--deps` also checks the packages of every repository (network: OSV).

Real output on a test home folder:

```
jetscan machine D:\demo-home

Credential stores (plaintext files on disk)
  ✗ ~/.git-credentials:1:14  GitHub Token [high]
      ghp_****************076c  fp 28c69bdebcfd6d90
  ✗ ~/.npmrc:1:34  npm Token [high]
      npm_****************gvr1  fp 38caced5d1e2e6fb
…
Machine hygiene (how keys and tokens are stored — values are never shown)
  ✗ ~/.git-credentials:1 — Git credentials are stored unencrypted; validity was not checked.
      Run git config --global credential.helper manager, then remove ~/.git-credentials and authenticate again.
  ✗ ~/.npmrc:1 — npm credentials are stored unencrypted; validity was not checked.
      Remove the literal credential; use an environment reference such as ${NPM_TOKEN}, supplied by a secret store.
  ✗ ~/.ssh/id_ed25519 — SSH private key is stored without passphrase encryption.
      Set a passphrase with ssh-keygen -p -f "$HOME\.ssh\id_ed25519"; use ssh-agent for convenience.
```

`${ENV}` references and placeholders are not reported. `--sarif` is not available for
`machine`.

### 4.6 hook: stop secrets before they are committed

```
$ jetscan hook install
✓ pre-commit hook installed: .\.git\hooks\pre-commit
  every `git commit` now checks the staged changes for secrets

$ jetscan hook uninstall
✓ pre-commit hook removed: .\.git\hooks\pre-commit
```

Run it inside a repository (or give the repository path: `jetscan hook install <repo>`).
Every `git commit` then runs `jetscan secrets --staged` and stops the commit if it adds a
secret. A secret caught before the commit never needs to be rotated. An existing
`pre-commit` hook that is not jetscan's is never overwritten: you get the line to add to it
instead. To skip the check once: `git commit --no-verify`.

### 4.7 resolve: fix what was found (alpha)

Resolve turns findings into a fix plan that you check before anything changes. It is local,
sends nothing, never runs a shell, package manager or git, and writes only after
`--confirm`. It is marked **alpha**: output and exit codes may still change.

```sh
jetscan resolve plan . --out jetscan-plan.json   # 1. read-only: make the plan
jetscan resolve preview jetscan-plan.json        # 2. read-only: the exact diff
jetscan resolve apply jetscan-plan.json --confirm  # 3. the only step that writes
jetscan resolve verify jetscan-plan.json         # 4. re-run the check per finding
```

The preview of the demo project:

```
A reviewed recipe (gha-run-env-v1) covers this finding; see the file patch below.
--- a/.github/workflows/pr-title.yml
+++ b/.github/workflows/pr-title.yml
@@ -9,8 +9,10 @@
     runs-on: ubuntu-latest
     steps:
       - name: Check the title format
+        env:
+          PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}
         run: |
-          title="${{ github.event.pull_request.title }}"
+          title="${PULL_REQUEST_TITLE}"
…
Nothing was changed. To write exactly this diff: jetscan resolve apply jetscan-plan.json --confirm
```

**What can be fixed automatically today:** exactly one kind of edit. Untrusted text in a
GitHub Actions `run:` script (`gha-script-injection`) is moved into an environment variable,
and only when the edit can be proven safe for that file. If not, the plan says why
(`echo ${{ … }}` without quotes, `eval`, `bash -c`, `$GITHUB_ENV`, command substitution,
a PowerShell runner, unusual YAML, …) and gives manual steps.

Everything else gets **advice, not an edit**:

- Leaked keys: revoke and rotate first, then move the value out of the code; history
  rewrite is optional cleanup. `verify` says `credential_revocation_cannot_be_checked_locally`.
- Dependency advisories: points to `jetscan deps --fix`.
- `permissions: write-all`: review only, because only you know what each job needs.
- Findings of jetscan Pro: advice only.

How `apply` protects your files: it runs only from the project the plan was made for (or
`--root` naming it); it refuses a file that changed since the plan; it writes all files or
none and restores everything if something fails; only `.github/workflows/*.yml|*.yaml` can
be patched; links and junctions are refused. The plan file is treated as untrusted input
and checked again on import and on apply. After `apply` the state is "applied, not
verified" until you run `verify`.

`verify` reports per finding: `verified_specific_issue`, `still_present` or `unknown`. It
speaks only about the findings in the plan, never "your project is secure".

You can also start from a Findings V2 report: `jetscan resolve plan report-v2.json --root
<project> --out plan.json`.

Exit codes:

| Command | 0 | 1 | 2 |
|---|---|---|---|
| plan | plan written/printed | — | bad input, `--out` file exists |
| preview | shown | — | plan invalid or a file changed |
| apply | applied, already applied, or nothing to apply | rolled back / failed | no `--confirm`, other project, file changed, invalid plan |
| verify | every finding verified | a finding is still present | anything unknown |

"Input coverage is partial" in the plan is honest, not an error: the GitHub Actions check
does not report whether it could read every file, so a plan built from it never claims to
cover everything.

## 5. Reading the results

### Symbols and colors

`✗` (red) needs fixing, `!` (yellow) is a weak spot, a warning or an incomplete check, `✓`
(green) is clean, `→` is advice. Colors appear only in a terminal and never when `NO_COLOR`
is set.

### Severity and confidence

These are two different questions:

- **Severity**: how bad is it *if it is real*? `critical`, `high`, `medium`, `low`, `info`.
- **Confidence**: how sure is jetscan that it *is* real?

In the free checks:

- **Secrets** show one level in brackets, `[high]` / `[medium]` / `[low]`. It says how
  sure the rule is that this is a real secret: an `AKIA…` key with the right shape is
  `high`; a value next to a word like `PASSWORD` in a `.env` file is `medium`. (In `--json`
  this field is called `confidence`.)
- **Vulnerabilities** use the advisory's severity (`CRITICAL`, `HIGH`, …), computed from
  its CVSS score. An advisory without a score is `unknown` and always fails `--exit-code`.
- **GitHub Actions** findings are `exploitable` (✗) or `harden` (!).

The jetscan Pro audits (and Findings V2 JSON) show both, for example
`HIGH [potential] <rule>` or `MEDIUM [confirmed] <rule>`:

| Confidence | Meaning |
|---|---|
| `confirmed` | jetscan saw the fact itself (for example: a header is missing from a response) |
| `potential` | the pattern matches, but something jetscan cannot see may change it (for example: a setting made outside the files jetscan reads) |
| `needs_review` | a pointer for a human: it may be on purpose (a public entry point, public data) |

### Checks: completed, partial, skipped

The jetscan Pro reports list every check that did not fully run (`Checks not fully run:`),
each with a status and the reason:

- `completed`: the check ran on everything it should.
- `partial`: it ran, but not on everything (a value could not be resolved, a limit was hit).
- `skipped`: it did not run, and the reason says why (not applicable, not in this mode).
- `error`: it failed.

The free checks say the same thing in words: `git history was NOT checked`, `1 package NOT
checked … results are incomplete`, `No lockfiles found — nothing was checked`.

### Limitations

Every Pro report ends with **Limitations**: what this kind of check cannot see (for example
"static analysis only: nothing was built or executed", "headers were checked on one page").
Read them. **No findings never means "secure"**: it means these rules found nothing in what
jetscan could read.

### Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `scan`, `secrets`, `deps`, `machine` **without** `--exit-code` | finished (findings or not) | — | error: bad arguments, a Teams flag without a key |
| the same **with** `--exit-code` | nothing to fix | something needs fixing: a secret that can leak (not `.gitignore`d ones), a known vulnerability (respecting `--fail-on`), a malicious package, an exploitable workflow, a high-level machine hygiene issue | incomplete: some packages could not be checked |
| Pro `web source`, `apk`, `android`, `ios`, `url` with `--exit-code` | no critical/high finding and every check ran | a critical or high finding | a check did not fully run (and no critical/high finding); also any error or a missing key |
| `license` | shown | — | a key is present but not accepted |
| `resolve …` | see [4.7](#47-resolve-fix-what-was-found-alpha) | | |

### JSON output

- `--json` on `scan`, `secrets`, `deps`, `machine` prints a stable machine-readable report
  with `"version": 1` (stable ordering, stable fingerprints, no full secrets).
- The Pro commands print **Findings V2** JSON with `--json` (`schema_version: 2`): every
  finding has `rule_id`, `severity`, `confidence`, a location, a masked excerpt, and the
  report has `checks` (with status and reason), `limitations` and the network activity.
  `web source`, `apk`, `android` and `ios` also accept `--json-v2` as another name for it.
- Status and errors go to stderr, so stdout stays a clean JSON document.

### Suppressing false positives

| Finding from | How to silence it |
|---|---|
| secrets (files, history, machine) | its fingerprint, `rule:<id>` or a path in `.jetscanignore`; or `jetscan:ignore` on the line |
| Pro web source, Android, iOS | `jetscan:ignore` on the line |
| vulnerabilities | `--fail-on high` to fail only on serious ones; or a baseline (Teams) |
| GitHub Actions, everything in an old project | a baseline: `--write-baseline` / `--baseline` (Teams, see [8](#8-ci-github-actions-and-others)) |

Malicious packages are never hidden by a baseline.

## 6. jetscan Pro

jetscan Pro is a separate build of jetscan with audits for websites and mobile apps. It
includes everything in the free build. The Pro audits are alpha: rules, output and exit codes
may still change. jetscan Pro is closed source: its code is not in this repository.

- `jetscan web source [path]`: the source of a Next.js or Vite React project. Privileged keys
  in client code, secrets in `NEXT_PUBLIC_` / `VITE_` variables, state-changing route handlers
  and Server Actions without a visible access check, non-constant HTML in DOM sinks, Supabase
  service-role keys the browser can see, CORS with credentials for any origin, public source
  maps.
- `jetscan apk <file.apk>`: an Android APK, without installing or running it. Debuggable
  builds, exported components, backup and cleartext settings, permissions, keys in resources
  and DEX strings.
- `jetscan android [path]` and `jetscan ios [path]`: Android (Gradle, Kotlin / Java) and iOS
  (Xcode, Swift / Objective-C) source projects. Manifest, plist and entitlement settings,
  signing files and passwords in the repository, provider keys, trust-all TLS, risky web
  views, weak cryptography, secrets in logs.
- `jetscan url <https://site>`: a passive check of a published website — only the requests a
  browser makes, to that site only: security headers, cookie flags, exposed `.git` / `.env`,
  public source maps, server-side keys in its JavaScript.
- The same audits as tools for AI editors (`jetscan mcp`) and in the menu.

The source and APK audits run on your machine and send nothing; the URL check talks only to
the site you name. A clean result means these rules found nothing, not that the app is
secure. Pro findings show both severity and confidence (see
[Severity and confidence](#severity-and-confidence)).

### Plans

| Key | Unlocks |
|---|---|
| Free trial | one audit of your choice (website source, APK, Android or iOS), 2 scans |
| jetscan Pro (personal, yearly) | every Pro audit, including the URL check |
| One-time audit (30 days) | every Pro audit, for one project |
| jetscan Teams | every Pro audit and the CI reports (`--sarif`, `--sbom`, `--baseline`) |

Teams is for one organization, up to 20 developers: $499 the first year, then $990 / year.
Prices of the other plans and the trial: <https://jetscan.jet.kim>.

### Getting and installing a key

1. Get a key at <https://jetscan.jet.kim> (crypto, via Cryptomus). It comes by email; renewals
   and a copy of the key are in your account there.
2. Put it in the environment variable `JETSCAN_LICENSE` (in CI, as a secret) or in the file
   `~/.jetscan/license` (`%USERPROFILE%\.jetscan\license` on Windows).
3. Check it with `jetscan license`.

The key is a signed text (organization, plan, expiry date). jetscan checks the signature
**on your machine**: no account, no activation, no network, so it works in an air-gapped CI.
`jetscan license` shows the plan, the expiry date and what the key unlocks, and never prints
the key:

```
$ jetscan license
jetscan Free — no license key (JETSCAN_LICENSE or ~/.jetscan/license).
Every free scan works without a key. Pro scans (web source, live website URL, APK, Android, iOS) need jetscan Pro, a one-time audit or a free trial (one scanner, a few scans); --sarif, --sbom and --baseline need jetscan Teams.
Pro, trial and Teams: https://jetscan.jet.kim
```

Thirty days before the expiry date of a yearly key jetscan starts warning on stderr; after
it, the paid features keep working for 14 more days, then stop. Scans without them keep
working. Honest limits of an offline key: it cannot be revoked before its date (keys are
issued for a year, not forever), and moving the system clock back extends it. This is a
trust model, on purpose, not DRM.

In the free build a Pro command says where it comes from, and scans nothing:

```
$ jetscan apk app.apk

✗ Error  `apk` is part of jetscan Pro: a static audit of Android APK files (manifest flags, exported components, cleartext traffic, embedded keys; nothing is installed or run). Get it at https://jetscan.jet.kim
```

## 7. AI editors (MCP)

`jetscan mcp` lets AI coding tools such as Claude Code, Cursor, VS Code (Copilot) and Devin
Desktop (formerly Windsurf) run jetscan's checks themselves, for example right after they
write code. It is a Model Context Protocol server on stdio: the editor starts `jetscan mcp`
and talks to it.

The easiest setup: **menu item 6** prints the commands and config files with the full path of
your jetscan already filled in.

### Claude Code

```sh
claude mcp add jetscan -- jetscan mcp                  # this project only
claude mcp add --scope user jetscan -- jetscan mcp     # every project
claude mcp list                                        # check it
```

Tested with a real Claude Code (2.1.323) on Windows. Start a new session; `/mcp` lists
jetscan.

### Cursor

Save as `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "jetscan": {
      "type": "stdio",
      "command": "jetscan",
      "args": ["mcp", "--root", "${workspaceFolder}"]
    }
  }
}
```

### VS Code (Copilot)

Save as `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "jetscan": {
      "type": "stdio",
      "command": "jetscan",
      "args": ["mcp", "--root", "${workspaceFolder}"]
    }
  }
}
```

If the file already exists, add only the `"jetscan"` entry. Then restart the editor or reload
its MCP servers. The Cursor and VS Code configs follow those editors' documentation but have
not been tested against them yet. If `jetscan` is not on your `PATH`, put its full path in
`"command"` (on Windows with double backslashes, `"C:\\Tools\\jetscan.exe"`). More editors
and details: [docs/mcp/README.md](../mcp/README.md).

### What the AI gets

| Tool | What it does | Plan |
|---|---|---|
| `scan_secrets` | leaked secrets in files and (by default) git history | free |
| `scan_dependencies` | vulnerable or malicious locked packages; **offline by default** (cache only), `offline: false` sends names + versions to OSV | free |
| `scan_github_actions` | the GitHub Actions checks | free |
| `resolve_plan` | a fix plan and diff preview; **never changes files** | free |
| the jetscan Pro audits | website source, APK, Android and iOS source audits and a passive live-website check | the jetscan Pro build + a Pro, one-time audit or Teams key, or a free trial for one audit |

Every tool is read-only and none applies a fix: the AI shows you the diff and applying it is
your call. Without a key, a Pro tool returns a short notice instead of scanning.

### Privacy with AI editors

- jetscan uploads nothing. **The AI tool, however, sends tool results to its own model**,
  like any text it reads. That is why secret values never appear in tool results, not even
  masked: only the rule, the location and the fingerprint.
- The tools read only inside the workspace (the `--root` folders, or the project folder).
  A path outside it, a link pointing outside it, a home folder or a whole drive is refused.

### Troubleshooting

- Logs go to stderr: `jetscan mcp 0.4.0: serving on stdio, workspace <folder>`. Most editors
  show it in their MCP logs.
- `refused: … is outside the workspace` → start the server in the project or add
  `--root <project>`.
- `refused: … is your home folder or a whole drive` → the editor started jetscan in your
  home folder; add `--root <project>`.
- `deps.osv: partial … offline` → `scan_dependencies` used only the cache. Ask the AI to call
  it with `offline: false` (this sends package names and versions to api.osv.dev).

## 8. CI (GitHub Actions and others)

Every check, `--exit-code`, `--json` and `--html` are free in CI too.

```sh
jetscan scan . --exit-code   # 0 clean · 1 something to fix · 2 incomplete
```

A GitHub Actions job that scans on every push and pull request, and nightly (a new advisory
for a package you already use then fails the scheduled run):

```yaml
name: jetscan
on:
  push:
  pull_request:
  schedule:
    - cron: "0 6 * * *"
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0          # full history: secrets that were committed and deleted
      - run: curl -fsSL https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.sh | sh && echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - run: jetscan scan . --fail-on high --exit-code
```

Tips:

- `fetch-depth: 0` matters: with the default shallow clone, history is not there to scan.
- Exit code 2 (OSV unreachable, some packages not checked) fails the job too: an incomplete
  scan is not a pass. Use `--offline` only with a cache you trust.
- `--fail-on high` fails only on high and critical vulnerabilities. Malicious packages,
  leaked secrets and vulnerabilities of unknown severity always fail.
- Pin actions to a commit SHA in your own workflows (jetscan's own check will remind you).

### jetscan Teams in CI: SARIF, SBOM, baseline

These need a **Teams** key in `JETSCAN_LICENSE` (store it as a CI secret):

| Option | What it does |
|---|---|
| `--sarif` | SARIF 2.1.0 for GitHub / GitLab code scanning (not for `machine`). Only actionable findings, masked secrets, `security-severity` for GitHub's levels. |
| `--sbom cyclonedx` / `--sbom spdx` | `deps`: a software bill of materials (CycloneDX 1.6 / SPDX 2.3, deterministic) for audits and the EU Cyber Resilience Act |
| `--write-baseline <file>` | save today's findings as a baseline (no secrets in it, only keys such as fingerprints and advisory ids) |
| `--baseline <file>` | show and fail only on findings that are **not** in the baseline |

An old project with known debt: record what is there once, commit the file, fail only on new
problems:

```sh
jetscan scan . --write-baseline jetscan-baseline.json   # once; commit this file
jetscan scan . --baseline jetscan-baseline.json --exit-code
```

A vulnerability stays "known" after an upgrade that did not fix it; a secret stays known
wherever it moves. Malicious packages are never hidden by a baseline. The report always says
how many known findings were hidden.

The full job with Teams reports:

```yaml
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - run: curl -fsSL https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.sh | sh && echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - run: jetscan scan . --baseline jetscan-baseline.json --fail-on high --exit-code --sarif > jetscan.sarif
        env:
          JETSCAN_LICENSE: ${{ secrets.JETSCAN_LICENSE }}
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: jetscan.sarif
```

Without a Teams key these flags stop with a clear message (exit 2) and nothing else changes:

```
✗ Error  --sarif is part of jetscan Teams (CI reports: --sarif, --sbom, --baseline). Get a key at https://jetscan.jet.kim and put it in JETSCAN_LICENSE (a CI secret) or ~/.jetscan/license; it is checked on this machine, nothing is sent. Without --sarif, every scan stays free
```

The install script installs the free build. The Pro audits in CI need the Pro build from your
account; it has no public install script.

## 9. Troubleshooting and FAQ

**Is my code uploaded anywhere?** No. Secret scanning, the GitHub Actions check, machine,
resolve and the Pro source and APK audits send nothing. The dependency check sends only
package names and versions to api.osv.dev (`--offline`: nothing). License keys are checked
offline. See the table in [section 1](#1-what-jetscan-is).

**I see `←[32m` or similar garbage instead of colors.** Your console does not support
colors and jetscan could not switch them on. Set `NO_COLOR=1` (PowerShell:
`$env:NO_COLOR = "1"`; cmd: `set NO_COLOR=1`), or use Windows Terminal. jetscan only prints
colors to a terminal, never into files or pipes.

**Saving JSON or SARIF on Windows.** In Windows PowerShell 5.1, `>` re-encodes a program's
output as UTF-16, which some tools cannot read. Use PowerShell 7, or
`cmd /c "jetscan scan . --json > report.json"`, or the `--html` option for a report file.

**A path with spaces does not work.** Put it in double quotes:
`jetscan scan "C:\My Projects\app"`. In the menu and the console, dragging the folder into the
window adds the quotes for you.

**`jetscan` is not found after installing.** Open a new terminal (the installer changed
`PATH`). On macOS/Linux check that `~/.local/bin` is on your `PATH`.

**Behind a proxy.** Set `HTTPS_PROXY` (for example
`HTTPS_PROXY=http://proxy.example:8080`) for the dependency check.

**Offline or air-gapped.** `jetscan secrets`, machine, the GitHub Actions check and the Pro
source/APK audits need no network at all. For dependencies, run once online to fill the
cache, then use `--offline`; packages not in the cache are listed as **not checked** and
`--exit-code` returns 2. License keys work offline.

**"not a git repository — git history was not scanned".** The folder is not a git repository
(or git is not installed). Files are still scanned; install git to check history. In CI use
`fetch-depth: 0`.

**Git history is slow on a huge repository.** Use `--no-history` for a quick look, and keep
history scanning for CI or the pre-commit hook (which checks only staged changes).

**A finding is wrong (false positive).** See [Suppressing false positives](#suppressing-false-positives).

**"Your jetscan Pro trial covers the apk scan only".** A trial unlocks one audit area. Other
Pro checks, including the URL check, need a paid plan.

**My license expired.** Yearly keys (Pro, Teams) keep working for 14 more days after the
expiry date, with a warning; then the paid features stop. One-time audit and trial keys stop
on the date. **Free scans always keep working.** Renew at <https://jetscan.jet.kim> and
replace the key. A key is checked against your computer's clock.

**"license key not accepted".** The key text is damaged (copy it again without line breaks
or extra characters) or it is not a jetscan key. A key for a plan this version does not know
asks you to update jetscan.

**`--sarif` says it is part of jetscan Teams although I have a Pro key.** Correct: the CI
reports are only in Teams. A Pro, audit or trial key unlocks the Pro scans.

**The Pro command says it is part of jetscan Pro although I have a key.** You are running
the free build. Install the Pro build from your account (`jetscan --version` must say
`(Pro)`).

**Does jetscan work in a company for free?** Yes. Using the free part at work, in a company
of any size, is allowed by its license. Teams is what lets an organization use the Teams
features.

## 10. Glossary

| Term | In one line |
|---|---|
| Advisory | A published notice that a package version has a vulnerability, with the versions that fix it. |
| Anon / publishable key | A key meant to be public (Supabase anon key, Stripe publishable key); not a leak by itself. |
| APK | The file an Android app is installed from. |
| ATS (App Transport Security) | The iOS setting that forces apps to use HTTPS. |
| Baseline | A file with today's known findings, so CI fails only on new ones (Teams). |
| Clickjacking | Loading your page in an invisible frame to trick users into clicking it. |
| Confidence | How sure jetscan is that a finding is real: confirmed, potential, needs_review. |
| CORS | Browser rules for which other websites may read your site's responses. |
| CSP (Content-Security-Policy) | A header that limits what scripts a page may load and run; the main browser defence against XSS. |
| CVE | A public id for a known vulnerability, such as CVE-2021-44906. |
| CVSS | A 0–10 score of how severe a vulnerability is. |
| CWE | A public id for a type of weakness, such as CWE-79 (XSS). |
| CycloneDX / SPDX | The two standard SBOM formats. |
| DAST | Testing a running application from outside, by sending requests. |
| DEX | The compiled code inside an APK. |
| Entitlements | iOS app permissions and capabilities declared at build time. |
| Exit code | The number a program returns: 0 fine, 1 found something, 2 incomplete or error. |
| Fingerprint | A 16-character hash that identifies a secret without revealing it. |
| GHSA | A GitHub Security Advisory id, such as GHSA-xvch-5gv4-984h. |
| Git history | All old versions of the files in a repository, including deleted ones. |
| HSTS | A header that tells browsers to use only HTTPS for a site. |
| Keystore | The file with an Android app's signing key. |
| Lockfile | The file that records the exact versions of every installed package. |
| Malicious package | A package published on purpose to steal or damage, not just buggy. |
| MCP (Model Context Protocol) | The standard way AI editors call external tools. |
| nosniff | `X-Content-Type-Options: nosniff`, stops browsers from guessing file types. |
| OSV / OSV.dev | The free open database of vulnerabilities that jetscan checks packages against. |
| Pre-commit hook | A script git runs before every commit; jetscan's blocks secrets. |
| Prompt injection | Text that tricks an AI into doing something its user did not ask for. |
| `pull_request_target` | A GitHub Actions trigger that runs with secrets even for pull requests from forks. |
| R8 | The Android tool that shrinks and obfuscates release code. |
| Referrer-Policy | A header that controls how much of your URL is sent to other sites. |
| Permissions-Policy | A header that limits browser features (camera, microphone…) a page may use. |
| Rotate a key | Revoke the old key and create a new one at the provider. |
| SARIF | A standard JSON format for scanner results, read by GitHub / GitLab code scanning. |
| SBOM | A software bill of materials: the list of every package in your product. |
| Server Action | A Next.js function that runs on the server when a form or button calls it. |
| Service-role key | A Supabase key with full access to the database; must never reach the browser. |
| Severity | How bad a finding is if it is real: critical, high, medium, low, info. |
| SHA-256 / SHA256SUMS | A file checksum, and the list of checksums used to verify a download. |
| Source map | A file that maps minified browser code back to the original source. |
| `security.txt` | A file that tells security researchers how to report a problem. |
| Typosquatting | A package named like a popular one (`lodahs`) to catch typos. |
| WebView | An embedded browser inside a mobile app. |
| XSS (cross-site scripting) | Getting a site to run an attacker's script in a visitor's browser. |
