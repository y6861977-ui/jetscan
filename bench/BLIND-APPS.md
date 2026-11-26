# jetscan on vulnerable apps it had never seen (blind test)

`bench/VULN-APPS.md` stopped being a fair test once checks were written against its five apps.
This page measures four other training apps that nobody on the project had looked at, in this
order: write the answer key from each project's own documentation, then run jetscan, then score.
The blind number below was written down before any rule was changed and is not edited since.

**Version:** jetscan main `4745e02` (0.4.0 plus the 2026-11-24 rules), Pro, default settings.
Run on 2026-11-24, Windows 11. Nothing from the apps was built, installed or run. Script:
`bench/blind-apps.sh`.

**Scoring** is the same as in `bench/VULN-APPS.md`: an item is **found** only when a finding
points at the planted flaw itself; pointing at the right component for another reason is
**partly**. The author of jetscan did the scoring.

## Answer key

Written from documentation only, before any scan:

| App | Commit | Source of the key | Items | Runtime-only |
|---|---|---|---|---|
| [AndroGoat](https://github.com/satishpatnayak/AndroGoat) (Android, Kotlin) | `77996f2` | README, "All vulnerabilities covered" | 33 | 6: root, emulator, two pinning bypasses, Firebase server rules, binary patching |
| [InjuredAndroid](https://github.com/B3nac/InjuredAndroid) (Android) | `2cc669a` | `InjuredAndroid-FlagWalkthroughs.md`, 18 flags | 18 | 4: Frida hook, open Firebase endpoint, rooted file access, Flutter SSL bypass |
| [Damn Vulnerable Bank](https://github.com/rewanthtammana/Damn-vulnerable-Bank) (Android + Node API) | `5136c34` | README spoiler list (checked items) and guide | 8 | 2: root/emulator detection, anti-debugging |
| [DVNA](https://github.com/appsecco/dvna) (Node.js, Express) | `9ba473a` | `docs/solution` (OWASP Top 10 2017 + 2 from 2013) | 19 | 1: insufficient logging (an absence, not code) |
| **Total** | | | **78** | **13** |

## Blind result

| App | Found | Partly | Missed | Runtime-only |
|---|---|---|---|---|
| AndroGoat | 14 | 1 | 12 | 6 |
| InjuredAndroid | 3 | 3 | 8 | 4 |
| Damn Vulnerable Bank | 3 | 2 | 1 | 2 |
| DVNA | 3 | 0 | 15 | 1 |
| **Total** | **23 (29%)** | **6** | **36** | **13** |

**Blind: 23 of 78 planted flaws (29%), 35% of the 65 a static tool can see.** This is the number
to quote for what jetscan finds in code it was not tuned on. The 68/109 of `bench/VULN-APPS.md` is
not a blind number.

What the blind run found: exported components, backup, cleartext and user-CA network configs,
the WebView file-access flags, AWS keys in code, plain-text SharedPreferences and SQLite
passwords, temp files with credentials, an unmasked password field, logcat leakage of a token,
intent redirection, SQL injection, XXE and an open redirect in DVNA.

What it missed, by kind:
- **The value reaches the sink through a variable** (`val qry = "…" + name.text; rawQuery(qry)`,
  `Log.i(tag, logMessage)` with the password in `logMessage`, `loadUrl(getToken)`).
- **Kotlin syntax:** `post == "F1ag_0n3"`, `x.text`, `val k: String = "…"`.
- **Express apps:** command injection, `eval` of the request, node-serialize, a hardcoded session
  secret, unescaped EJS output (`<%- %>`), DOM XSS in an EJS script, `X-Powered-By`, Sequelize
  query logging, and a known-vulnerable `mathjs` that was invisible because the project has no
  lockfile.
- **Patterns with no rule yet:** HTML built from input in `loadData`, the clipboard, XOR "encryption"
  with a constant key, biometrics without a `CryptoObject`, MD5 for a PIN.
- **Logic, Flutter/Dart, binaries:** not visible to a pattern scanner.

Noise in the blind run: 5 findings in the vendored `public/assets/jquery-3.2.1.min.js` of DVNA
(2 `WEB-RANDOM-017`, 3 `WEB-XSS-003`).

## After tuning (not blind)

The gaps above were closed with general checks, not with app-specific strings, then all four apps
were scanned again. **This is not a blind number any more**, it shows what the new checks reach.

| App | Found | Partly | Missed | Runtime-only |
|---|---|---|---|---|
| AndroGoat | 23 | 1 | 3 | 6 |
| InjuredAndroid | 5 | 3 | 6 | 4 |
| Damn Vulnerable Bank | 6 | 0 | 0 | 2 |
| DVNA | 12 | 0 | 6 | 1 |
| **Total** | **46 (59%)** | **4** | **15** | **13** |

What was added:

| Check | Where | Blind items it reaches |
|---|---|---|
| A value assigned earlier in the file: SQL (`rawQuery(qry)`), log messages, `loadUrl(url)`, file writes | `ANDROID-SQL-015`, `-LOG-014`, `-WEBVIEW-010`, `-STORAGE-013` | AndroGoat 7, 9, 11; DVBank 7 |
| Kotlin `==`, `.text`, typed constants; comparisons with `getString(R.string.…)` | `ANDROID-BACKDOOR-019` | AndroGoat 19; InjuredAndroid 1, 3 |
| `loadData` / `loadDataWithBaseURL` of HTML that carries input (or writes an input's value itself) with JavaScript on | `ANDROID-WEBVIEW-010` | AndroGoat 10, 13 |
| A password, card number or one-time code put on the clipboard (not when marked `EXTRA_IS_SENSITIVE`) | `ANDROID-STORAGE-013` | AndroGoat 18 |
| XOR with a repeating key used as encryption (Java and JavaScript) | `ANDROID-CRYPTO-012`, `WEB-CRYPTO-021` | DVBank 3, 4 |
| `BiometricPrompt.authenticate` without a `CryptoObject`; MD5 next to a PIN | `ANDROID-CRYPTO-012` | AndroGoat 30, 33 |
| Shell commands, `eval`, `vm.run*`, `math.eval`, node-serialize `unserialize` with request data | `WEB-EXEC-022` (new) | DVNA 2, 15 |
| Hardcoded `session` / `cookieSession` / `cookieParser` / `expressJwt` secret | `WEB-CRYPTO-021` | DVNA 4 |
| Raw output in `.ejs` / `.hbs` / `.pug` templates; `innerHTML` in template scripts | `WEB-XSS-003` | DVNA 12, 13, 14 |
| Express without `disable('x-powered-by')` / helmet; `new Sequelize` without `logging` | `WEB-ERROR-018` | DVNA 6, 11 |
| `package.json` exact versions when no npm lockfile covers the folder (free) | `jetscan deps` | DVNA 16 (mathjs 3.10.1); node-serialize 0.0.4 too |
| Minified and vendored files (`*.min.js`, `vendor/`, `jquery…`) are skipped by the web code rules | web | removes the blind-run noise |

Still missed: AndroGoat 4 (a game score trusted from SharedPreferences), 20 (an AI key in no
provider's format), 27 (debuggable only in the published APK, not in the source); InjuredAndroid
4 (a base64-decoded flag), 7, 8 (the AWS keys are not in the repository), 10 (Unicode case
collision), 14 and 15 (Flutter / native); DVNA 3, 5, 8, 9, 17 (logic: password reset, data
exposure, access control, CSRF) and 10 (a stack trace from the framework at runtime).

## False alarms of the new checks

Before/after on the same real projects as `bench/VULN-APPS.md`:

| Project | 4745e02 | now | New findings |
|---|---|---|---|
| vercel/commerce, taxonomy, nextjs-subscription-payments, excalidraw, dub, cal.com (web) | 2, 0, 5, 8, 14, 21 | same | 0 |
| NewPipe (Android) | 14 | 15 | 1 low: `loadUrl` of an intent extra in the reCAPTCHA activity |
| Aegis | 3 | 3 | 0 (it marks copied codes `EXTRA_IS_SENSITIVE`) |
| AntennaPod | 26 | 30 | 4 `ANDROID-SQL-015`: SQL built from strings in a variable, as the inline rule already reports |
| Nextcloud | 40 | 40 | 0 |
| NetNewsWire, mastodon-ios, wikipedia-ios | 10, 2, 13 | same | 0 |
| The 5 apps of `bench/VULN-APPS.md` | 68 of 109 | 68 of 109 | no regression (Juice Shop: −15 findings in a vendored `dat.gui.min.js`, +9 `cookieParser('kekse')` secrets) |

The first draft of the Android checks added 13 findings on these projects (a `TAG` constant read
as a token, Aegis' own biometric wrapper and its clipboard, HTML built from app resources); all
were fixed before the numbers above.

`jetscan deps` with the `package.json` fallback: on the ten repositories of `bench/README.md` it
adds one source, express (no lockfile; 8 exact dev-dependency pins), with one real advisory
(`hbs 4.4.0`). Projects with a lockfile are unchanged.
