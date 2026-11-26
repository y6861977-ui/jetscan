# jetscan Pro on deliberately vulnerable apps

Training apps whose authors publish the list of vulnerabilities they planted. That list is the
answer key, and it was not written by us. We ran jetscan on each app and checked every listed
item by hand: found, partly found, or missed. Script: `bench/vuln-apps.sh`.

**Version:** jetscan 0.4.0 (Pro), default settings. Run on 2026-11-23, Windows 11. Nothing from the
apps was built, installed or run.

**Read with care.** The author of jetscan did the scoring, so the "found / partly / missed" calls
are ours. The rule: an item counts as **found** only when a jetscan finding points at the planted
flaw itself, not only at the component it lives in. Pointing at the right component with the
wrong reason (for example "exported provider" for a path traversal inside that provider) is
**partly**.

## Summary

| App | Platform | Planted (author's list) | Found | Partly | Missed | Cannot be found statically |
|---|---|---|---|---|---|---|
| [OVAA](https://github.com/oversecured/ovaa) | Android source | 18 | 14 | 2 | 2 | 0 |
| [DIVA](https://github.com/payatu/diva-android) | Android source | 13 | 13 | 0 | 0 | 0 |
| [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) | Android source + APK | 25 | 14 | 0 | 6 | 5 |
| [DVIA-v2](https://github.com/prateek147/DVIA-v2) | iOS source | 15 | 6 | 0 | 2 | 7 |
| [OopsSec Store](https://github.com/kOaDT/oss-oopssec-store) | Next.js | 38 | 21 | 0 | 17 | — |
| **Total** | | **109** | **68** | **2** | **27** | **12** |

The table is the third re-run of 2026-11-24 (see "Re-runs" below). History: 2026-11-23 — 20
found, 7 partly; 2026-11-24 — 27, then 38, then 68.

In short: **jetscan now finds 68 of 109 planted flaws (62%)**, 70% of the 97 a static tool can
see at all.

**This number is no longer a blind test.** Most checks added on 2026-11-24 were written after
reading these five apps, so the score above says "jetscan can find these patterns", not "jetscan
finds 62% of what a real app hides". Two things keep it honest: every new check was run on real
open-source projects before it was kept (results under each re-run), and the next measurement
should use vulnerable apps we have not looked at (for example InjuredAndroid, AndroGoat, Damn
Vulnerable Bank, DVNA, VAmPI). It is good at configuration: manifests, Info.plist,
public environment variables and known CVEs in dependencies. It is weak at code: insecure storage,
SQL built from strings, hardcoded crypto keys, WebViews loading user input, weak password hashes.
It raised no false alarms on these apps beyond two low "needs review" notes on MD5 inside a
vendored crypto library (DVIA-v2).

Most of OopsSec Store's 38 are logic flaws (authorization, CSRF, race conditions, prompt
injection) that no pattern scanner finds without running the app. About 11 of them have a clear
pattern in the code; jetscan found 4 of those 11.

## Where jetscan is strong

- Exported Android components, backup, debuggable builds, cleartext HTTP defaults (DIVA access
  control 1–3, InsecureBankv2 activities, provider, receiver, backup, HTTP, debuggable in the APK).
- iOS App Transport Security off, UIWebView, URL schemes (DVIA-v2 network, WebView, IPC).
- Credentials in resources: `https://adm1n:…@dev.victim.com` in OVAA's `strings.xml`.
- `setAllowFileAccessFromFileURLs(true)` (OVAA 4), passwords in `Log.d` by variable name
  (InsecureBankv2), `MODE_WORLD_READABLE`, passwords in SharedPreferences.
- Next.js: a secret in a `NEXT_PUBLIC_` variable, `dangerouslySetInnerHTML` / `innerHTML` with
  non-constant HTML (two XSS challenges), and React2Shell through the dependency check
  (`next 15.2.2`, GHSA-9qr9-h5gf-34mp).

## Re-runs

### 2026-11-24, first: six gaps closed (secrets and web)

Three checks in `jetscan secrets` (free, every command that scans for secrets uses them) and three
in `jetscan web source` (Pro):

| Check | Command | Gap | New finds in the five apps |
|---|---|---|---|
| `hardcoded-crypto-key`: a string passed as the key to `createHmac`, `jwt.sign`/`verify`, `SecretKeySpec`, `hmac.new`, ... | free | 2 | Juice Shop HMAC key (not scored) |
| `fallback-secret`: `process.env.JWT_SECRET \|\| "secret"`, `os.getenv("SECRET_KEY", "…")`, Laravel `env()` | free | 3 | OopsSec weak JWT secret |
| `hardcoded-password-check` (low confidence): `password == "…"` | free | 6 | DVIA-v2 ×2 (in categories scored as runtime-only, so not counted) |
| `WEB-SQL-011`: SQL built from strings in `$queryRawUnsafe`, `sequelize.query`, `db.query`, ... | Pro | 1 | OopsSec ×4 SQL injection; Juice Shop login and search |
| `WEB-HASH-012`: MD5 / SHA-1 / SHA-256 near password handling | Pro | 4 | OopsSec weak MD5 |
| `WEB-XXE-013`: libxmljs `noent: true` | Pro | 5 | OopsSec XXE |

Gap 6 is only partly closed: DIVA's `hckey…equals("vendorsecretkey")` and InsecureBankv2's
`username.equals("devadmin")` have no password word in the name and are still missed.

**False alarms.** On the ten popular repositories of `bench/README.md` the three free checks add
**0** findings (the first draft added 16: FastAPI documentation, Laravel settings, a Flask test;
they now skip documentation files, assertions and settings named like `PASSWORD_BROKER`). On six
real Next.js projects (vercel/commerce, shadcn-ui/taxonomy, vercel/nextjs-subscription-payments,
excalidraw, dub `apps/web`, cal.com `apps/web` + `packages`) the web checks add 3 findings, all SQL
really built from strings (a dev script truncating tables by name, a Salesforce query built from an
email domain, `sql.raw` of a JSON path), plus one `low` where the values are parameters.

### 2026-11-24, second: Android and iOS (gaps 7–12)

| Check | Rule | New finds in the five apps |
|---|---|---|
| SQL built from strings in `rawQuery` / `execSQL` (DML only; `Meta.TABLE_NAME` constants and `String.format` with constants are not findings) | `ANDROID-SQL-015` (new) | DIVA input validation 1, DIVA storage 2 |
| Password or card column in a plain SQLite table | `ANDROID-STORAGE-013` | DIVA storage 2 |
| Files on shared external storage (one per file) | `ANDROID-STORAGE-013` | DIVA storage 4, InsecureBankv2 SD card |
| `loadUrl` with a URL from input or an intent; `file://` from shared storage with JavaScript on | `ANDROID-WEBVIEW-010` | DIVA input validation 2, InsecureBankv2 WebView, OVAA 4 |
| FileProvider `<root-path>` | `ANDROID-EXPORT-001` | OVAA 16 |
| `createPackageContext(…, CONTEXT_IGNORE_SECURITY)`, `DexClassLoader` reading shared storage | `ANDROID-CODELOAD-016` (new) | OVAA 15, OVAA 18 |
| `host.endsWith("example.com")` / `getHost().contains(…)` | `ANDROID-HOSTCHECK-017` (new) | OVAA 3 |
| Password saved to a plain Core Data / Realm / Couchbase / YapDatabase / SQLite store or plist file (one per file) | `IOS-STORAGE-006` | DVIA-v2 local data storage (all five stores); iGoat-Swift Yap exercise |

Not closed: DIVA storage 3 (a temp file in the app's own folder), DIVA insecure logging (the log
message names a card, the variable does not), DIVA hardcoding 1 and InsecureBankv2's `devadmin`
(no password word in the name), native C code (DIVA hardcoding 2, input validation 3).

**False alarms on real apps.** Android sources of NewPipe, Aegis, AntennaPod and Nextcloud: 0 new
findings in Aegis; in NewPipe 4 "shared external storage" notes (low, needs review: a download app
that writes there on purpose); in AntennaPod 5 and in Nextcloud 4 `ANDROID-SQL-015` findings, all
SQL really built from strings — mostly database migrations, and one real bug class in AntennaPod
(`"…WHERE file_url='" + fileUrl + "'"`: a path with an apostrophe breaks the query). The first
draft of the SQL check gave 27 findings in AntennaPod alone (class-qualified constants and DDL in
migrations); that was fixed before this run. Also flagged and kept: AntennaPod `<root-path
path=".">` (medium) and Nextcloud `<root-path path="/storage/">` (low), plus two Nextcloud editors
that load an intent extra into a WebView (low, the activity may not be exported). iOS sources of
NetNewsWire, mastodon-ios and wikipedia-ios (2 400+ Swift files): **0** new findings.

### 2026-11-24, third: the ceiling pass

Web (`jetscan web source`, Pro), new rules `WEB-REDIRECT-014` … `WEB-CRYPTO-021`:

| Check | OopsSec challenge |
|---|---|
| Redirect to a URL from the query, no same-origin check | open-redirect |
| `readFile` / `writeFile` with a path joined from the request, no `basename` / `..` check | path-traversal |
| Server-side `fetch` of a URL from the body or query, no host allowlist; fixed `https://host/…` is not a finding | server-side-request-forgery |
| `Math.random()` for a token, a linear congruential generator in code | insecure-randomness-gift-card |
| Stack trace in a response object (not in a log call, not behind a production check) | information-disclosure-api-error |
| `data: body` / `{ ...body }` into a database write; `role` / `isAdmin` from the body | mass-assignment |
| SVG in an upload allowlist | malicious-file-upload |
| JWT algorithm read from the token header; `"none"` allowed; AES-CBC decrypt without a MAC | jwt-algorithm-confusion, aes-cbc-padding-oracle |

Also counted now: middleware-authorization-bypass, which the dependency check already reports
(CVE-2025-29927 in `next 15.2.2`), the same way React2Shell was counted.

Android (`jetscan android`, Pro), new rules `ANDROID-INTENT-018`, `ANDROID-BACKDOOR-019`,
`ANDROID-NATIVE-020`, and additions to existing ones:

| Check | Planted flaw |
|---|---|
| Implicit intent (`new Intent("x.ACTION")`, or `setAction`) that carries credentials, no `setPackage` | OVAA 7, 8; InsecureBankv2 intent sniffing |
| `Intent` from `getParcelableExtra` started as is | OVAA 5 |
| `setResult(code, data)` with the `onActivityResult` intent; `data.getData()` used without a scheme check | OVAA 2, 6 |
| `new File(dir, uri.getLastPathSegment())` in a provider | OVAA 12 |
| Serializable `readObject` that deletes files or runs code | OVAA 9 |
| `SecretKeySpec` from a string constant (one `getBytes` hop) | OVAA 14; InsecureBankv2 weak crypto, hardcoded secrets, local encryption |
| `x.getText()…equals("…")`, `username.equals("…")` | DIVA hardcoding 1; InsecureBankv2 developer backdoor |
| Credentials written with `FileWriter`; log message labelled "credit card" / "password" with a value | DIVA storage 3, insecure logging |
| C/C++ files: `strcpy` / `strcat` / `sprintf` / `gets`, `#define …KEY "…"` | DIVA hardcoding 2, input validation 3 |
| Password `EditText` without a password input type | (none here: InsecureBankv2 masks with `android:password`) |

iOS (`jetscan ios`, Pro) and the free secrets rules:

| Check | Planted flaw |
|---|---|
| Logging an object that was given a password field (`print("\(user)")` after `user["password"] = …`) | DVIA-v2 side-channel leakage |
| `RNEncryptor` / `RNDecryptor` `password:` and CryptoSwift `AES(key:)` with a string (free `hardcoded-crypto-key`) | DVIA-v2 broken cryptography |

Still missed: OVAA 10, 11 (memory corruption); InsecureBankv2 weak authorization, pasteboard,
keyboard cache, parameter manipulation, username enumeration, weak change password; DVIA-v2
excessive permissions, phishing; 17 OopsSec challenges that are logic or runtime flaws (BOLA,
IDOR, CSRF, race conditions, brute force, prompt injection, session fixation, insecure password
reset, client-side price, broken function-level authorization, malicious MCP server, exposed
MCP config and git repository, typosquat package and AI rules file left as inert lab artifacts).

**False alarms on real projects (this pass).** Web: 0 new findings in vercel/commerce, taxonomy,
nextjs-subscription-payments, excalidraw and dub; 1 in cal.com (an API key made with
`Math.random()` in a settings component). The first draft of these web rules gave about 40 on
the same projects (redirects to the app's own paths, browser-side fetches, `data: input` after
schema validation, stack traces logged or behind a production check, migration SQL); all were
fixed before this run. Android: 0 new findings in NewPipe, Aegis, AntennaPod and Nextcloud from
the rules of this pass. iOS: 0 new in NetNewsWire, mastodon-ios, wikipedia-ios. Free secrets:
0 new on the ten repositories of `bench/README.md`.

Totals against jetscan 0.4.0 on the real projects, all passes of 2026-11-24 together: web +2
(dub), +5 (cal.com); Android +4 (NewPipe, shared-storage notes), +6 (AntennaPod), +15
(Nextcloud: 4 SQL from strings, 7 shared-storage notes, 2 WebView intent extras, 1 root-path,
1 password column); iOS +0. Each is a review pointer (most `low` / `needs_review`), described
under the earlier re-runs.

## Gaps, ordered by how cheap they are to close

Each of these is a token pattern, the kind of check jetscan already does, not data-flow analysis.

| # | Pattern jetscan misses | Seen in |
|---|---|---|
| 1 | Raw SQL built from strings: `$queryRawUnsafe(…)`, `rawQuery("…" + x)`, `execSQL("…" + x)` | OopsSec ×4 (SQLi challenges), DIVA input validation 1 / storage 2 |
| 2 | Hardcoded key passed to crypto: `new SecretKeySpec(KEY.getBytes(), …)` with a literal `KEY`, `createHmac('sha256', '<literal>')` | OVAA 14, InsecureBankv2 crypto, Juice Shop HMAC key |
| 3 | Fallback secret: `process.env.JWT_SECRET \|\| "secret"` | OopsSec weak JWT secret |
| 4 | Fast hash for passwords in JS/TS: `createHash("md5")` near password code (exists for iOS, not web) | OopsSec weak MD5 |
| 5 | XML parser with entities on: `noent: true` (libxmljs) | OopsSec XXE |
| 6 | Secret compared to a literal: `.equals("vendorsecretkey")`, `password == "This!sA5Ecret"`, `username.equals("devadmin")` | DIVA hardcoding 1, DVIA-v2, InsecureBankv2 backdoor |
| 7 | Files on external storage / temp files with user data: `getExternalStorageDirectory()`, `File.createTempFile` | DIVA storage 3–4, InsecureBankv2 SD card |
| 8 | WebView loading input or file:// with JavaScript on: `loadUrl(x.getText()…)`, `loadUrl("file://" + …)` + `setJavaScriptEnabled(true)` | DIVA input validation 2, InsecureBankv2 WebView |
| 9 | FileProvider `<root-path>` | OVAA 16 |
| 10 | Loading other apps' code: `createPackageContext(…, CONTEXT_IGNORE_SECURITY)`, `DexClassLoader` from a writable path | OVAA 15, 18 |
| 11 | Weak host check: `getHost().endsWith("example.com")` | OVAA 3 |
| 12 | iOS insecure storage: passwords in UserDefaults, plists, Core Data, Realm; Keychain without an accessibility class | DVIA-v2 local data storage |
| 13 | Native C code (`strcpy`, keys in `.c` files) is not scanned | DIVA hardcoding 2, input validation 3 |

Gaps 1–12 were worked on 2026-11-24 (see "Re-runs"); gap 6 and 13 remain open.

## Per app

### OVAA (18)

| # | Planted flaw (author's wording, shortened) | jetscan |
|---|---|---|
| 1 | Arbitrary `login_url` via deep link | partly: deep-link activity listed as an entry point (INFO) |
| 2 | Content providers with `grantUriPermissions` reached via deep link | missed |
| 3 | Weak host validation in the WebView deep link | missed |
| 4 | WebView `setAllowFileAccessFromFileURLs(true)` | **found** |
| 5 | Intent redirection via `redirect_intent` in LoginActivity | partly: LoginActivity exported |
| 6 | File theft via `ACTION_PICK` result | missed |
| 7 | Broadcast with credentials | missed |
| 8 | Activity launch with encrypted token in the URL | missed |
| 9 | File deletion via `DeleteFilesSerializable` | missed |
| 10 | Memory corruption via Parcelable | missed |
| 11 | Memory corruption via Serializable | missed |
| 12 | Path traversal in `TheftOverwriteProvider` | partly: provider exported |
| 13 | Logs via `InsecureLoggerService`; credentials in `Log.d` | partly: service exported; the log line missed |
| 14 | Hardcoded AES key in `WeakCrypto` | partly: `Cipher.getInstance("AES")` (ECB) flagged; the key missed |
| 15 | Code execution from other apps in `OversecuredApplication` | missed |
| 16 | FileProvider shares `root` | missed |
| 17 | Credentials in `strings.xml` `test_url` | **found** (CRITICAL) |
| 18 | DEX loaded from a world-writable directory | missed |

### DIVA (13)

Found: insecure data storage 1 (SharedPreferences), access control 1, 2 and 3 (exported
activities, exported provider). Missed: insecure logging (`Log.e` with a card number), hardcoding
1 (`equals("vendorsecretkey")`), insecure data storage 2–4 (SQLite, temp file, external storage),
input validation 1 (SQL built from input), 2 (WebView `loadUrl` of input), 3 and hardcoding 2
(native C code, not scanned).

### InsecureBankv2 (25)

Five items need the app running and cannot be found by any static tool: root detection, emulator
detection, application patching, sensitive data in memory, runtime manipulation.

Found: flawed broadcast receiver (exported), vulnerable activity components, insecure content
provider, insecure logging (`Log.d` with username and password), debuggable (APK), backup,
insecure HTTP. Partly: local encryption (`MODE_WORLD_READABLE` found, hardcoded key missed),
intent sniffing (exported components only). Missed: weak authorization, insecure WebView, weak
cryptography (hardcoded key, zero IV), pasteboard, keyboard cache, SD card storage, parameter
manipulation, hardcoded secrets, username enumeration, developer backdoor (`devadmin`), weak
change password.

### DVIA-v2 (15)

Seven categories need the app running: jailbreak detection, runtime manipulation, anti
hooking/debugging, binary protection, Touch/Face ID bypass, application patching, sensitive data in
memory. Found: network layer security (ATS off), WebView issues (UIWebView), IPC (URL schemes, as
INFO). Missed: local data storage, excessive permissions, phishing, side-channel leakage, broken
cryptography. Noise: two LOW "MD5 near password" notes inside the vendored RNCryptor library.

### OopsSec Store (38)

Found: public env variable (`NEXT_PUBLIC_PAYMENT_SECRET`), XSS and self-XSS
(`dangerouslySetInnerHTML` / `innerHTML`), React2Shell (dependency check); since 2026-11-24 also
the four SQL injection challenges (`$queryRawUnsafe`, WEB-SQL-011), weak MD5 hashing (`hashMD5(password)`,
WEB-HASH-012), weak JWT secret (`|| "secret"`, `fallback-secret`) and XXE (`noent: true`, WEB-XXE-013). The MCP token challenge hides the token by string
concatenation, so no secret scanner can be expected to find it in source. The other 27 are logic
and runtime flaws.

### Not scored

- iGoat-Swift: no numbered answer key. jetscan reported 8 findings, including the password in
  `Credentials.plist`, ATS off, and two private keys in its test server folder.
- Juice Shop (secrets only): the RSA private key in `lib/insecurity.ts` is found; the HMAC key
  literal on line 42 of the same file was missed on 2026-11-23 and is found since 2026-11-24
  (`hardcoded-crypto-key`).
