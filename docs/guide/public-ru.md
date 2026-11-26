# Справочник jetscan

Этот справочник описывает бесплатный jetscan 0.5.0 и коротко — jetscan Pro. Каждая команда,
опция и сообщение ниже сверены с самой программой. Примеры вывода — настоящие запуски на
маленьких демо-проектах, сокращённые там, где стоит `…`. Сама программа пишет по-английски,
поэтому вывод оставлен как есть. Если справочник и `jetscan --help` расходятся, верьте
`--help` и сообщите нам.

Открыть справочник можно в любой момент: `jetscan guide` (пункт меню 13). Он откроется в
браузере, без интернета, и покажет, что открывает ваш тариф. См.
[Справочник в браузере](#справочник-в-браузере-пункт-13).

Читать можно подряд или сразу нужный раздел. Незнакомые слова объяснены в
[словаре](#10-словарь-терминов).

<!-- toc -->
- [1. Что такое jetscan](#1-что-такое-jetscan)
- [2. Установка и первый запуск](#2-установка-и-первый-запуск)
- [3. Меню и консоль](#3-меню-и-консоль)
- [4. Бесплатные проверки](#4-бесплатные-проверки)
- [5. Как читать результаты](#5-как-читать-результаты)
- [6. jetscan Pro](#6-jetscan-pro)
- [7. ИИ-редакторы (MCP)](#7-ии-редакторы-mcp)
- [8. CI (GitHub Actions и другие)](#8-ci-github-actions-и-другие)
- [9. Проблемы и частые вопросы](#9-проблемы-и-частые-вопросы)
- [10. Словарь терминов](#10-словарь-терминов)
<!-- /toc -->

## 1. Что такое jetscan

jetscan — сканер безопасности, который работает **на вашем компьютере**. Он ищет проблемы, у
которых есть точный ответ:

- **Утёкшие секреты**: API-ключи, токены, приватные ключи и пароли в файлах и в истории git
  (в том числе ключи, которые давно удалили, но они остались в старых коммитах).
- **Известные уязвимости** в пакетах проекта (по открытой базе OSV.dev) и пакеты, которые
  известны как вредоносные.
- **Опасные workflow GitHub Actions**, которыми посторонний может воспользоваться через
  pull request.
- **Весь компьютер**: токены в открытом виде, SSH-ключи без пароля, секреты в истории
  командной строки, все репозитории в домашней папке.
- В **jetscan Pro** (отдельная сборка): исходный код сайтов (Next.js / Vite React), файлы
  Android APK, исходники Android и iOS и пассивная проверка живого сайта.

jetscan не оценивает стиль кода и не гадает. Он сообщает факты, которые может показать:
файл, строку, правило и что делать.

### Ваш код остаётся на вашем компьютере

jetscan никогда не загружает ваш код, ничего не отправляет на сервер jetscan и не требует
аккаунта. Телеметрии нет. Несколько проверок пользуются сетью — и только так:

| Что вы запускаете | Что уходит в сеть |
|---|---|
| `jetscan secrets`, `machine`, `hook`, проверка GitHub Actions, `resolve`, меню | ничего |
| `jetscan deps` и часть `jetscan scan` про зависимости | **имена и версии** пакетов на `api.osv.dev` (никогда не код, не пути, не имя проекта). `--offline` не отправляет ничего. Ответы кэшируются на 24 часа. |
| `jetscan secrets --verify` (по умолчанию выключено) | каждый найденный ключ уходит **только к своему провайдеру** (токен GitHub — в GitHub) одним запросом «кто я» только на чтение |
| `jetscan machine --deps` | то же, что `jetscan deps`, для каждого репозитория |
| `jetscan mcp` (ИИ-редакторы) | по умолчанию ничего; проверка зависимостей идёт в сеть, только если ИИ попросит `offline: false` |
| Pro: `web source`, `apk`, `android`, `ios` | ничего |
| Pro: `url <сайт>` | только те запросы, что делает браузер, **только к этому сайту** |
| Ключи лицензии (`jetscan license`, Pro, Teams) | ничего: ключ проверяется на вашем компьютере |

jetscan нужны две стандартные программы: **git** (читать историю и знать, какие файлы
закоммичены) и **curl** (для всех сетевых запросов выше). curl есть в Windows 10 и новее, в
macOS и в большинстве дистрибутивов Linux. Без git jetscan всё равно проверяет файлы и прямо
пишет, что история не проверялась.

## 2. Установка и первый запуск

jetscan — один маленький файл без среды выполнения и без зависимостей. Права администратора
не нужны.

### Windows

Откройте PowerShell и выполните:

```powershell
irm https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.ps1 | iex
```

Скрипт скачивает последний релиз, сверяет его с файлом `SHA256SUMS` релиза, при
несовпадении отказывается ставить, кладёт `jetscan.exe` в `%LOCALAPPDATA%\jetscan\bin` и
добавляет эту папку в пользовательский `PATH`. После этого откройте **новый** терминал, чтобы
`PATH` обновился.

### macOS и Linux

```sh
curl -fsSL https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.sh | sh
```

Ставит в `~/.local/bin/jetscan`, тоже после проверки `SHA256SUMS`. Проверьте, что
`~/.local/bin` есть в `PATH`. Поддерживаются Linux x64 и arm64 (статические сборки), macOS на
Apple silicon и Intel.

Настройки обоих установщиков (переменные окружения):

| Переменная | Что значит |
|---|---|
| `JETSCAN_VERSION` | поставить конкретную версию, например `JETSCAN_VERSION=v0.5.0` (по умолчанию — последнюю) |
| `JETSCAN_INSTALL_DIR` | только macOS/Linux: куда положить файл (по умолчанию `~/.local/bin`) |

### Ручная загрузка и проверка SHA256

На странице релизов `github.com/y6861977-ui/jetscan` у каждого релиза есть архив для каждой
системы и файл `SHA256SUMS`:

| Система | Архив |
|---|---|
| Windows x64 | `jetscan-<версия>-x86_64-pc-windows-msvc.zip` |
| Linux x64 | `jetscan-<версия>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `jetscan-<версия>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon | `jetscan-<версия>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `jetscan-<версия>-x86_64-apple-darwin.tar.gz` |

Сравните SHA-256 архива с его строкой в `SHA256SUMS`:

```powershell
# Windows (PowerShell)
Get-FileHash .\jetscan-v0.5.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

```sh
# Linux
sha256sum -c SHA256SUMS --ignore-missing
# macOS
shasum -a 256 jetscan-v0.5.0-aarch64-apple-darwin.tar.gz
```

Если значения отличаются — не запускайте файл.

### Сборка jetscan Pro

jetscan Pro — **отдельная сборка с закрытым кодом** (бесплатная сборка не умеет
Pro-проверки даже с ключом). См. [6. jetscan Pro](#6-jetscan-pro) и <https://jetscan.jet.kim>.
`jetscan --version` у Pro-сборки печатает `jetscan 0.5.0 (Pro)`, у бесплатной —
`jetscan 0.5.0`.

### Сборка из исходников

```sh
cargo build --release      # target/release/jetscan(.exe)
cargo test
```

### Первый запуск

- **Дважды щёлкните** `jetscan.exe` (Windows) или наберите `jetscan` без аргументов в
  терминале — откроется меню с номерами. Команды учить не нужно. См.
  [раздел 3](#3-меню-и-консоль).
- Или наберите команду, например `jetscan scan .` в папке проекта (`.` значит «эта папка»).
- `jetscan --help` — все команды и опции; `jetscan --version` — версия.
- `jetscan guide` — этот справочник в браузере (без интернета).

Windows может показать предупреждение SmartScreen для программы из интернета: так Windows
ведёт себя с любыми новыми программами, это не находка jetscan. Если сомневаетесь, сначала
проверьте SHA256.

### Какие файлы хранит jetscan

Всё лежит в одной папке в домашнем каталоге: `~/.jetscan` (в Windows
`%USERPROFILE%\.jetscan`). Другую папку можно задать через `JETSCAN_HOME`.

| Файл | Что это |
|---|---|
| `osv-cache/` | кэш ответов OSV (24 часа) |
| `license` | ваш ключ лицензии, если вы положили его сюда |
| `guide/` | страница, которую открывает `jetscan guide` (каждый раз заново) |

## 3. Меню и консоль

Запустите `jetscan` без аргументов в терминале (или двойным щелчком) — увидите
(бесплатная сборка):

```
  jetscan 0.5.0  —  security scanner
  Everything runs on this computer. Your code and files are never uploaded.
  New here? 13 opens the guide in your browser.

  CHECK A PROJECT
     1   Leaked secrets, vulnerable packages and risky GitHub Actions
     2   Leaked secrets only

  FIX AND TOOLS
     3   Fix what was found  (plan → preview → apply → verify)    alpha
     4   Scan this whole computer for exposed credentials
     5   License status / where to buy
     6   Connect jetscan to your AI editor (Claude Code, Cursor, VS Code…)
    12   jetscan console — type jetscan commands
    13   User guide — opens in your browser, works offline

  JETSCAN PRO
         jetscan Pro adds website, APK, Android, iOS and live-site checks
         https://jetscan.jet.kim

     0   Quit

  Type a number and press Enter:
```

В Pro-сборке в блоке JETSCAN PRO вместо этого — её аудиты (см. [6](#6-jetscan-pro)).

Как устроено меню:

- Оно задаёт несколько вопросов. **Enter** — предложенный ответ, **0** — назад.
- Когда нужна папка или файл, их можно **перетащить в окно** вместо набора пути.
- Перед запуском меню пишет `Running: jetscan …`, после — `Equivalent command:`: точную
  команду, чтобы в следующий раз набрать её самому или вставить в скрипт.
- В ваших файлах ничего не меняется, пока вы не наберёте `yes` там, где меню об этом просит.
- Если ввод — не терминал (конвейер, CI), `jetscan` без аргументов печатает справку;
  `jetscan menu` открывает меню явно.

### Пункты

| Пункт | Что делает | То же, что |
|---|---|---|
| 1 | Спрашивает папку проекта, «Also check the git history?» (Enter = да) и «Look up vulnerable packages online (OSV.dev)?» (Enter = да; нет = только кэш). Затем полная проверка. | `jetscan scan <папка>` (+ `--no-history`, `--offline`) |
| 2 | Спрашивает папку и про историю git, ищет только секреты. Полностью без сети. | `jetscan secrets <папка>` |
| 3 | Строит план исправлений для GitHub Actions проекта, показывает точный diff и записывает его, только если набрать `yes`. См. [4.7](#47-resolve-исправить-найденное-alpha). | `jetscan resolve plan/preview/apply` |
| 4 | Проверяет домашнюю папку: сохранённые пароли и токены, SSH-ключи, историю командной строки и все git-репозитории. Спрашивает, проверять ли ещё пакеты онлайн (Enter = нет). Может занять несколько минут. | `jetscan machine` (+ `--deps`) |
| 5 | Показывает лицензию: тариф, срок, что открывает. | `jetscan license` |
| 6 | Печатает настройку для ИИ-редакторов с полным путём к вашему jetscan. Если установлен Claude Code, предлагает выполнить команду настройки сам (только если набрать `yes`). | см. [7](#7-ии-редакторы-mcp) |
| 12 | Консоль jetscan (ниже). | — |
| 13 | Открывает этот справочник в браузере (ниже). | `jetscan guide` |
| 0 | Выход. | — |

### Консоль (пункт 12)

Пункт 12 открывает строку `jetscan>`, где набирают команды jetscan — со словом `jetscan`
впереди или без него. Работает и в бесплатной, и в Pro-сборке.

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
  guide                       the full user guide in your browser (offline)
    jetscan Pro adds web, apk, android, ios and url: https://jetscan.jet.kim

    help <command> = its options (e.g. help secrets). guide = the full user
    guide in your browser. history = this session's commands (sensitive values
    omitted). clear = clear the screen. exit = back to the menu.
```

Что можно набрать:

```
jetscan> secrets . --no-history
jetscan> jetscan scan "C:\My Projects\app"
jetscan> deps . --offline
jetscan> help secrets
jetscan> guide --lang ru
jetscan> history
```

Что важно знать:

- Здесь работают только команды jetscan. **Это не системная оболочка**: `dir`, `ls`, `cd` и
  подобные получают ответ `That is not a jetscan command.` и
  `` Only jetscan commands work here: `help` lists them, `guide` explains. ``
- `menu`, `console` и `mcp` здесь запрещены (вы уже в меню).
- Пути с пробелами — в "двойных кавычках". Если перетащить файл или папку в окно, кавычки
  добавятся сами.
- Встроенные слова: `help`, `help <команда>`, `history`, `clear`, `exit` / `quit` / `0`
  (назад в меню). `guide` открывает этот справочник, как пункт 13.
- История хранится только в памяти до закрытия меню. Строки с распознанным секретом,
  аргументы лицензии и отвергнутые строки показываются как `[refused command]` или
  `[arguments omitted]`, никогда целиком.
- Каждый запуск заканчивается словами `done`, `found issues (exit 1)` или `error (exit 2)`.

### Справочник в браузере (пункт 13)

`jetscan guide` (или `jetscan instructions`, `jetscan docs`, или пункт меню 13) открывает
этот справочник одной страницей в браузере. Справочник встроен в jetscan: он работает без
интернета, и ничего никуда не отправляется.

```
jetscan guide [--lang en|ru] [--no-open]
```

Страница собирается под тариф на этом компьютере. Вверху — рамка **Ваш тариф**: название
(Бесплатный, Пробный, Разовый аудит, Pro или Teams), что он открывает, до какого числа
действует и сколько пробных сканов осталось. Главы, которые ваш тариф не открывает,
сокращены до пары строк: что это и что нужно, чтобы открыть. Ключ и счётчик пробы только
читаются.

Страница сохраняется в `~/.jetscan/guide/jetscan-guide-<версия>-<язык>.html` (каждый раз
заново), путь печатается всегда:

```
Guide for your plan (Free) opened: C:\Users\you\.jetscan\guide\jetscan-guide-0.5.0-ru.html
```

- **Язык**: `--lang ru` или `--lang en`. Без него — русский, если `LC_ALL`, `LC_MESSAGES` или
  `LANG` (первая заданная) начинается с `ru`, иначе английский. В Windows эти переменные
  обычно не заданы, поэтому там пишите `--lang ru`.
- **Без браузера**: с `--no-open`, если задана `JETSCAN_NO_OPEN` или вывод идёт не в
  терминал (конвейер, CI), jetscan только сохраняет страницу, печатает путь и пишет
  `Open that file in any web browser`. То же — если браузер не удалось запустить.
- Браузер запускается со страницей как единственным аргументом (`explorer.exe` в Windows,
  `open` в macOS, `xdg-open` в Linux с рабочим столом), никогда через оболочку.

## 4. Бесплатные проверки

Всё это бесплатно — и для себя, и в компании, без ключа. Запускайте в папке проекта или
укажите путь: `jetscan scan C:\work\app`, `jetscan scan ~/code/app`.

### 4.1 scan: всё сразу

`jetscan scan [путь]` запускает поиск секретов, проверку зависимостей и проверку GitHub
Actions и заканчивает одной сводкой. Настоящий запуск на демо-проекте (AWS-ключ, который
удалили, но он остался в коммите; файл `.env`, не исключённый из git; старый `minimist`; и
workflow, который вставляет заголовок pull request в скрипт):

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

`--html report.html` дополнительно пишет одну самодостаточную HTML-страницу (сводка,
вредоносные пакеты, замаскированные секреты, уязвимости со ссылками на osv.dev, план
исправлений, скрипты установки и подозрительные имена). Она ничего не грузит из сети,
открывается офлайн, её безопасно пересылать. Если проверка была неполной, страница так и
пишет, а не выглядит «чистой».

### 4.2 secrets: утёкшие ключи и пароли

`jetscan secrets [путь]` ищет секреты в файлах и в истории git. Полностью без сети.

**Как сгруппированы находки** (сначала самое срочное):

1. **Committed to git** — уже в репозитории, есть у каждого клона.
2. **Not ignored by git** — ещё не закоммичено, но до утечки один `git add .`.
3. **Only in git history** — удалено из файлов, но осталось в старом коммите.
4. **Local only** — файл в `.gitignore`. Показывается, но утечкой не считается и никогда не
   валит `--exit-code`.

**Что вы видите.** Никогда не весь секрет: только маску (`AKIA************AQJD`) и отпечаток
(`fp 0a6287585102cc5a` — первые 16 hex-символов SHA-256). Текст из файлов очищается перед
выводом, так что файл не может подсунуть управляющие коды терминала.

**Что находит**: ключи AWS, GitHub, GitLab, Slack (токены и вебхуки), Stripe, Google API,
OpenAI, Anthropic, Hugging Face, Groq, Replicate, Perplexity, xAI, npm, PyPI, Telegram,
Resend, SendGrid, Twilio, Mailgun, Discord, Shopify и DigitalOcean; приватные ключи
(PEM/PGP); пароли в URL; чувствительные значения в `.env`, `.npmrc`, `.pypirc`,
`.git-credentials`, `.docker/config.json`; сохранённые пароли в файлах учётных данных вроде
`.netrc`, `.pgpass` и в настройках FTP/SFTP-клиентов.

**Секреты в коде**: ключ, переданный строкой прямо в криптовызов (`createHmac`,
`jwt.sign` / `jwt.verify`, `jwt.encode`, `hmac.new`, `SecretKeySpec`, `SignedString`);
запасное значение секретной переменной окружения (`process.env.JWT_SECRET || "…"`,
`os.getenv("SECRET_KEY", "…")`, `env()` в Laravel). Если переменную забыли задать на сервере,
приложение молча подписывает токены этим значением, поэтому находкой считается даже
`"secret"`. Пароль, который сравнивается с прописанным в коде значением, показывается с
низкой уверенностью: проверьте его сами. Эти три проверки не работают в документации
(`.md`, `.rst`, `.txt`): там такие строки — примеры.

Полезные опции:

| Опция | Что делает |
|---|---|
| `--no-history` | не проверять историю git (быстрее) |
| `--staged` | только подготовленные изменения — то, что добавит следующий коммит (так работает хук) |
| `--verify` | спросить провайдера каждого ключа, работает ли он ещё (сеть, см. ниже) |
| `--max-size <КБ>` | пропускать файлы больше этого размера (по умолчанию 1024) |
| `--exit-code` | код 1, если секрет может утечь (см. [5](#5-как-читать-результаты)) |
| `--json` | вывод для программ |

**Ключ ещё живой? (`--verify`)** По умолчанию выключено, потому что это сетевой трафик. Для
каждого ключа jetscan отправляет один запрос «кто я» только на чтение — его собственному
провайдеру (GitHub `/user`, OpenAI `/v1/models`, Slack `auth.test`, …) — и помечает находку
`LIVE` или `revoked`. Ключ передаётся curl через стандартный ввод (никогда в командной
строке), по https, без редиректов, только на разрешённый хост этого провайдера. Ответ `401`
от GitLab или Mailgun считается «unknown»: ключ может быть от своего GitLab или от
EU-аккаунта Mailgun. Поддерживаются: GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, npm,
Telegram, SendGrid, Mailgun, Discord, Resend, Hugging Face, Groq, xAI, Replicate. Не
проверяются (нет безвредного способа или нужна пара ключей): AWS, Twilio, Shopify, Google,
PyPI, вебхуки Slack, приватные ключи.

**Что делать с найденным секретом.** **Сначала** отзовите его и выпустите новый у
провайдера. Удалить строку недостаточно: у всех, кто клонировал репозиторий или видел лог CI,
старое значение осталось. Затем уберите новое значение из кода (переменная окружения,
хранилище секретов) и, если репозиторий общий, подумайте о переписывании истории
(git filter-repo / BFG) — это уборка, а не исправление.

**Ложные срабатывания.** Два способа заглушить находку, которая не секрет:

```
# .jetscanignore  (в проверяемой папке; # — комментарий)
dfcc91fb832c15bc        # один конкретный секрет, где бы он ни был
rule:url-credentials    # всё правило
testdata/               # папка (префикс пути)
tests/fixture.env       # один файл
```

Или напишите `jetscan:ignore` прямо на этой строке, например в комментарии:
`token = "…"  # jetscan:ignore`. Отчёт покажет, сколько находок заглушено:

```
Scanned 6 files
1 suppressed by .jetscanignore

✓ No secrets found
```

### 4.3 deps: уязвимые и вредоносные пакеты

`jetscan deps [путь]` читает lock-файлы и проверяет каждую точную версию по OSV.dev.

| Экосистема | Lock-файлы |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic и Berry), `pnpm-lock.yaml` (v5, v6, v9); если npm-lockfile нет ни в папке, ни выше, — точные версии из `package.json` (`"mathjs": "3.10.1"`; диапазоны вроде `^1.2` и транзитивные зависимости неизвестны) |
| crates.io (Rust) | `Cargo.lock` |
| Go | `go.mod` (с `replace`) |
| PyPI (Python) | `requirements*.txt` (точные `==`), `poetry.lock`, `Pipfile.lock`, `uv.lock` |

- Lock-файл, который не удалось разобрать, помечается **not checked**, но никогда не
  «чистым». Локальные, path-, git- и workspace-пакеты пропускаются (их нет ни в одной базе
  уязвимостей).
- Для каждого уязвимого пакета даётся **одна версия, которая исправляет всё, что можно**:
  `→ minimist 1.2.5 → 1.2.6  fixes 1 vulnerability`.
- **Вредоносные пакеты** (известное вредоносное ПО, id `MAL-…` и бюллетени с CWE-506) идут
  отдельным разделом. Обновление не поможет: удалите пакет и считайте компьютер, где его
  ставили, скомпрометированным.
- **Скрипты установки**: пакеты, которые выполняют команды при `npm install`, перечислены с
  точными командами. **Подозрительные имена**, похожие на популярные пакеты (тайпсквоттинг),
  тоже.

**`--fix`** печатает план исправлений — точные команды. Ничего не запускается и не меняется.

```
Fix plan (nothing is run or edited — review and apply yourself)
  package-lock.json
    minimist 1.2.5 → 1.2.6
      $ npm install minimist@1.2.6
```

Прямая зависимость получает `npm install x@1.2.3` (или `yarn add` / `pnpm add`); транзитивная —
запись `overrides` / `resolutions` / `pnpm.overrides`. Rust: `cargo update -p x --precise …`;
Go: `go get …`; Python: poetry / uv / pipenv или строка, которую надо поправить.

**Сеть, кэш, офлайн.** На `api.osv.dev` уходят только имена и версии пакетов. Ответы
кэшируются в `~/.jetscan/osv-cache` на 24 часа.

| Опция | Что делает |
|---|---|
| `--offline` | только кэш, ничего не отправлять |
| `--no-cache` | спросить OSV заново, даже если кэш свежий |
| `--fail-on <уровень>` | с `--exit-code`: падать только на `critical`, `high`, `medium` или `low` (по умолчанию) и выше |

Если OSV недоступен, берётся старый кэш, и отчёт пишет, какого он возраста. Пакеты без
данных помечаются **not checked**, и неполная проверка никогда не выглядит чистой:

```
$ jetscan deps . --offline --exit-code      (кэш пуст)

  package-lock.json (npm, 1 package)

Checked 0 packages
! 1 package NOT checked (offline, not in cache) — results are incomplete
                                                        (код выхода 2)
```

Прокси берётся из `HTTPS_PROXY`.

**SBOM** (`--sbom cyclonedx` или `--sbom spdx`, CycloneDX 1.6 / SPDX 2.3) входит в jetscan
Teams, см. [8](#8-ci-github-actions-и-другие).

### 4.4 Проверка GitHub Actions

`jetscan scan` также читает `.github/workflows/*.yml` и составной `action.yml` — полностью
локально. Это факты о файле, а не советы по стилю:

| Проверка | Уровень | Что значит |
|---|---|---|
| `gha-script-injection` | exploitable | недоверенный текст (`${{ github.head_ref }}`, заголовок или текст PR/issue, сообщение коммита…) вставляется в скрипт `run:` (или `github-script`) до запуска оболочки, поэтому ветка с именем `$(curl …\|sh)` выполнится как код |
| `gha-pwn-request` | exploitable | workflow `pull_request_target` / `workflow_run` (у него есть секреты и токен на запись) забирает код PR и тем самым запускает чужой код |
| `gha-insecure-commands` | exploitable | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` снова включает `set-env` / `add-path` |
| `gha-unpinned-action` | harden | сторонний action на теге или ветке: тот, кто управляет тегом, может подменить то, что запускается |
| `gha-write-all-permissions` | harden | `permissions: write-all` |

Находки exploitable помечены `✗` и валят `--exit-code`; harden помечены `!` и не валят:

```
GitHub Actions (workflow files: known attack patterns, checked locally)
  ! .github/workflows/lint.yml:8 — third-party action tj-actions/changed-files@v45 is pinned to a mutable tag or branch
      pin it to a full commit SHA: tj-actions/changed-files@<40-hex sha> # v45
  ! .github/workflows/write-all.yml:5 — workflow or job grants write-all permissions
      grant only what the job needs, e.g. permissions: { contents: read }
```

Задача, которую форк запустить не может (например,
`if: github.event.pull_request.head.repo.full_name == github.repository` или задача только
для Dependabot), не сообщается. Файл workflow, который встроенный читатель YAML понимает не
полностью (якоря, табуляция, многострочные flow-коллекции), пропускается, а не угадывается.

### 4.5 machine: весь компьютер

`jetscan machine` проходит по домашней папке:

- **Хранилища учётных данных** в открытом виде: `~/.git-credentials`, `~/.npmrc`,
  `~/.pypirc`, `~/.netrc`, `~/.docker/config.json`, `~/.cargo/credentials.toml`,
  `~/.kube/config`, `~/.aws/credentials` и другие.
- **Приватные SSH-ключи без пароля** (файл ключа разбирается, а не угадывается по
  заголовку), а в Linux/macOS — ключи, доступные другим пользователям.
- Файлы **истории командной строки**.
- **Все git-репозитории** в домашней папке (`--depth <N>` — как глубоко искать, по умолчанию
  6) с обычным поиском секретов.
- `--deps` дополнительно проверяет пакеты каждого репозитория (сеть: OSV).

Настоящий вывод на тестовой домашней папке:

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

Ссылки вида `${ENV}` и заглушки не сообщаются. `--sarif` для `machine` недоступен.

### 4.6 hook: остановить секрет до коммита

```
$ jetscan hook install
✓ pre-commit hook installed: .\.git\hooks\pre-commit
  every `git commit` now checks the staged changes for secrets

$ jetscan hook uninstall
✓ pre-commit hook removed: .\.git\hooks\pre-commit
```

Запускайте внутри репозитория (или укажите путь: `jetscan hook install <репозиторий>`).
После этого каждый `git commit` выполняет `jetscan secrets --staged` и останавливает коммит,
если он добавляет секрет. Секрет, пойманный до коммита, не нужно перевыпускать. Чужой
`pre-commit`-хук никогда не перезаписывается: вместо этого вы получите строку, которую надо в
него добавить. Пропустить проверку один раз: `git commit --no-verify`.

### 4.7 resolve: исправить найденное (alpha)

Resolve превращает находки в план исправлений, который вы проверяете до любых изменений. Он
работает локально, ничего не отправляет, никогда не запускает оболочку, менеджер пакетов или
git и пишет только после `--confirm`. Помечен **alpha**: вывод и коды выхода ещё могут
меняться.

```sh
jetscan resolve plan . --out jetscan-plan.json   # 1. только чтение: составить план
jetscan resolve preview jetscan-plan.json        # 2. только чтение: точный diff
jetscan resolve apply jetscan-plan.json --confirm  # 3. единственный шаг, который пишет
jetscan resolve verify jetscan-plan.json         # 4. перепроверить каждую находку
```

Предпросмотр для демо-проекта:

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

**Что исправляется автоматически сейчас:** ровно один вид правки. Недоверенный текст в
скрипте `run:` GitHub Actions (`gha-script-injection`) переносится в переменную окружения —
и только если безопасность правки для этого файла доказуема. Если нет, план объясняет почему
(`echo ${{ … }}` без кавычек, `eval`, `bash -c`, `$GITHUB_ENV`, подстановка команд,
раннер PowerShell, необычный YAML, …) и даёт шаги для ручного исправления.

Всё остальное получает **совет, а не правку**:

- Утёкшие ключи: сначала отозвать и перевыпустить, потом убрать значение из кода;
  переписывание истории — необязательная уборка. `verify` пишет
  `credential_revocation_cannot_be_checked_locally`.
- Уязвимости зависимостей: отсылка к `jetscan deps --fix`.
- `permissions: write-all`: только на проверку — какие права нужны каждой задаче, знаете
  только вы.
- Находки jetscan Pro: только советы.

Как `apply` бережёт файлы: запускается только из того проекта, для которого составлен план
(или с `--root`, указывающим на него); отказывается, если файл изменился после плана; пишет
все файлы или ни одного и при сбое всё возвращает; править можно только
`.github/workflows/*.yml|*.yaml`; ссылки и junction запрещены. Файл плана считается
недоверенным и проверяется заново при импорте и при применении. После `apply` состояние —
«applied, not verified», пока вы не запустите `verify`.

`verify` по каждой находке пишет: `verified_specific_issue`, `still_present` или `unknown`.
Он говорит только о находках из плана и никогда — «ваш проект безопасен».

Можно начать и с отчёта Findings V2: `jetscan resolve plan report-v2.json --root <проект>
--out plan.json`.

Коды выхода:

| Команда | 0 | 1 | 2 |
|---|---|---|---|
| plan | план записан/напечатан | — | плохой ввод, файл `--out` уже есть |
| preview | показан | — | план неверный или файл изменился |
| apply | применён, уже был применён или нечего применять | откат / сбой | нет `--confirm`, другой проект, файл изменился, неверный план |
| verify | все находки подтверждены | находка осталась | что-то неизвестно |

«Input coverage is partial» в плане — честность, а не ошибка: проверка GitHub Actions не
сообщает, смогла ли она прочитать каждый файл, поэтому план на её основе никогда не
утверждает, что покрыл всё.

## 5. Как читать результаты

### Значки и цвета

`✗` (красный) — надо исправить, `!` (жёлтый) — слабое место, предупреждение или неполная
проверка, `✓` (зелёный) — чисто, `→` — совет. Цвета есть только в терминале и никогда, если
задана `NO_COLOR`.

### Серьёзность и уверенность

Это два разных вопроса:

- **Серьёзность (severity)** — насколько это плохо, *если это правда*: `critical`, `high`,
  `medium`, `low`, `info`.
- **Уверенность (confidence)** — насколько jetscan уверен, что это *правда*.

В бесплатных проверках:

- **Секреты** показывают один уровень в скобках: `[high]` / `[medium]` / `[low]`. Он
  говорит, насколько правило уверено, что это настоящий секрет: ключ `AKIA…` правильной
  формы — `high`; значение рядом со словом вроде `PASSWORD` в `.env` — `medium`. (В `--json`
  это поле так и называется — `confidence`.)
- **Уязвимости** используют серьёзность из бюллетеня (`CRITICAL`, `HIGH`, …), посчитанную по
  его оценке CVSS. Бюллетень без оценки — `unknown`, и он всегда валит `--exit-code`.
- **GitHub Actions**: `exploitable` (✗) или `harden` (!).

Аудиты jetscan Pro (и JSON Findings V2) показывают оба значения, например
`HIGH [potential] <правило>` или `MEDIUM [confirmed] <правило>`:

| Уверенность | Что значит |
|---|---|
| `confirmed` | jetscan сам увидел факт (например: заголовка нет в ответе) |
| `potential` | шаблон совпал, но что-то невидимое для jetscan может это изменить (например: настройка, сделанная вне файлов, которые читает jetscan) |
| `needs_review` | указатель для человека: это может быть сделано намеренно (открытая точка входа, публичные данные) |

### Проверки: completed, partial, skipped

Отчёты jetscan Pro перечисляют каждую проверку, которая прошла не полностью
(`Checks not fully run:`), со статусом и причиной:

- `completed` — проверка прошла по всему, что должна была.
- `partial` — прошла, но не по всему (значение не удалось вычислить, упёрлась в лимит).
- `skipped` — не запускалась, причина сказана (неприменима, не в этом режиме).
- `error` — сбой.

Бесплатные проверки говорят то же словами: `git history was NOT checked`, `1 package NOT
checked … results are incomplete`, `No lockfiles found — nothing was checked`.

### Ограничения (Limitations)

Каждый Pro-отчёт заканчивается блоком **Limitations**: чего такая проверка не видит
(например, «static analysis only: nothing was built or executed», «headers were checked on
one page»). Читайте его. **«Нет находок» никогда не значит «безопасно»**: это значит, что эти
правила ничего не нашли в том, что jetscan смог прочитать.

### Коды выхода

| Команда | 0 | 1 | 2 |
|---|---|---|---|
| `scan`, `secrets`, `deps`, `machine` **без** `--exit-code` | завершено (с находками или без) | — | ошибка: неверные аргументы, флаг Teams без ключа |
| то же **с** `--exit-code` | исправлять нечего | есть что исправить: секрет, который может утечь (не из `.gitignore`), известная уязвимость (с учётом `--fail-on`), вредоносный пакет, exploitable-workflow, серьёзная проблема гигиены машины | неполно: часть пакетов не проверена |
| Pro `web source`, `apk`, `android`, `ios`, `url` с `--exit-code` | нет critical/high и все проверки прошли | есть critical или high находка | проверка прошла не полностью (и нет critical/high); также любая ошибка или нет ключа |
| `license` | показано | — | ключ есть, но не принят |
| `resolve …` | см. [4.7](#47-resolve-исправить-найденное-alpha) | | |

### JSON

- `--json` у `scan`, `secrets`, `deps`, `machine` печатает стабильный отчёт для программ с
  `"version": 1` (стабильный порядок, стабильные отпечатки, без полных секретов).
- Pro-команды с `--json` печатают **Findings V2** (`schema_version: 2`): у каждой находки
  есть `rule_id`, `severity`, `confidence`, место, замаскированный фрагмент, а у отчёта —
  `checks` (со статусом и причиной), `limitations` и сетевая активность. `web source`, `apk`,
  `android` и `ios` принимают также `--json-v2` — другое имя того же.
- Статус и ошибки идут в stderr, так что stdout остаётся чистым JSON-документом.

### Как заглушить ложные срабатывания

| Находка из | Как заглушить |
|---|---|
| секреты (файлы, история, machine) | отпечаток, `rule:<id>` или путь в `.jetscanignore`; или `jetscan:ignore` на строке |
| Pro web source, Android, iOS | `jetscan:ignore` на строке |
| уязвимости | `--fail-on high`, чтобы падать только на серьёзных; или baseline (Teams) |
| GitHub Actions и вообще всё в старом проекте | baseline: `--write-baseline` / `--baseline` (Teams, см. [8](#8-ci-github-actions-и-другие)) |

Вредоносные пакеты baseline не скрывает никогда.

## 6. jetscan Pro

jetscan Pro — отдельная сборка jetscan с аудитами сайтов и мобильных приложений. В неё входит
всё, что есть в бесплатной. Аудиты Pro — alpha: правила, вывод и коды выхода ещё могут
меняться. Код jetscan Pro закрыт: его нет в этом репозитории.

- `jetscan web source [путь]`: исходники проекта на Next.js или Vite React. Привилегированные
  ключи в клиентском коде, секреты в переменных `NEXT_PUBLIC_` / `VITE_`, обработчики
  маршрутов и Server Actions, которые меняют данные без видимой проверки доступа,
  непостоянный HTML в DOM, ключи Supabase service-role, которые видит браузер, CORS с
  учётными данными для любого источника, публичные source maps.
- `jetscan apk <файл.apk>`: Android APK, без установки и запуска. Отладочные сборки,
  экспортированные компоненты, настройки резервного копирования и открытого HTTP, разрешения,
  ключи в ресурсах и строках DEX.
- `jetscan android [путь]` и `jetscan ios [путь]`: исходники Android (Gradle, Kotlin / Java)
  и iOS (Xcode, Swift / Objective-C). Настройки манифеста, plist и entitlements, файлы
  подписи и пароли в репозитории, ключи провайдеров, TLS «доверять всем», опасные web view,
  слабая криптография, секреты в логах.
- `jetscan url <https://сайт>`: пассивная проверка опубликованного сайта — только те запросы,
  что делает браузер, только к этому сайту: заголовки безопасности, флаги cookie, открытые
  `.git` / `.env`, публичные source maps, серверные ключи в его JavaScript.
- Те же аудиты — как инструменты для ИИ-редакторов (`jetscan mcp`) и в меню.

Аудиты исходников и APK работают на вашем компьютере и ничего не отправляют; проверка URL
обращается только к указанному сайту. Чистый результат значит, что эти правила ничего не
нашли, а не что приложение безопасно. Находки Pro показывают и серьёзность, и уверенность
(см. [Серьёзность и уверенность](#серьёзность-и-уверенность)).

### Тарифы

| Ключ | Что открывает |
|---|---|
| Бесплатная проба | один аудит на выбор (исходники сайта, APK, Android или iOS), 2 скана |
| jetscan Pro (личный, на год) | все аудиты Pro, включая проверку URL |
| Разовый аудит (30 дней) | все аудиты Pro, для одного проекта |
| jetscan Teams | все аудиты Pro и CI-отчёты (`--sarif`, `--sbom`, `--baseline`) |

Teams — для одной организации, до 20 разработчиков: $499 за первый год, затем $990 в год.
Цены остальных тарифов и пробы: <https://jetscan.jet.kim>.

### Как получить и установить ключ

1. Получите ключ на <https://jetscan.jet.kim> (криптовалютой, через Cryptomus). Он придёт на
   почту; продление и копия ключа — в личном кабинете там же.
2. Положите его в переменную окружения `JETSCAN_LICENSE` (в CI — как секрет) или в файл
   `~/.jetscan/license` (в Windows `%USERPROFILE%\.jetscan\license`).
3. Проверьте командой `jetscan license`.

Ключ — подписанный текст (организация, тариф, срок). jetscan проверяет подпись **на вашем
компьютере**: без аккаунта, без активации, без сети, поэтому всё работает и в изолированном
CI. `jetscan license` показывает тариф, срок и что открывает ключ, а сам ключ не печатает
никогда:

```
$ jetscan license
jetscan Free — no license key (JETSCAN_LICENSE or ~/.jetscan/license).
Every free scan works without a key. Pro scans (web source, live website URL, APK, Android, iOS) need jetscan Pro, a one-time audit or a free trial (one scanner, a few scans); --sarif, --sbom and --baseline need jetscan Teams.
Pro, trial and Teams: https://jetscan.jet.kim
```

За тридцать дней до конца годового ключа jetscan начинает предупреждать в stderr; после срока
платные функции работают ещё 14 дней, затем выключаются. Сканы без них продолжают работать.
Честные пределы офлайн-ключа: его нельзя отозвать раньше срока (ключи выдаются на год, а не
навсегда), и перевод системных часов назад его продлевает. Это сознательная модель доверия, а
не DRM.

В бесплатной сборке Pro-команда говорит, откуда она, и ничего не сканирует:

```
$ jetscan apk app.apk

✗ Error  `apk` is part of jetscan Pro: a static audit of Android APK files (manifest flags, exported components, cleartext traffic, embedded keys; nothing is installed or run). Get it at https://jetscan.jet.kim
```

## 7. ИИ-редакторы (MCP)

`jetscan mcp` позволяет ИИ-инструментам для кода — Claude Code, Cursor, VS Code (Copilot),
Devin Desktop (бывший Windsurf) — самим запускать проверки jetscan, например сразу после того,
как они написали код. Это сервер Model Context Protocol на stdio: редактор запускает
`jetscan mcp` и общается с ним.

Проще всего — **пункт меню 6**: он печатает команды и файлы настроек с уже подставленным
полным путём к вашему jetscan.

### Claude Code

```sh
claude mcp add jetscan -- jetscan mcp                  # только этот проект
claude mcp add --scope user jetscan -- jetscan mcp     # все проекты
claude mcp list                                        # проверить
```

Проверено с настоящим Claude Code (2.1.323) в Windows. Начните новую сессию; `/mcp` покажет
jetscan.

### Cursor

Сохраните как `.cursor/mcp.json` в проекте:

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

Сохраните как `.vscode/mcp.json` в проекте:

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

Если файл уже есть, добавьте только запись `"jetscan"`. Затем перезапустите редактор или
перезагрузите его MCP-серверы. Настройки Cursor и VS Code сделаны по их документации, но на
настоящих редакторах ещё не проверены. Если `jetscan` нет в `PATH`, укажите полный путь в
`"command"` (в Windows — с двойными обратными слешами, `"C:\\Tools\\jetscan.exe"`). Другие
редакторы и подробности: [docs/mcp/README.md](https://github.com/y6861977-ui/jetscan/blob/main/docs/mcp/README.md).

### Что получает ИИ

| Инструмент | Что делает | Тариф |
|---|---|---|
| `scan_secrets` | утёкшие секреты в файлах и (по умолчанию) в истории git | бесплатно |
| `scan_dependencies` | уязвимые или вредоносные пакеты; **по умолчанию офлайн** (только кэш), `offline: false` отправляет имена и версии в OSV | бесплатно |
| `scan_github_actions` | проверки GitHub Actions | бесплатно |
| `resolve_plan` | план исправлений и предпросмотр diff; **файлы не меняет никогда** | бесплатно |
| аудиты jetscan Pro | аудиты исходников сайта, APK, Android и iOS и пассивная проверка живого сайта | сборка jetscan Pro + ключ Pro, разового аудита или Teams, или бесплатная проба одного аудита |

Все инструменты только читают, ни один не применяет исправлений: ИИ показывает вам diff, а
применять или нет — решаете вы. Без ключа Pro-инструмент возвращает короткое сообщение вместо
сканирования.

### Приватность с ИИ-редакторами

- jetscan ничего не загружает. **Но ИИ-инструмент отправляет результаты своей модели**, как и
  любой текст, который читает. Поэтому значений секретов в результатах нет совсем, даже
  замаскированных: только правило, место и отпечаток.
- Инструменты читают только внутри рабочей области (папки `--root` или папка проекта). Путь
  снаружи, ссылка наружу, домашняя папка или целый диск — отказ.

### Если что-то не работает

- Логи идут в stderr: `jetscan mcp 0.5.0: serving on stdio, workspace <folder>`. Большинство
  редакторов показывает их в логах MCP.
- `refused: … is outside the workspace` → запустите сервер в проекте или добавьте
  `--root <проект>`.
- `refused: … is your home folder or a whole drive` → редактор запустил jetscan в домашней
  папке; добавьте `--root <проект>`.
- `deps.osv: partial … offline` → `scan_dependencies` использовал только кэш. Попросите ИИ
  вызвать его с `offline: false` (так в api.osv.dev уйдут имена и версии пакетов).

## 8. CI (GitHub Actions и другие)

Все проверки, `--exit-code`, `--json` и `--html` бесплатны и в CI.

```sh
jetscan scan . --exit-code   # 0 чисто · 1 есть что исправить · 2 неполно
```

Задача GitHub Actions, которая проверяет каждый push и pull request и запускается каждую ночь
(новый бюллетень для пакета, который вы уже используете, уронит ночной запуск):

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

Советы:

- `fetch-depth: 0` важен: при неглубоком клоне по умолчанию истории для проверки нет.
- Код 2 (OSV недоступен, часть пакетов не проверена) тоже валит задачу: неполная проверка — не
  успех. `--offline` используйте только с кэшем, которому доверяете.
- `--fail-on high` падает только на high и critical уязвимостях. Вредоносные пакеты, утёкшие
  секреты и уязвимости неизвестной серьёзности валят всегда.
- В своих workflow закрепляйте actions на SHA коммита (проверка jetscan напомнит).

<!-- jetscan:plan ci -->
### jetscan Teams в CI: SARIF, SBOM, baseline

Им нужен ключ **Teams** в `JETSCAN_LICENSE` (храните его как секрет CI):

| Опция | Что делает |
|---|---|
| `--sarif` | SARIF 2.1.0 для code scanning в GitHub / GitLab (не для `machine`). Только находки, требующие действий, замаскированные секреты, `security-severity` для уровней GitHub. |
| `--sbom cyclonedx` / `--sbom spdx` | `deps`: список компонентов ПО (CycloneDX 1.6 / SPDX 2.3, детерминированно) для аудитов и европейского Cyber Resilience Act |
| `--write-baseline <файл>` | сохранить сегодняшние находки как baseline (секретов в нём нет — только ключи вроде отпечатков и id бюллетеней) |
| `--baseline <файл>` | показывать и валить только находки, которых **нет** в baseline |

Старый проект с известным долгом: один раз запишите, что есть, закоммитьте файл и падайте
только на новом:

```sh
jetscan scan . --write-baseline jetscan-baseline.json   # один раз; закоммитьте файл
jetscan scan . --baseline jetscan-baseline.json --exit-code
```

Уязвимость остаётся «известной» после обновления, которое её не исправило; секрет остаётся
известным, куда бы он ни переехал. Вредоносные пакеты baseline не скрывает никогда. Отчёт
всегда пишет, сколько известных находок скрыто.

Полная задача с отчётами Teams:

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

Без ключа Teams эти флаги останавливаются с понятным сообщением (код 2), остальное не
меняется:

```
✗ Error  --sarif is part of jetscan Teams (CI reports: --sarif, --sbom, --baseline). Get a key at https://jetscan.jet.kim and put it in JETSCAN_LICENSE (a CI secret) or ~/.jetscan/license; it is checked on this machine, nothing is sent. Without --sarif, every scan stays free
```

Скрипт установки ставит бесплатную сборку. Для Pro-аудитов в CI нужна Pro-сборка из
кабинета; публичного скрипта установки у неё нет.

<!-- jetscan:end -->
## 9. Проблемы и частые вопросы

**Мой код куда-то загружается?** Нет. Поиск секретов, проверка GitHub Actions, machine,
resolve и Pro-аудиты исходников и APK ничего не отправляют. Проверка зависимостей отправляет
только имена и версии пакетов на api.osv.dev (`--offline` — ничего). Ключи лицензий
проверяются офлайн. См. таблицу в [разделе 1](#1-что-такое-jetscan).

**Вместо цветов вижу `←[32m` и подобный мусор.** Консоль не поддерживает цвета, и jetscan не
смог их включить. Задайте `NO_COLOR=1` (PowerShell: `$env:NO_COLOR = "1"`; cmd:
`set NO_COLOR=1`) или используйте Windows Terminal. Цвета jetscan выводит только в терминал,
никогда в файлы и конвейеры.

**Сохранение JSON или SARIF в Windows.** В Windows PowerShell 5.1 оператор `>` перекодирует
вывод программы в UTF-16, и некоторые инструменты его не читают. Используйте PowerShell 7,
или `cmd /c "jetscan scan . --json > report.json"`, или опцию `--html` для файла отчёта.

**Путь с пробелами не работает.** Возьмите его в двойные кавычки:
`jetscan scan "C:\My Projects\app"`. В меню и консоли кавычки добавятся сами, если перетащить
папку в окно.

**После установки `jetscan` не находится.** Откройте новый терминал (установщик поменял
`PATH`). В macOS/Linux проверьте, что `~/.local/bin` есть в `PATH`.

**Работа через прокси.** Для проверки зависимостей задайте `HTTPS_PROXY` (например,
`HTTPS_PROXY=http://proxy.example:8080`).

**Без сети или в изолированной среде.** `jetscan secrets`, machine, проверке GitHub Actions и
Pro-аудитам исходников/APK сеть не нужна вовсе. Для зависимостей один раз запустите проверку с
сетью, чтобы заполнить кэш, затем используйте `--offline`; пакеты не из кэша помечаются
**not checked**, и `--exit-code` вернёт 2. Ключи лицензий работают офлайн.

**«not a git repository — git history was not scanned».** Папка — не git-репозиторий (или git
не установлен). Файлы всё равно проверены; чтобы проверять историю, поставьте git. В CI
используйте `fetch-depth: 0`.

**История git долго проверяется в огромном репозитории.** Для быстрого взгляда — `--no-history`,
а историю оставьте для CI или pre-commit-хука (он проверяет только подготовленные изменения).

**Находка ошибочная (ложное срабатывание).** См. [Как заглушить ложные срабатывания](#как-заглушить-ложные-срабатывания).

**«Your jetscan Pro trial covers the apk scan only».** Проба открывает одну область. Другим
Pro-проверкам, включая проверку URL, нужен платный тариф.

**Лицензия истекла.** Годовые ключи (Pro, Teams) работают ещё 14 дней после срока с
предупреждением, затем платные функции отключаются. Ключи разового аудита и пробы перестают
работать в день окончания. **Бесплатные проверки работают всегда.** Продлите на
<https://jetscan.jet.kim> и замените ключ. Ключ проверяется по часам вашего компьютера.

**«license key not accepted».** Текст ключа повреждён (скопируйте его заново без переносов
строк и лишних символов) или это не ключ jetscan. Если ключ для тарифа, который эта версия не
знает, jetscan попросит обновиться.

**`--sarif` пишет, что это jetscan Teams, хотя у меня ключ Pro.** Верно: CI-отчёты есть только
в Teams. Ключ Pro, аудита или пробы открывает Pro-проверки.

**Pro-команда пишет, что это jetscan Pro, хотя ключ есть.** Вы запускаете бесплатную сборку.
Поставьте Pro-сборку из кабинета (`jetscan --version` должен показать `(Pro)`).

**Можно ли бесплатно пользоваться jetscan в компании?** Да. Бесплатную часть разрешено
использовать на работе в компании любого размера. Teams нужен, чтобы организация пользовалась
функциями Teams.

## 10. Словарь терминов

| Термин | Одной строкой |
|---|---|
| Advisory (бюллетень) | Опубликованное сообщение, что у версии пакета есть уязвимость, с версиями, где она исправлена. |
| Anon / publishable key | Ключ, который задуман публичным (anon-ключ Supabase, publishable-ключ Stripe); сам по себе не утечка. |
| APK | Файл, из которого ставится Android-приложение. |
| ATS (App Transport Security) | Настройка iOS, которая заставляет приложения использовать HTTPS. |
| Baseline | Файл с сегодняшними известными находками, чтобы CI падал только на новых (Teams). |
| Clickjacking | Загрузка вашей страницы в невидимом фрейме, чтобы обманом заставить нажать на неё. |
| Confidence (уверенность) | Насколько jetscan уверен, что находка настоящая: confirmed, potential, needs_review. |
| CORS | Правила браузера: каким другим сайтам можно читать ответы вашего сайта. |
| CSP (Content-Security-Policy) | Заголовок, который ограничивает, какие скрипты страница может грузить и выполнять; главная защита браузера от XSS. |
| CVE | Публичный номер известной уязвимости, например CVE-2021-44906. |
| CVSS | Оценка серьёзности уязвимости от 0 до 10. |
| CWE | Публичный номер типа слабости, например CWE-79 (XSS). |
| CycloneDX / SPDX | Два стандартных формата SBOM. |
| DAST | Проверка работающего приложения снаружи, отправкой запросов. |
| DEX | Скомпилированный код внутри APK. |
| Entitlements | Разрешения и возможности iOS-приложения, заданные при сборке. |
| Код выхода | Число, которое возвращает программа: 0 — всё хорошо, 1 — что-то найдено, 2 — неполно или ошибка. |
| Отпечаток (fingerprint) | 16-символьный хеш, который опознаёт секрет, не раскрывая его. |
| GHSA | Номер GitHub Security Advisory, например GHSA-xvch-5gv4-984h. |
| История git | Все старые версии файлов репозитория, в том числе удалённых. |
| HSTS | Заголовок, который велит браузерам открывать сайт только по HTTPS. |
| Keystore | Файл с ключом подписи Android-приложения. |
| Lock-файл | Файл с точными версиями всех установленных пакетов. |
| Вредоносный пакет | Пакет, опубликованный нарочно, чтобы красть или вредить, а не просто с ошибкой. |
| MCP (Model Context Protocol) | Стандартный способ, которым ИИ-редакторы вызывают внешние инструменты. |
| nosniff | `X-Content-Type-Options: nosniff`, запрещает браузеру угадывать тип файла. |
| OSV / OSV.dev | Бесплатная открытая база уязвимостей, по которой jetscan проверяет пакеты. |
| Pre-commit-хук | Скрипт, который git запускает перед каждым коммитом; хук jetscan не пропускает секреты. |
| Prompt injection | Текст, который заставляет ИИ сделать то, о чём пользователь не просил. |
| `pull_request_target` | Триггер GitHub Actions, который работает с секретами даже для pull request из форков. |
| R8 | Инструмент Android, который сжимает и запутывает релизный код. |
| Referrer-Policy | Заголовок, который решает, какую часть адреса отправлять другим сайтам. |
| Permissions-Policy | Заголовок, который ограничивает функции браузера (камера, микрофон…), доступные странице. |
| Перевыпустить ключ (rotate) | Отозвать старый ключ и создать новый у провайдера. |
| SARIF | Стандартный JSON-формат результатов сканеров, его читает code scanning в GitHub / GitLab. |
| SBOM | Список компонентов ПО: все пакеты, из которых состоит продукт. |
| Server Action | Функция Next.js, которая выполняется на сервере, когда её вызывает форма или кнопка. |
| Service-role key | Ключ Supabase с полным доступом к базе; никогда не должен попадать в браузер. |
| Severity (серьёзность) | Насколько плоха находка, если она настоящая: critical, high, medium, low, info. |
| SHA-256 / SHA256SUMS | Контрольная сумма файла и список сумм для проверки загрузки. |
| Source map | Файл, который сопоставляет сжатый браузерный код с исходным. |
| `security.txt` | Файл, который подсказывает исследователям, как сообщить о проблеме. |
| Тайпсквоттинг | Пакет с именем, похожим на популярное (`lodahs`), в расчёте на опечатку. |
| WebView | Встроенный браузер внутри мобильного приложения. |
| XSS (межсайтовый скриптинг) | Когда сайт выполняет скрипт злоумышленника в браузере посетителя. |
