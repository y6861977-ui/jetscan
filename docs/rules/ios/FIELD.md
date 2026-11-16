# Полевой тест `jetscan ios` (2026-11-16)

Шесть известных open-source iOS-приложений; **ничего не собиралось и не запускалось** (ни xcodebuild, ни код). Четыре —
shallow-клоны (`git clone --depth 1`), два — архив GitHub `HEAD.tar.gz` (у Wikipedia и NetNewsWire есть пути, недопустимые в
NTFS — папка с пробелом в конце, `"` в имени, — `git checkout` на Windows падает; при распаковке пропущены только эти
файлы: папка `WMFData/…/History /` у Wikipedia, `AppStore/` со скриншотами у NetNewsWire). Запуск — release-сборка
`jetscan ios`; после теста клоны удалены.

| Приложение | Коммит | Xcode-проектов / целей | Файлов прочитано | Swift / ObjC проверено | Тестовых пропущено | Время (тёплый кэш) |
|---|---|---|---|---|---|---|
| Signal (`signalapp/Signal-iOS`) | `a690a26` | 1 / 8 | 2 912 | 2 298 / 75 | 408 | 1,7 с |
| Element (`element-hq/element-ios`) | `7ba8beb` | 0 (XcodeGen `project.yml`) | 2 802 | 1 838 / 671 | 172 | 0,9 с |
| DuckDuckGo (`duckduckgo/iOS`) | `7b3f601` | 1 / 15 | 1 429 | 919 / 1 | 277 | 0,5 с |
| Firefox + Focus (`mozilla-mobile/firefox-ios`) | `80df876` | 4 / 38 | 3 766 | 2 127 / 16 | 1 214 | 1,6 с |
| NetNewsWire (`Ranchero-Software/NetNewsWire`) | `a5cec78` | 1 / 8 | 903 | 625 / 25 | 125 | 0,4 с |
| Wikipedia (`wikimedia/wikipedia-ios`) | `0cc1624` | 1 / 10 | 2 897 | 1 324 / 279 | 332 | 1,0 с |

## Раунд 1: 68 находок, 13 FP (+1 завышенная severity, +2 ошибки привязки к цели) — что исправлено

| # | Паттерн | Где | Исправление (тест) |
|---|---|---|---|
| 1 | `INFOPLIST_FILE = "$(SRCROOT)/Signal/Signal-Info.plist"` при проекте в корне скана → `/Signal/…` отбрасывался как абсолютный; Info.plist найден только по имени, без цели | Signal | `$(SRCROOT)` = корень → путь без ведущего `/` (`field_test_project_patterns`) |
| 2 | Xcode 16: xcconfig через `baseConfigurationReferenceAnchor` + `…RelativePath` (синхронизированная папка) не читался → `INFOPLIST_FILE` неизвестен | NetNewsWire | поддержан якорь + относительный путь (тот же тест) |
| 3 | `public static let ecbMode = Options(rawValue: kCCOptionECBMode)` — объявление опции в обёртке CommonCrypto → CRYPTO medium | Signal | объявление константы-псевдонима (`static let x =`, `case x =`) — не использование (`field_test_false_positive_patterns`) |
| 4 | `https://user:pass@host` в тестах URL-парсера → SECRET «Password in URL» ×3 | Signal, Firefox | в тестовых файлах — только форматы ядра высокой уверенности, как в комментариях (`field_test_secret_patterns`) |
| 5 | `Logger.info("…\(redact(pushToken))…")` → LOG ×2 | Signal | значение внутри `redact(…)`/`mask(…)`/`hash(…)`/… — не вывод секрета; push-токен — не секрет |
| 6 | `Logger.info("…\(token.version)…")` (поле объекта) → LOG | Signal | `секрет.поле` — не секрет, кроме полей-представлений (`.value`, `.rawValue`, `.base64EncodedString()`…) |
| 7 | `[NSUserDefaults … setObject:apnsDeviceToken forKey:@"apnsDeviceToken"]` / `pushDeviceToken` → STORAGE medium ×5 | Element | токены push/APNs/FCM/VoIP, страниц, синхронизации, отмены/наблюдения — не секреты (без ключа провайдера APNs-токеном не отправить уведомление) |
| 8 | `logger.log("…\(token)…")`, где `token: ActionToken` → LOG | Firefox | объявленный тип имени (`token: ActionToken`, `NSObjectProtocol`, `UUID`, `CKServerChangeToken`…) говорит «не секрет» |
| 9 | `Local-Info.plist` с `NSAllowsArbitraryLoads` используется только конфигурацией `LocalDebug` → high | Wikipedia | файл только debug-конфигураций → не выше low, с пояснением и тегом `build:debug-only` (`debug_only_plists_are_capped_at_low`) |

## Раунд 2 (после исправлений): 55 находок, 0 FP

TP — верный факт, который стоит ревью (в т. ч. info). Deb — факт верен, но по замыслу приложения (браузер, клиент
самостоятельно размещаемых серверов, менеджер паролей копирует пароль, отладочная функция).

| Правило | Всего | TP | Deb | FP | Строго (TP) | Мягко (TP+Deb) |
|---|---|---|---|---|---|---|
| IOS-ATS-001 | 10 | 4 | 6 | 0 | 40% | 100% |
| IOS-URLSCHEME-002 (info) | 34 | 34 | 0 | 0 | 100% | 100% |
| IOS-ENTITLEMENTS-003 | 5 | 5 | 0 | 0 | 100% | 100% |
| IOS-SIGNING-005 | 1 | 1 | 0 | 0 | 100% | 100% |
| IOS-TLS-008 | 1 | 0 | 1 | 0 | 0% | 100% |
| IOS-PASTEBOARD-012 | 4 | 0 | 4 | 0 | 0% | 100% |
| IOS-SECRET-004, STORAGE-006, KEYCHAIN-007, WEBVIEW-009, CRYPTO-010, LOG-011 | 0 | — | — | — | — | — |
| **Итого** | **55** | **44** | **11** | **0** | **80%** | **100%** |

Разбор по приложениям:

- **Signal (5):** ATS `signal.org` + поддомены по HTTP в приложении, NSE и Share Extension (medium/needs_review) → TP; URL-схема
  `sgnl` → TP; PASTEBOARD — копирование пароля БД в отладочной функции (`debugOnly_keyData`) → Deb.
- **Element (3):** ATS `NSAllowsArbitraryLoads` (клиент Matrix для любых, в т. ч. своих, серверов) → Deb; `webcredentials:*.element.io`
  → TP; схема `$(APPLICATION_SCHEME)` (XcodeGen, не раскрыть) → TP. `ios.project` честно `partial`: проект генерируется
  (`project.yml`), конфигурации неизвестны.
- **DuckDuckGo (14):** ATS (браузер) → Deb; PASTEBOARD ×3 — копирование пароля в автозаполнении/генераторе паролей
  (функция) → Deb; URL-схемы ×10 (в т. ч. `http`/`https` как браузер по умолчанию) → TP. SECRET-004 `partial`: два JSON > 1 МиБ.
- **Firefox + Focus (10):** TLS — делегат `CertificatesFetcher` принимает любой сертификат, чтобы показать цепочку в просмотрщике
  сертификатов → Deb (высокий риск только если сессию переиспользуют для данных); ATS ×2 (браузеры) → Deb; URL-схемы ×7 → TP.
  `ios.project` `partial`: `CODE_SIGN_ENTITLEMENTS = $(inherit)…` (опечатка в проекте; неизвестная переменная не угадывается).
- **NetNewsWire (10):** ATS ×2 (читалка лент с любых сайтов) → Deb; закоммиченный `NetNewsWire.provisionprofile` (low) → TP;
  URL-схемы ×7 (`feed`, `feeds`, …) → TP.
- **Wikipedia (13):** ATS в `Local-Info.plist` (только `LocalDebug`, low) → TP; `applinks:`/`webcredentials:`/`activitycontinuation:*.wikipedia.org`
  ×4 → TP (поддоменов сотни — языковые разделы; каждый из них может отдать apple-app-site-association, поэтому стоит ревью);
  URL-схемы ×8 → TP.
  `partial`: отсутствующий `OpenSourceDebug.xcconfig`, двоичный `LibrariesUsed.plist`.

Правильные «не находки» (проверено вручную по grep): DuckDuckGo `URLCredentialCreator`, Element `MXKWebViewViewController`
(после `SecTrustEvaluate`), Firefox `BrowserViewController+WebViewDelegates` (сертификат из CertStore пользователя), Signal
`OWSUrlSession` (пиннинг) — `URLCredential(trust:)` с проверкой не репортится; NetNewsWire `UserDefaults.set(data, forKey: changeTokenKey)`
(токен CloudKit) — не секрет; тестовые папки (2 528 файлов) на шаблоны кода не проверялись.

## Что не видно из исходников

- Pods/SPM-зависимости (не обходятся) и всё, что добавляется при сборке (собранный .ipa не анализируется).
- Info.plist из `INFOPLIST_KEY_*` (Signal: 6 целей с `GENERATE_INFOPLIST_FILE = YES`) не реконструируется — ATS и URL-типы
  так не задать, поэтому для правил это не потеря.
