# Полевой тест `jetscan android` (2026-11-16)

Пять известных open-source Android-приложений, shallow-клоны (`git clone --depth 1`, `core.longpaths`) во временный
каталог; **ничего не собиралось и не запускалось** (ни Gradle, ни код). Запуск — release-сборка
`jetscan android`; после теста клоны удалены.

| Приложение | Коммит | Модулей Android | Файлов прочитано | Kotlin/Java проверено | Время (тёплый кэш) |
|---|---|---|---|---|---|
| NewPipe (`TeamNewPipe/NewPipe`) | `1e61c9a` | 2 | 1 268 | 593 | 0,7 с |
| Thunderbird / K-9 (`thunderbird/thunderbird-android`) | `d2ecc5c` | 87 | 7 288 | 2 844 | 2,4 с |
| Nextcloud (`nextcloud/android`) | `fea333a` | 2 | 2 146 | 1 193 | 0,8 с |
| Aegis (`beemdevelopment/Aegis`) | `d6f4e59` | 1 | 551 | 233 | 0,3 с |
| AntennaPod (`AntennaPod/AntennaPod`) | `45de161` | десятки (точно не считалось) | 1 141 | 558 | 0,5 с |

Первый холодный прогон Thunderbird — 38 с (диск/антивирус); повторный — 2,4 с (`jetscan secrets` по тому же
дереву — 8,7 с).

## Раунд 1: 88 находок, 13 FP — и что исправлено

| # | Паттерн | Где | Исправление (тест) |
|---|---|---|---|
| 1 | `plugins { alias(…android.application) apply false }` в корне → корень «приложение»: MINIFY по корню, `partial` «нет манифеста» у всех правил | NewPipe, Thunderbird, Nextcloud, AntennaPod | `apply false` не применяет плагин (`field_test_project_patterns`) |
| 2 | AGP 9 `minSdk { version = release(X) }` и `configure<ApplicationExtension> { }` не читались → «SDK не задан» → значения AGP по умолчанию (targetSdk 1): ложные NET ×2, BACKUP medium | NewPipe | блочная форма SDK, константы `buildSrc`; «по умолчанию AGP» только если SDK вообще не упоминается (тот же тест) |
| 3 | Неразрешённый `${плейсхолдер}` в `android:authorities`/`android:name` делал `partial` все правила манифеста | NewPipe, Aegis, AntennaPod | `partial` только если атрибут важен правилу (exported/enabled/permission… → EXPORT, allowBackup → BACKUP, …) |
| 4 | Convention-плагины в `build-plugin/` не распознавались; операторы `buildTypes` всех скриптов применялись ко всем модулям | Thunderbird | `build-plugin*` — build-logic; скрипты `<id>.gradle.kts` сопоставляются с модулем по id (в т. ч. `id(ThunderbirdPlugins.App.androidCompose)` через строковые константы), транзитивно; SDK — из применённого скрипта |
| 5 | «Password in URL» в Javadoc (`smtp://user:password@server`) → high ×3 | Thunderbird | в комментариях — только форматы высокой уверенности ядра |
| 6 | `VeryTrustingTrustManager` в модуле тестовых утилит `mail/testing/src/main` → TLS high; `keystore.jks` там же → medium | Thunderbird | каталоги `testing`/`test-utils`/`benchmarks`… перед `src/` — тестовые (`reach_by_source_set`) |
| 7 | `Log.v(TAG, negativeResponseFromOldToken, …)` (исключение) → LOG ×2 | Thunderbird | имена со словами response/error/exception/result/request/… — не секрет |
| 8 | `Log.d(… poToken …)` внутри `if (BuildConfig.DEBUG)` | NewPipe | ветка `BuildConfig.DEBUG` не попадает в release — не находка |
| 9 | `result.putString(Constants.SSO_TOKEN, token)` (Bundle) → STORAGE | Nextcloud | получатель должен быть редактором SharedPreferences (`edit()`, `editor`, `prefs…`) |
| 10 | Один файл > 1 МиБ (`gradle/verification-metadata.xml`) делал `partial` все 15 проверок | Nextcloud | неполнота адресная: пропущенный XML вне `res/` — только SECRET-006, с путём |

Улучшения точности без FP (по тем же данным): `tools:ignore="Exported…"` → info/needs_review «экспорт намеренный»
(AntennaPod ×4, Thunderbird, Nextcloud); сводка runtime-разрешений библиотечных модулей не дублируется (Thunderbird ×5);
AGP 9 `optimization { enable = … }` считается за R8.

## Раунд 2 (после исправлений): 69 находок, 0 FP

TP — верный факт, который стоит ревью (в т. ч. info). Deb — факт верен, но по замыслу приложения (точка входа,
отладочное/демо-приложение, протокол требует).

| Правило | Всего | TP | Deb | FP | Строго (TP) | Мягко (TP+Deb) |
|---|---|---|---|---|---|---|
| ANDROID-EXPORT-001 | 38 | 22 | 16 | 0 | 58% | 100% |
| ANDROID-NET-003 | 4 | 4 | 0 | 0 | 100% | 100% |
| ANDROID-BACKUP-004 | 6 | 5 | 1 | 0 | 83% | 100% |
| ANDROID-PERMS-005 | 6 | 6 | 0 | 0 | 100% | 100% |
| ANDROID-SECRET-006 | 3 (info, `AIza`) | 3 | 0 | 0 | 100% | 100% |
| ANDROID-MINIFY-007 | 2 | 1 | 1 | 0 | 50% | 100% |
| ANDROID-KEYSTORE-009 | 2 | 2 | 0 | 0 | 100% | 100% |
| ANDROID-WEBVIEW-010 | 3 | 0 | 3 | 0 | 0% | 100% |
| ANDROID-CRYPTO-012 | 1 | 0 | 1 | 0 | 0% | 100% |
| ANDROID-STORAGE-013 | 4 (info) | 4 | 0 | 0 | 100% | 100% |
| ANDROID-DEBUG-002, SIGNING-008, TLS-011, LOG-014 | 0 | — | — | — | — | — |
| **Итого** | **69** | **47** | **22** | **0** | **68%** | **100%** |

Разбор по приложениям:

- **NewPipe (10):** WEBVIEW мост в `PoTokenWebView` (JS включён; страница — BotGuard YouTube) → Deb; EXPORT
  `PanicResponderActivity`, `RouterActivity` (low) → Deb; BACKUP (allowBackup, targetSdk 35), PERMS
  `SYSTEM_ALERT_WINDOW` + сводка, EXPORT info ×3 (MediaButton, PlayerService, FilePicker), SECRET info (публичный
  ключ innertube `AIza…`) → TP.
- **Thunderbird (9):** BACKUP k9mail/thunderbird → TP; BACKUP и MINIFY (convention-скрипт
  `thunderbird.app.android.compose`) у демо-приложения `components/ui/catalog` → Deb; CRYPTO MD5 в `Authentication.java`
  (CRAM-MD5 требует протокол) → Deb; KEYSTORE тестовый `mail/testing/.../keystore.jks` (low) → TP; EXPORT
  `SettingsProvider` (info, `tools:ignore`: намеренный экспорт для миграции — проверять подпись вызывающего), info ×2 → TP.
  Release `isMinifyEnabled = minify.get()` — честно `partial` (exit 2).
- **Nextcloud (25):** EXPORT `ComposeActivity`, `FileContentProvider`, `SsoGrantPermissionActivity` (medium) → TP (те же,
  что в полевом тесте APK); NET cleartext + user CA (для self-hosted, намеренно, но факт) → TP; MINIFY (release без R8)
  → TP; KEYSTORE `.github/workflows/QA_keystore.jks` (medium) → TP; PERMS ×2, SECRET info ×2 (`AIza` в gplay), STORAGE
  push-токен, EXPORT info ×7 → TP; EXPORT low ×4 (`ModifiedAuthenticatorActivity`, `FileDisplayActivity`,
  `AuthenticatorActivity`, `BootupBroadcastReceiver`) и WEBVIEW ×2 (JS включается в базовом классе) → Deb.
  `gradle/verification-metadata.xml` > 1 МиБ — `partial` только SECRET-006.
- **AntennaPod (22):** NET ×2, BACKUP, PERMS, EXPORT info ×6 (в т. ч. 4 с `tools:ignore`), STORAGE ×3 (пароли синхронизации,
  родительского контроля, прокси — в открытых SharedPreferences) → TP; EXPORT medium `WearDataListenerService` (GMS Wear)
  и low ×8 (MainActivity, виджеты, системные broadcast'ы с своими действиями) → Deb. `android:enabled="${…}"` без
  литерала в Gradle — честно `partial`.
- **Aegis (3):** BACKUP (правила объявлены, не анализировались), PERMS → TP; `PanicResponderActivity` → Deb.

## Что НЕ видно из исходников (сверка с полевым тестом APK 2026-11-12)

- K-9 `androidx.compose.ui.tooling.PreviewActivity` (TP в APK) объявлена в манифесте AAR-библиотеки — в исходниках
  её нет: ограничение «манифесты внешних библиотек не видны» (оно в отчёте).
- Итоговый набор разрешений APK больше: их добавляют AAR.

## Возможные улучшения общих правил APK (пока не внесены)

- В `PUBLIC_ENTRY_ACTIONS` нет `android.appwidget.action.APPWIDGET_CONFIGURE` (документированная точка входа
  конфигурации виджета; AntennaPod `WidgetConfigActivity` → low вместо info).
- Действия Wear OS Data Layer (`com.google.android.gms.wearable.*`) вызывает Google Play services — кандидат в
  «публичные точки входа» с пометкой.
