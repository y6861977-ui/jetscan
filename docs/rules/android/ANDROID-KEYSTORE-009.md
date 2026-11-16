# ANDROID-KEYSTORE-009 — хранилище ключей в дереве проекта

**Статус:** реализовано (`src/android_audit/rules/secret.rs (`keystores`)`). **Категория:** `secret_exposure`. **CWE:** CWE-321.
**MASVS:** категория MASVS-RESILIENCE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Файлы `*.jks`, `*.keystore`, `*.bks`, `*.p12`, `*.pfx` — **только по имени, содержимое не открывается никогда**.

| Условие | Severity / Confidence |
|---|---|
| на файл указывает `storeFile` конфига с литеральными паролями (SIGNING-008) | high / potential |
| прочие | medium / potential |
| имя с `debug`, или в тестовом каталоге | low / needs_review |
| в `.gitignore` | low / needs_review |

Git не запускается: «в репозитории» — значит в папке проекта; `.gitignore` сопоставляется упрощённо.

## Полевой тест (2026-11-16, `FIELD.md`)
Хранилище в модуле тестовых утилит (`mail/testing/src/main/resources/keystore.jks`) — low/needs_review.

## Фикстуры
Позитив: `insecure-app/app/release.jks` (+ пароли в Gradle → high), тест `kotlin_signing_and_keystores`
(`keys/upload.jks` → high, `debug.keystore` → low, git-ignored → low). Негатив: `hardened-app` (нет хранилищ).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Хранить ключи вне репозитория (Play App Signing, секреты CI); если хранилище публиковалось — сменить ключ загрузки.
