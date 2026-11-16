# WEB-FIREBASE-010 — открытые правила безопасности Firebase

**Статус:** реализовано (`src/web_audit/rules/firebase.rs`). **Категория:** `access_control`.
**CWE:** CWE-862. **Уверенность:** никогда не `confirmed` — развёрнутые правила могут отличаться от файла.

## Риск
Firebase-конфиг веб-приложения (`apiKey: "AIza…"`, `projectId`) публичен по замыслу и **находкой не
является**. Данные Firestore, Cloud Storage и Realtime Database защищают только правила безопасности:
«тестовый режим», `if true` или «любой вошедший» на всю базу означают, что базу читает и меняет любой,
кто откроет DevTools.

## Что читается (только файлы, к проекту не подключаемся)
| Файл | Язык |
|---|---|
| `*.rules` с `service cloud.firestore` / `service firebase.storage` (`firestore.rules`, `storage.rules`) | правила Firebase |
| `*.rules.json` с ключом `"rules"` (`database.rules.json`) | JSON (комментарии `//`, `/* */` допускаются) |
| `firebase.json` | какие файлы правил подключены (значения `"rules"`) |

`*.rules` без этих `service` (udev, прочие DSL) молча пропускается; `*.rules.json` без `"rules"` — тоже.
Файл из `firebase.json`, которого нет среди разобранных (другое имя, вне корня), — в `limitations`.

## Разбор
Правила Firestore/Storage: блоки `service`, вложенные `match` с путями (`/{document=**}`, `{x}`),
`allow <ops>[: if <условие>];`, функции `function f() { … return expr; }` без параметров (их `return`
подставляется в условие). Комментарии вырезаны. Условие сравнивается по тексту без пробелов и внешних
скобок:
- `true` или `allow read;` без условия → открыто;
- `request.time < timestamp.date(Y, M, D)` → тестовый режим (дата — в заголовке);
- `request.auth != null` (и равносильные короткие формы) → «любой вошедший»;
- всё прочее (сравнение владельца, `get()`/`exists()`, функции с параметрами) → не находка.

RTDB: `.read`/`.write` со значением `true`/`"true"` → открыто; `"now < <мс>"` → тестовый режим;
`"auth != null"` → «любой вошедший». Путь — цепочка ключей под `rules`, `$var` — подстановка.

## Находки
| Что | Severity / Confidence |
|---|---|
| Открыто на запись (`write`/`create`/`update`/`delete`) где угодно | high / potential |
| Открыто на чтение всей базы/всех файлов (`/{x=**}` сразу под корнем, RTDB — корень) | high / potential |
| Открыто на чтение «личной» коллекции (users, orders, messages…) | high / potential |
| Открыто на чтение «публичной» коллекции (posts, products…; Storage: public, avatars, images…) | low / needs_review |
| Открыто на чтение прочей коллекции/пути | medium / needs_review |
| Тестовый режим (`request.time < timestamp.date(…)`, `"now < …"`) | high / potential |
| Только `request.auth != null` на всю базу / все файлы (RTDB — на корне) | medium / needs_review |

Сравнение с часами не делается (вывод детерминирован): тестовый режим с прошедшей датой всё равно
находка — обычно такое правило продлевают, а не исправляют. `jetscan:ignore` на строке `allow`/ключа —
подавление. `id` — от (правило, путь файла, сервис, путь match, операции, вид), без номера строки.

## Проверка `WEB-FIREBASE-010`
- Файлы правил разобраны → `completed` (`partial`, если файл не дочитан до конца: незакрытый блок,
  битый JSON — или бюджет обхода).
- Firebase в зависимостях (`firebase`, `firebase-admin`, `reactfire`, `@angular/fire`, `vuefire`) или
  `firebase.json` в корне, а файлов правил нет → `skipped`, `not_checked: … copy the deployed rules from
  the Firebase console …`.
- Иначе `skipped`, `not_applicable`.

## Ограничения
- Правила из консоли Firebase не видны: файл может быть устаревшим.
- Условия с данными (`get()`, `exists()`, `resource.data`), функции с параметрами, `||` с открытой
  веткой (`if true || …`) не оцениваются; «любой вошедший» на отдельной коллекции не сообщается.
- Не разбираются `.bolt`, правила, собранные скриптами, и пути из `firebase.json` к файлам с другим
  расширением (только сообщаются в `limitations`).

## Фикстуры и тесты
`fixtures/web/firebase-rules/` (позитивы и негативы помечены в комментариях; `config/99-usb.rules` —
не Firebase; `src/firebase.ts` — публичный apiKey, не находка). Тесты: `web_firebase_010_rules_files`,
`web_firebase_010_skipped_without_rules` (`src/web_audit/tests.rs`), модульные — в `firebase.rs`.

## Что делать
Писать правила по владельцу: `allow read, write: if request.auth != null && request.auth.uid == userId;`
для `/users/{userId}`; общую `match /{document=**}` не открывать; тестовый режим заменить до запуска.
Проверить развёрнутые правила в консоли Firebase (Rules Playground).
