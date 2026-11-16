# WEB-DEBUG-007 — публичные source maps в продакшен-сборке

**Статус:** реализовано, только конфиги (`src/web_audit/rules/debug.rs`).
**Категория:** `information_disclosure`. **CWE:** CWE-540 (Inclusion of Sensitive Information in
Source Code). **ASVS:** не сопоставлено.

## Риск
Source map отдаёт браузеру исходный код с комментариями и путями. Это не секрет и не уязвимость
сама по себе, но упрощает анализ приложения и иногда раскрывает то, что не предназначалось
пользователю. Поэтому `low`.

## Что проверяется
| Конфиг | Находка (low / potential) | Не находка |
|---|---|---|
| `next.config.*` | `productionBrowserSourceMaps: true` | `false`, другие опции (`experimental.serverSourceMaps`) |
| `vite.config.*` | `sourcemap: true`, `sourcemap: "inline"` | `"hidden"` (файлы есть, бандл на них не ссылается), `css.devSourcemap` |

Упоминания в комментариях и строках не считаются. `potential`: отдаёт ли хостинг `.map` наружу,
без деплоя не узнать.

## Почему не больше
Роадмап предлагал ещё «debug-настройки в продакшене» и проверку артефактов сборки. Артефакты
(`.next`, `dist`) мы не читаем, а флаги отладки в коде (`DEBUG = true`, `console.log`) без рантайма
не отличить от разработческих — это был бы шум. Расширение — только с артефактом сборки на входе.

## Фикстуры
`fixtures/web/next-routes/next.config.mjs:4`, `fixtures/web/vite-react/vite.config.ts:12` (позитив;
`css.devSourcemap` там же — негатив); негатив `sourcemap: 'hidden'`, `productionBrowserSourceMaps: false`,
закомментированный и строковый вариант — в тесте `web_debug_007_source_maps`.

## Что делать
Выключить, либо собирать `hidden` source maps и загружать их только в трекер ошибок.
