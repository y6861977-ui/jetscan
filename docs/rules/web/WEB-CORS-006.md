# WEB-CORS-006 — CORS пускает чужие сайты с credentials

**Статус:** реализовано (`src/web_audit/rules/cors.rs`). **Категория:** `cors`.
**CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains). **ASVS:** не сопоставлено.

## Риск
Если сервер копирует `Origin` запроса в `Access-Control-Allow-Origin` и отвечает
`Access-Control-Allow-Credentials: true`, любой сайт, который откроет вошедший пользователь, может
вызвать API с его cookies и прочитать ответ.

## Уровни
| Что в файле | Severity / Confidence |
|---|---|
| Origin берётся из запроса (`req.headers.origin`, `headers.get("origin")`) + Credentials `true`, не дальше 5 строк друг от друга | high / potential |
| `cors({ origin: true, credentials: true })` или `origin: (o, cb) => cb(null, true)` + credentials | high / potential |
| `Access-Control-Allow-Origin: *` + Credentials `true` (в т. ч. `next.config` `{ key, value }`, `cors({ origin: "*", credentials: true })`) | low / needs_review |

Пара `*` + credentials браузером отвергается — это сломанная настройка, а не утечка; низкий уровень
стоит потому, что её типично «чинят» отражением Origin. Одна находка на файл (отражение важнее).
`potential`, а не `confirmed`: эндпоинт может не использовать cookies или не отдавать ничего ценного.

## Не находка
`*` без credentials (публичный API); `cors({ origin: [...allowlist], credentials: true })`;
`cors({ origin: true })` без credentials; значение Origin — переменная после проверки по списку;
заголовки Origin и Credentials в разных местах файла (> 5 строк).

## Фикстуры
`fixtures/web/next-routes/`: позитив — `app/api/cors-reflect/route.ts:5` (high),
`server/express.ts:6` (high), `app/api/cors-star/route.ts:5` (low), `next.config.mjs:13` (low);
негатив — `app/api/cors-public/route.ts` (`*` без credentials + allowlist в другой функции),
`server/express-safe.ts`. Тест: `web_cors_006_next_routes`.

## Что делать
Явный список разрешённых origin; `Vary: Origin`; credentials — только для своих доменов.
Проверка вручную: запрос с `Origin: https://evil.example` и cookie сессии — ответ не должен
содержать этот origin в `Access-Control-Allow-Origin`.

## Ограничения
`const o = req.headers.origin; setHeader("Access-Control-Allow-Origin", o)` — отражение через
переменную не видно (пропуск). Конфиги хостинга (`vercel.json`, nginx) не читаются.
