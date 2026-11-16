# WEB-ENV-002 — секрет в публичной переменной окружения (`NEXT_PUBLIC_*`, `VITE_*`)

**Статус:** реализовано (`src/web_audit/rules/env.rs`). **Категория:** `secret_exposure`.
**CWE:** CWE-200; при значении в формате ключа ещё CWE-798. **ASVS:** не сопоставлено.

## Риск
Next.js при сборке подставляет значения `NEXT_PUBLIC_*` в клиентский JavaScript; Vite отдаёт `VITE_*`
клиентскому коду через `import.meta.env`. Секрет в такой переменной уходит в браузер. Ядро
(`jetscan secrets`) такие ключи пропускает намеренно — слово `PUBLIC` для него признак публичного
значения (`src/secrets/special.rs`), поэтому это отдельное правило.

Префикс зависит от фреймворка: Next — `NEXT_PUBLIC_`, Vite — `VITE_`, неизвестный — оба.

## Уровни

| Что найдено | Severity / Confidence |
|---|---|
| `.env*`: значение публичной переменной в привилегированном формате ядра (`sk_live_`, `ghp_`, ...) | critical / potential |
| `.env*`: имя с `SECRET`/`PASSWORD`/`PASSWD`/`PWD`/`PRIVATE`/`SERVICE_ROLE`, значение не заглушка | high / needs_review |
| Клиентский/общий код читает `process.env.NEXT_PUBLIC_*SECRET*` / `import.meta.env.VITE_*SECRET*`, которой нет в `.env*` | high / needs_review |

Находка по `.env*` сообщает, читается ли переменная в просканированном клиентском коде и где
(`tags: referenced:true/false`). Даже при чтении — `potential`: сборку мы не запускаем.

## Не находка
- Публичные по замыслу имена: `PUBLISHABLE`, `ANON`, `PUBLIC`, `SITE`, `DSN`, `CLIENTID`
  (`NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`, `…_SUPABASE_ANON_KEY`, `…_RECAPTCHA_SITE_KEY`).
  Firebase `apiKey` (`AIza…`) — публичный.
- Пустые значения, заглушки (`your_…`, `<…>`, `changeme`, `xxx`, `${VAR}`), флаги и числа.
- Переменные без публичного префикса; префикс другого фреймворка (`VITE_` в Next.js).
- Чтение в серверном файле; упоминание внутри строки; `jetscan:ignore`.
- Значение — ключ Supabase service-role/secret: это WEB-SUPABASE-005 (без дубля).
- `.env.example` / `.sample` / `.template` / `.dist` не читаются.

## Фикстуры
`fixtures/web/next-app/dot-env.local` (строки 4, 6 — позитив; остальное — негатив),
`fixtures/web/next-app/app/components/Analytics.tsx:7` (позитив по чтению), строка 5 там же —
перекрёстная ссылка, `app/api/pay/route.ts` — серверное чтение (негатив),
`fixtures/web/vite-react/dot-env:4` + `src/github.ts`. Тесты: `web_env_002_*`.

## Что делать
1. Если значение — настоящий ключ: **перевыпустить**, он уже мог попасть в задеплоенный бандл.
2. Убрать публичный префикс, читать переменную только в серверном коде; в клиент отдавать результат
   серверного вызова, а не ключ.

## Ограничения
Свой `envPrefix` в `vite.config`, блок `env`/`publicRuntimeConfig` в `next.config`, CRA `REACT_APP_`
не разбираются. Динамическое чтение `process.env[name]` не распознаётся.
