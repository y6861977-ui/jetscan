# WEB-XSS-003 — неконстантный HTML в DOM-синке

**Статус:** реализовано, только `potential` (`src/web_audit/rules/xss.rs`). **Категория:** `xss`.
**CWE:** CWE-79. **ASVS:** не сопоставлено.

## Риск
Синк превращает строку в живой HTML. Если туда попадают данные пользователя без очистки — XSS.

## Синки
`dangerouslySetInnerHTML={{ __html: X }}` (и объектная форма), `el.innerHTML = X` / `+=`,
`el.outerHTML = X`, `el.insertAdjacentHTML(pos, X)`, `document.write(X)` / `writeln(X)`.
Проверяются все не-тестовые JS/TS-файлы — серверный рендер с `dangerouslySetInnerHTML` тоже даёт XSS.

## Уровни

| X | Результат |
|---|---|
| Только литералы (`"<b>x</b>"`, `"a" + "b"`, шаблон без `${}`) | не находка |
| Константа по построению: в шаблоне/склейке только `process.env.*` / `import.meta.env.*` (значения сборки/оператора) и локальные переменные, которым присваиваются только литералы; `JSON.stringify` литерала или константы модуля из литералов | не находка |
| Целиком вызов `*safe*`/`*sanitize*`/`*purify*`/`*escape*`/`xss`/`encodeHtml` (`markdownToSafeHTML(x)`, `DOMPurify.sanitize(x)`) | не находка |
| Целиком вызов функции, определённой в проекте, чей файл использует санитайзер (`sanitize-html`, `dompurify`, `isomorphic-dompurify`, `xss`, `DOMPurify.sanitize(`) — импортированной или объявленной в том же файле | не находка |
| Файл использует подсветку (`shiki`, `@shikijs/*`, `prismjs`, `highlight.js`, `lowlight`, `refractor`, `codeToHtml(`) — её вывод экранирован | info / potential |
| Значение целиком `JSON.stringify(…)` (или шаблон, в котором только `${JSON.stringify(…)}`) в атрибутах `<script>` / `<Script>` с JSON-типом: `application/ld+json`, `application/json`, `speculationrules`, `importmap` (тег ищется не дальше 400 байт назад, `type` — до или после синка) | low / potential, с пометкой «`</script>` не экранируется» |
| В выражении виден источник (`location`, `searchParams`, `params.`, `.value`, `document.cookie`, `window.name`, `req.query`, `event.data`, ...) | high / potential |
| Иное | medium / potential |

`potential` всегда: поток данных не отслеживается, эксплуатируемость не утверждается.
Фрагмент показывает строку синка со скрытыми литералами; если значение (`__html: …`) на другой строке —
и её тоже (через ` … `).

Правила выше добавлены по полевому тесту 2026-11-12 (паттерны 5–8; было 7% точности, 22 из 30 FP).
Фикстура `fixtures/web/xss-patterns/`.

## Не находка
Сравнение `el.innerHTML === ""`, `textContent`, закомментированный синк, тестовые файлы,
`innerHTMLx` и подобные имена.

## Фикстуры
`fixtures/web/next-app/app/components/Comment.tsx`: позитив — строки 10, 11, 25, 26; негатив —
12 (константа), 13 (DOMPurify), 23 (конкатенация литералов), 24 (`escapeHtml`), 27, 28, 29.
Тесты: `web_xss_003_*`.

## Что делать
Рендерить как текст (JSX `{value}`, `textContent`). Если HTML нужен — пропускать через проверенный
санитайзер (например, DOMPurify) прямо в месте синка; для URL-параметров — никогда не вставлять
как HTML.

## Ограничения
Имя функции-санитайзера принимается на веру (её код не проверяется) — это осознанный компромисс,
описанный здесь; кастомная функция с «escape» в имени может быть некорректной. Источник ищется
только в самом выражении: `const h = location.hash; el.innerHTML = h` даст `medium`, не `high`.
