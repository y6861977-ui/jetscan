// Scores findings on Plazmaz/leaky-repo with the repo's own method (.leaky-meta/benchmark.py):
// per file, expected = risk + informative lines from secrets.csv; found = number of findings;
// false positives = max(found - expected, 0); finds = found - false positives.
import { readFileSync } from 'node:fs';
const [csvFile, jetscanFile, gitleaksFile] = process.argv.slice(2);
const expected = new Map();
for (const line of readFileSync(csvFile, 'utf8').split(/\r?\n/)) {
  if (!line.trim() || line.startsWith('#')) continue;
  const [name, risk, info] = line.split(',');
  expected.set(name.trim(), Number(risk) + Number(info));
}
const norm = (p) => p.replace(/\\/g, '/').replace(/^\.\//, '');
const tools = {
  jetscan: JSON.parse(readFileSync(jetscanFile, 'utf8')).findings.map((f) => norm(f.path)),
  gitleaks: JSON.parse(readFileSync(gitleaksFile, 'utf8')).map((f) => norm(f.File)),
};
const total = [...expected.values()].reduce((a, b) => a + b, 0);
const out = {};
for (const [tool, files] of Object.entries(tools)) {
  const counts = new Map();
  for (const f of files) counts.set(f, (counts.get(f) || 0) + 1);
  let finds = 0, fps = 0, covered = 0;
  const rows = {};
  for (const [name, exp] of expected) {
    const found = counts.get(name) || 0;
    const fp = Math.max(found - exp, 0);
    finds += found - fp; fps += fp; if (found) covered++;
    rows[name] = `${found}/${exp}`;
  }
  const outside = [...counts].filter(([f]) => !expected.has(f));
  out[tool] = { finds, fps, covered, rows, outside };
  console.log(`${tool}: files covered ${covered}/${expected.size}, finds ${finds}/${total} (${(100 * finds / total).toFixed(1)}%), false positives ${fps}, findings outside the answer key ${outside.reduce((a, [, n]) => a + n, 0)}`);
}
console.log('\n| File | expected | jetscan | gitleaks |\n|---|---|---|---|');
for (const [name, exp] of expected) console.log(`| ${name} | ${exp} | ${out.jetscan.rows[name].split('/')[0]} | ${out.gitleaks.rows[name].split('/')[0]} |`);
for (const t of Object.keys(out)) if (out[t].outside.length) console.log(`\n${t} outside the key: ${out[t].outside.map(([f, n]) => `${f}(${n})`).join(', ')}`);
