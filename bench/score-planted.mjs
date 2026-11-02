// Scores jetscan and gitleaks findings against truth.json (planted repo).
// A planted secret counts as found when a finding points at its file and line.
// A finding that matches no planted secret is a false positive (decoys are where they should come from).
import { readFileSync } from 'node:fs';
const [truthFile, jetscanFile, gitleaksFile] = process.argv.slice(2);
const truth = JSON.parse(readFileSync(truthFile, 'utf8'));
const norm = (p) => p.replace(/\\/g, '/').replace(/^\.\//, '');
const jet = JSON.parse(readFileSync(jetscanFile, 'utf8')).findings.map((f) => ({ file: norm(f.path), line: f.line, rule: f.rule }));
const gl = JSON.parse(readFileSync(gitleaksFile, 'utf8')).map((f) => ({ file: norm(f.File), line: f.StartLine, rule: f.RuleID }));

function score(name, findings) {
  const used = new Set();
  const rows = truth.secrets.map((s) => {
    const hits = findings.map((f, i) => [f, i]).filter(([f]) => f.file === s.file && f.line === s.line);
    hits.forEach(([, i]) => used.add(i));
    return { id: s.id, found: hits.length > 0, rules: hits.map(([f]) => f.rule) };
  });
  const extra = findings.filter((_, i) => !used.has(i));
  const decoyFiles = new Set(truth.decoys.map((d) => d.file));
  return { name, found: rows.filter((r) => r.found).length, rows, extra, decoyHits: extra.filter((f) => decoyFiles.has(f.file)) };
}
const results = [score('jetscan', jet), score('gitleaks', gl)];
console.log(`| Secret | history only | jetscan | gitleaks |\n|---|---|---|---|`);
truth.secrets.forEach((s, i) => console.log(`| ${s.provider} | ${s.only_in_history ? 'yes' : ''} | ${results[0].rows[i].found ? '✓' : '✗'} | ${results[1].rows[i].found ? '✓' : '✗'} |`));
for (const r of results) {
  console.log(`\n${r.name}: found ${r.found}/${truth.secrets.length}; other findings ${r.extra.length} (on decoys: ${r.decoyHits.length})`);
  for (const f of r.extra) console.log(`  extra: ${f.file}:${f.line} ${f.rule}`);
}
