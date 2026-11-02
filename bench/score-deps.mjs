// Compares jetscan deps --json and trivy fs --format json on the same directory.
// A vulnerability is "the same" when package, version and advisory match (by id or alias).
import { readFileSync } from 'node:fs';
const [name, jetFile, trivyFile] = process.argv.slice(2);
const jet = JSON.parse(readFileSync(jetFile, 'utf8')).findings.map((f) => ({
  pkg: `${f.package.toLowerCase()}@${f.version}`, ids: new Set([f.id, ...(f.aliases || [])]) }));
const trivy = (JSON.parse(readFileSync(trivyFile, 'utf8')).Results || []).flatMap((r) => (r.Vulnerabilities || []).map((v) => ({
  pkg: `${(v.PkgName || '').toLowerCase()}@${v.InstalledVersion}`, ids: new Set([v.VulnerabilityID, ...(v.VendorIDs || [])]) })));
// Trivy lists one entry per (package, advisory, lockfile); dedupe both sides by package + advisory.
const dedupe = (list) => { const out = []; for (const x of list) { if (!out.some((y) => y.pkg === x.pkg && [...x.ids].some((i) => y.ids.has(i)))) out.push(x); } return out; };
const J = dedupe(jet), T = dedupe(trivy);
const same = (a, b) => a.pkg === b.pkg && [...a.ids].some((i) => b.ids.has(i));
const both = J.filter((j) => T.some((t) => same(j, t))).length;
const pk = (l) => new Set(l.map((x) => x.pkg)).size;
console.log(`| ${name} | ${J.length} (${pk(J)} pkgs) | ${T.length} (${pk(T)} pkgs) | ${both} | ${J.length - both} | ${T.filter((t) => !J.some((j) => same(j, t))).length} |`);
if (process.env.SHOW) {
  for (const t of T.filter((t) => !J.some((j) => same(j, t)))) console.log('  only trivy:', t.pkg, [...t.ids].join(','));
  for (const j of J.filter((j) => !T.some((t) => same(j, t)))) console.log('  only jetscan:', j.pkg, [...j.ids].join(','));
}
