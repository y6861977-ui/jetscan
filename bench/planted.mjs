// Builds a git repository with planted FAKE secrets (random values in each provider's real
// format, with real checksums where the format has one) and decoys that are not secrets.
// Writes truth.json: what is where. Usage: node planted.mjs <empty-dir> [seed]
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

const dir = process.argv[2];
let state = Number(process.argv[3] || 7) >>> 0;
const rnd = () => { state ^= state << 13; state >>>= 0; state ^= state >>> 17; state ^= state << 5; state >>>= 0; return state / 2 ** 32; };
const pick = (alphabet, n) => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join('');
const AZ = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', az = 'abcdefghijklmnopqrstuvwxyz', D = '0123456789';
const B62 = D + AZ + az, HEX = '0123456789abcdef', URL = B62 + '_-', B32 = AZ + '234567';
const crc32 = (s) => { let c, crc = 0xffffffff; for (const ch of Buffer.from(s)) { c = (crc ^ ch) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; } return (crc ^ 0xffffffff) >>> 0; };
const base62 = (n, len) => { let s = ''; do { s = B62[n % 62] + s; n = Math.floor(n / 62); } while (n > 0); return s.padStart(len, '0'); };
const withCrc = (prefix, body) => `${prefix}${body}${base62(crc32(body), 6)}`;

const pem = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).trim();

// [id, provider, file, how it appears in the file]
const secrets = [
  ['aws-key', 'AWS access key ID', 'config/aws.py', (v) => `AWS_ACCESS_KEY_ID = "${v}"`, 'AKIA' + pick(B32, 16)],
  ['aws-secret', 'AWS secret access key', 'config/aws.py', (v) => `AWS_SECRET_ACCESS_KEY = "${v}"`, pick(B62 + '/+', 40)],
  ['github-classic', 'GitHub token (ghp_)', 'scripts/release.sh', (v) => `export GITHUB_TOKEN=${v}`, withCrc('ghp_', pick(B62, 30))],
  ['github-fine', 'GitHub fine-grained token', '.env', (v) => `GH_PAT=${v}`, `github_pat_11${pick(AZ + D, 20)}_${pick(B62, 59)}`],
  ['gitlab', 'GitLab token', 'ci/deploy.yml', (v) => `      GITLAB_TOKEN: ${v}`, 'glpat-' + pick(URL, 20)],
  ['slack-bot', 'Slack bot token', 'bot/settings.json', (v) => `{ "slack_token": "${v}" }`, `xoxb-${pick(D, 12)}-${pick(D, 13)}-${pick(B62, 24)}`],
  ['slack-webhook', 'Slack webhook URL', 'bot/notify.js', (v) => `const hook = "${v}";`, `https://hooks.slack.com/services/T${pick(AZ + D, 10)}/B${pick(AZ + D, 10)}/${pick(B62, 24)}`],
  ['stripe', 'Stripe live secret key', 'billing/stripe.rb', (v) => `Stripe.api_key = "${v}"`, 'sk_live_51' + pick(B62, 97)],
  ['google', 'Google API key', 'web/maps.html', (v) => `<script src="https://maps.googleapis.com/maps/api/js?key=${v}"></script>`, 'AIza' + pick(URL, 35)],
  ['openai', 'OpenAI API key', 'ai/client.py', (v) => `client = OpenAI(api_key="${v}")`, `sk-proj-${pick(URL, 74)}T3BlbkFJ${pick(URL, 74)}`],
  ['anthropic', 'Anthropic API key', 'ai/claude.ts', (v) => `const client = new Anthropic({ apiKey: "${v}" });`, `sk-ant-api03-${pick(URL, 93)}AA`],
  ['npm', 'npm token', '.npmrc', (v) => `//registry.npmjs.org/:_authToken=${v}`, withCrc('npm_', pick(B62, 30))],
  ['pypi', 'PyPI token', '.pypirc', (v) => `[pypi]\nusername = __token__\npassword = ${v}`, 'pypi-AgEIcHlwaS5vcmc' + pick(URL, 120)],
  ['sendgrid', 'SendGrid API key', 'mail/send.go', (v) => `const sendgridKey = "${v}"`, `SG.${pick(URL, 22)}.${pick(URL, 43)}`],
  ['twilio', 'Twilio API key SID', 'sms/twilio.php', (v) => `$sid = "${v}";`, 'SK' + pick(HEX, 32)],
  ['shopify', 'Shopify access token', 'shop/config.yml', (v) => `access_token: ${v}`, 'shpat_' + pick(HEX, 32)],
  ['digitalocean', 'DigitalOcean token', 'infra/main.tf', (v) => `  token = "${v}"`, 'dop_v1_' + pick(HEX, 64)],
  ['huggingface', 'Hugging Face token', 'ml/train.py', (v) => `HF_TOKEN = "${v}"`, 'hf_' + pick(AZ + az, 34)],
  ['telegram', 'Telegram bot token', 'bot/telegram.py', (v) => `TOKEN = "${v}"`, `${pick('123456789', 1)}${pick(D, 9)}:AA${pick(URL, 33)}`],
  // The first part of a Discord bot token is the bot's numeric id (a snowflake) in base64.
  ['discord', 'Discord bot token', 'bot/discord.js', (v) => `client.login("${v}");`,
    `${Buffer.from('1' + pick(D, 17)).toString('base64').replace(/=+$/, '')}.${pick(URL, 6)}.${pick(URL, 38)}`],
  ['rsa-key', 'RSA private key', 'deploy/id_rsa', (v) => v, pem],
  ['postgres-url', 'Database URL with password', 'docker-compose.yml', (v) => `      DATABASE_URL: ${v}`, `postgres://app:${pick(B62, 20)}@db.internal:5432/app`],
  ['env-password', 'Password in .env', '.env.production', (v) => `DB_PASSWORD=${v}`, pick(B62 + '!@#%', 20)],
];

// Not secrets: a scanner should stay quiet on all of these.
const decoys = [
  ['aws-docs-example', 'docs/aws.md', 'Example from the AWS docs: `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`'],
  ['placeholder-github', 'docs/setup.md', 'export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'],
  ['placeholder-stripe', 'docs/billing.md', 'Stripe.api_key = "sk_live_your_key_here"'],
  ['env-reference', 'ci/build.yml', '      API_KEY: ${{ secrets.API_KEY }}\n      DB_PASSWORD: ${DB_PASSWORD}'],
  ['sha256', 'checksums.txt', `${createHash('sha256').update('a').digest('hex')}  app-linux-x64.tar.gz`],
  ['uuid', 'fixtures/ids.json', '{ "request_id": "3f2c9a8e-7b41-4d2a-9c3e-1a5b6d7e8f90" }'],
  ['npm-integrity', 'package-lock.json', `{ "packages": { "node_modules/left-pad": { "version": "1.3.0", "integrity": "sha512-${createHash('sha512').update('left-pad').digest('base64')}" } } }`],
  ['git-sha', 'CHANGELOG.md', '- Fix crash on empty input (a94a8fe5ccb19ba61c4c0873d391e987982fbbd3)'],
  ['base64-image', 'web/logo.css', `.logo { background: url(data:image/png;base64,${Buffer.from(pick(B62, 120)).toString('base64')}); }`],
  ['password-prompt', 'src/login.py', 'password = getpass.getpass("Password: ")'],
];

if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
mkdirSync(dir, { recursive: true });
const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' });
git('init', '-q', '-b', 'main'); git('config', 'user.name', 'Bench'); git('config', 'user.email', 'bench@example.com');
git('config', 'core.autocrlf', 'false');
const files = new Map();
const add = (file, text) => files.set(file, (files.has(file) ? files.get(file) + '\n' : '') + text);
const flush = () => { for (const [f, t] of files) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t + '\n'); } };

// Commit 1: everything. Commit 2: every other secret removed, so it lives only in history.
const truth = { secrets: [], decoys: decoys.map(([id, file]) => ({ id, file })) };
secrets.forEach(([id, provider, file, render, value], i) => {
  add(file, render(value));
  truth.secrets.push({ id, provider, file, value, line: files.get(file).split('\n').findIndex((l) => l.includes(value.split('\n')[0])) + 1, only_in_history: i % 2 === 1 });
});
for (const [, file, text] of decoys) add(file, text);
flush(); git('add', '-A'); git('commit', '-q', '-m', 'Initial import');
for (const s of truth.secrets.filter((s) => s.only_in_history)) {
  const [, , , render] = secrets.find(([id]) => id === s.id);
  files.set(s.file, files.get(s.file).replace(render(s.value), '# moved to the secret manager'));
}
for (const f of files.keys()) rmSync(join(dir, f), { force: true });
flush(); git('add', '-A'); git('commit', '-q', '-m', 'Move secrets to the secret manager');
writeFileSync(join(dirname(dir), 'truth.json'), JSON.stringify(truth, null, 2));
console.log(`${truth.secrets.length} secrets (${truth.secrets.filter((s) => s.only_in_history).length} only in history), ${decoys.length} decoys`);
