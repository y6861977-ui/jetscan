#!/usr/bin/env bash
# Reproduces bench/README.md. Needs git, node, and jetscan, gitleaks and trivy on PATH
# (or JETSCAN=, GITLEAKS=, TRIVY= pointing at the binaries). Works in Git Bash on Windows.
# Usage: bench/run.sh <work-dir>
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?usage: bench/run.sh <work-dir>}
JETSCAN=${JETSCAN:-jetscan} GITLEAKS=${GITLEAKS:-gitleaks} TRIVY=${TRIVY:-trivy}
mkdir -p "$work/repos" "$work/out"
cd "$work"
"$JETSCAN" --version; "$GITLEAKS" version; "$TRIVY" --version | head -1

# Repositories at the commits used in README.md.
while read -r name repo commit; do
  [ -d "repos/$name" ] && continue
  git init -q "repos/$name"
  git -C "repos/$name" fetch -q --depth 1 "https://github.com/$repo.git" "$commit"
  git -C "repos/$name" checkout -q FETCH_HEAD
done <<'EOF'
leaky-repo Plazmaz/leaky-repo 2e951359cac53addbee56437da3ffb546e3dfe24
express expressjs/express bcc0551cb7a785b7772f77cb59ce55a2bc94975a
flask pallets/flask 49943b5a94413a530761350f04e896f76e8d620e
requests psf/requests 3c7baaa05ab4aa49cc819ce3a819d260de19c157
fastapi fastapi/fastapi 45cb2252c737906f37544f5ba6bee0295fb81468
axios axios/axios 9d11464a75ee5c644c0308d742f58755c0482594
gin gin-gonic/gin 0f09c3a9b4626d9fe9979cf4d0521d6ae32ab646
laravel laravel/laravel def7ce14811161f3c689a71ca8abc1369da44bd6
axum tokio-rs/axum 40d061fdacd468217c7a609bede16357276b6c40
django django/django a05e16a7230fe33d3f43f4a3aaed103cebb42efc
spring-petclinic spring-projects/spring-petclinic 500158f732419217507c7656904b8e6aa1bcc0d6
NodeGoat OWASP/NodeGoat c5cb68a7084e4ae7dcc60e6a98768720a81841e8
pygoat adeyosemanputra/pygoat 2aa4cc14f251e4a780e94e200aed6b36a5b15c21
EOF

echo; echo "== 1. Planted secrets (files and git history), seeds 1-10"
for seed in 1 2 3 4 5 6 7 8 9 10; do
  node "$here/planted.mjs" "$work/planted-$seed/repo" "$seed" > /dev/null
  (cd "planted-$seed/repo" && "$JETSCAN" secrets . --json > ../jetscan.json || true
   "$GITLEAKS" git . --no-banner --log-level error --report-format json --report-path ../gitleaks.json || true)
  echo "-- seed $seed"
  node "$here/score-planted.mjs" "planted-$seed/truth.json" "planted-$seed/jetscan.json" "planted-$seed/gitleaks.json" | tail -3
done

echo; echo "== 2. leaky-repo (its own answer key and scoring method; files at HEAD)"
(cd repos/leaky-repo && "$JETSCAN" secrets . --no-history --json > ../../out/leaky.jetscan.json || true
 "$GITLEAKS" dir . --no-banner --log-level error --report-format json --report-path ../../out/leaky.gitleaks.json || true)
node "$here/score-leaky.mjs" repos/leaky-repo/.leaky-meta/secrets.csv out/leaky.jetscan.json out/leaky.gitleaks.json | head -3

echo; echo "== 3. Findings on popular repositories (files at HEAD; triage by hand)"
for n in express flask requests fastapi axios gin laravel axum django spring-petclinic; do
  (cd repos && "$JETSCAN" secrets "$n" --no-history --json > "../out/$n.jetscan.json" || true
   "$GITLEAKS" dir "$n" --no-banner --log-level error --report-format json --report-path "../out/$n.gitleaks.json" || true)
  node -e "const fs=require('fs');console.log('$n', 'jetscan', JSON.parse(fs.readFileSync('out/$n.jetscan.json')).findings.length, 'gitleaks', JSON.parse(fs.readFileSync('out/$n.gitleaks.json')).length)"
done

echo; echo "== 4. Dependencies: jetscan deps vs trivy fs (dev dependencies included on both sides)"
echo "| repo | jetscan | trivy | both | only jetscan | only trivy |"
for n in NodeGoat pygoat axios flask fastapi gin axum; do
  (cd repos && "$JETSCAN" deps "$n" --json > "../out/$n.deps.jetscan.json" 2>/dev/null || true
   "$TRIVY" fs --quiet --scanners vuln --include-dev-deps --format json --output "../out/$n.deps.trivy.json" "$n" || true)
  node "$here/score-deps.mjs" "$n" "out/$n.deps.jetscan.json" "out/$n.deps.trivy.json"
done
