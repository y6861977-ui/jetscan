#!/usr/bin/env bash
# Reproduces bench/BLIND-APPS.md: jetscan Pro on four training apps it was not tuned on.
# Needs git and a Pro build of jetscan with a license key (JETSCAN=path, default `jetscan`).
# Nothing from the cloned apps is built, installed or run. Works in Git Bash on Windows.
# Usage: bench/blind-apps.sh <work-dir>
set -euo pipefail
work=${1:?usage: bench/blind-apps.sh <work-dir>}
JETSCAN=${JETSCAN:-jetscan}
mkdir -p "$work/apps" "$work/out"
cd "$work"
"$JETSCAN" --version

while read -r name repo commit; do
  [ -d "apps/$name" ] && continue
  git init -q "apps/$name"
  git -C "apps/$name" fetch -q --depth 1 "https://github.com/$repo.git" "$commit"
  git -C "apps/$name" checkout -q FETCH_HEAD
done <<'EOF'
androgoat satishpatnayak/AndroGoat 77996f239587a8ed2691629777374b5f4a364589
injuredandroid B3nac/InjuredAndroid 2cc669a1829427f1183b47b80af846cc919bd6f6
dvbank rewanthtammana/Damn-vulnerable-Bank 5136c3484c704dc74e8837e324ac24b1452a1e31
dvna appsecco/dvna 9ba473add536f66ac9007966acb2a775dd31277a
EOF

run() { local out=$1; shift; "$JETSCAN" "$@" > "out/$out.txt" 2>&1 || true; echo "== $out: $(grep -cE '^(CRITICAL|HIGH|MEDIUM|LOW|INFO) ' "out/$out.txt" || true) findings"; }
run androgoat.android      android apps/androgoat
run injured.android        android apps/injuredandroid/InjuredAndroid
run dvbank.android         android apps/dvbank/DamnVulnerableBank
run dvbank.apk             apk apps/dvbank/dvba.apk
run dvbank.backend.web     web source apps/dvbank/BackendServer
run dvna.web               web source apps/dvna
"$JETSCAN" scan apps/dvna --no-history > out/dvna.scan.txt 2>&1 || true
"$JETSCAN" scan apps/dvbank/BackendServer --no-history > out/dvbank.backend.scan.txt 2>&1 || true
echo "Reports are in $work/out; score them against the tables in bench/BLIND-APPS.md."
