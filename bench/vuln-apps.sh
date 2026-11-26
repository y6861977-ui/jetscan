#!/usr/bin/env bash
# Reproduces bench/VULN-APPS.md: jetscan Pro on deliberately vulnerable training apps.
# Needs git and a Pro build of jetscan with a license key (JETSCAN=path, default `jetscan`).
# Nothing from the cloned apps is built, installed or run. Works in Git Bash on Windows.
# Usage: bench/vuln-apps.sh <work-dir>
set -euo pipefail
work=${1:?usage: bench/vuln-apps.sh <work-dir>}
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
ovaa oversecured/ovaa e5d5a8baef62117d93b1314c1f6b30aefd38bd68
diva-android payatu/diva-android 2bb63b531ba66c22563ac0911973389e2a0cb723
InsecureBankv2 dineshshetty/Android-InsecureBankv2 3c8cc3a3ce45ed56d0f58f236b541b41f992e51f
DVIA-v2 prateek147/DVIA-v2 96466ab85569dbcd37c69b2d15d22ff666f57031
iGoat-Swift OWASP/iGoat-Swift 8c8a8ed6051279f06098f72d6d5aeeb65f8905f2
oopssec-store kOaDT/oss-oopssec-store aa683a74f90184e30e8398a5621f58d6d69bdee8
juice-shop juice-shop/juice-shop c9f99228d9d56afb5f5ca7925376292f7fa44b13
EOF

run() { local out=$1; shift; "$JETSCAN" "$@" > "out/$out.txt" 2>&1 || true; echo "== $out: $(grep -cE '^(CRITICAL|HIGH|MEDIUM|LOW|INFO) ' "out/$out.txt" || true) findings"; }
run ovaa.android           android apps/ovaa
run diva.android           android apps/diva-android
run insecurebank.android   android apps/InsecureBankv2/InsecureBankv2
run insecurebank.apk       apk apps/InsecureBankv2/InsecureBankv2.apk
run dvia.ios               ios apps/DVIA-v2
run igoat.ios              ios apps/iGoat-Swift
run oopssec.web            web source apps/oopssec-store
"$JETSCAN" scan apps/oopssec-store --no-history > out/oopssec.scan.txt 2>&1 || true
"$JETSCAN" secrets apps/juice-shop --no-history > out/juice-shop.secrets.txt 2>&1 || true
echo "Reports are in $work/out; score them against the tables in bench/VULN-APPS.md."
