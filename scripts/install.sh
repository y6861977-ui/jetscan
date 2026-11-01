#!/bin/sh
# Установщик jetscan для Linux/macOS: скачивает релиз с GitHub, сверяет SHA-256
# с SHA256SUMS релиза и кладёт бинарник в ~/.local/bin. Без sudo.
#   curl -fsSL https://raw.githubusercontent.com/y6861977-ui/jetscan/main/scripts/install.sh | sh
# Переменные: JETSCAN_REPO (owner/jetscan), JETSCAN_VERSION (v0.1.0, по умолчанию
# последний релиз), JETSCAN_INSTALL_DIR (по умолчанию ~/.local/bin).
set -eu

REPO="${JETSCAN_REPO:-y6861977-ui/jetscan}"
VERSION="${JETSCAN_VERSION:-latest}"
DEST="${JETSCAN_INSTALL_DIR:-$HOME/.local/bin}"

die() {
    echo "jetscan install: $*" >&2
    exit 1
}

case "$REPO" in
    */*) ;;
    *) die "JETSCAN_REPO must look like owner/jetscan" ;;
esac
case "$REPO" in *[!A-Za-z0-9._/-]*) die "bad JETSCAN_REPO" ;; esac

os=$(uname -s)
arch=$(uname -m)
case "$os-$arch" in
    Linux-x86_64 | Linux-amd64) target=x86_64-unknown-linux-musl ;;
    Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-musl ;;
    Darwin-arm64) target=aarch64-apple-darwin ;;
    Darwin-x86_64) target=x86_64-apple-darwin ;;
    *) die "no prebuilt binary for $os $arch — build from source: cargo install --locked --path ." ;;
esac

if [ "$VERSION" = latest ]; then
    VERSION=$(curl -fsSL --proto '=https' --tlsv1.2 "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
    [ -n "$VERSION" ] || die "cannot find the latest release of $REPO"
fi
case "$VERSION" in
    v[0-9]*) ;;
    *) die "bad version '$VERSION'" ;;
esac
case "$VERSION" in *[!A-Za-z0-9._-]*) die "bad version '$VERSION'" ;; esac

name="jetscan-$VERSION-$target"
base="https://github.com/$REPO/releases/download/$VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "jetscan install: downloading $name"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || die "download failed"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "SHA256SUMS download failed"

expected=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$name.tar.gz" | awk '{ print $1 }')
else
    actual=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{ print $1 }')
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || die "checksum mismatch — nothing was installed"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$DEST"
cp "$tmp/$name/jetscan" "$DEST/jetscan.new"
chmod 755 "$DEST/jetscan.new"
mv -f "$DEST/jetscan.new" "$DEST/jetscan"

echo "jetscan install: $("$DEST/jetscan" --version) → $DEST/jetscan"
case ":$PATH:" in
    *":$DEST:"*) ;;
    *) echo "jetscan install: add it to PATH:  export PATH=\"$DEST:\$PATH\"" ;;
esac
