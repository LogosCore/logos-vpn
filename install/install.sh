#!/bin/sh
# logos-vpn's installer for Linux and macOS, as core serves it
# (GET /api/v1/vpn/install.sh; docs: contracts/vpn-front, "Installing").
# Core's Connect a machine gives the line that runs it:
#
#   curl -fsSL https://core/api/v1/vpn/install.sh | sudo sh -s -- https://core lgv_…
#
# It fetches this core's logos-vpn for the machine's system with the key,
# checks it against the release's SHA256SUMS, puts it on the PATH
# (/usr/local/bin, or LOGOS_VPN_DIR) and connects with the key. Run again,
# it replaces the one there: core's release, whatever it is.
#
# Options, before the address:
#   --pin sha256//…     core's public key, for curl (--pinnedpubkey): a
#                       self-signed core, its certificate otherwise refused
#   --cert-sha256 FP    core's certificate's fingerprint, for logos-vpn
#   --no-connect        install, and stop there
set -eu

pin=""
cert=""
connect=1
while [ $# -gt 0 ]; do
  case $1 in
    --pin) pin=${2:?--pin sha256//…}; shift 2 ;;
    --cert-sha256) cert=${2:?--cert-sha256 FP}; shift 2 ;;
    --no-connect) connect=0; shift ;;
    --) shift; break ;;
    -*) echo "logos-vpn install: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
if [ $# -ne 2 ]; then
  echo "usage: install.sh [--pin sha256//…] [--cert-sha256 FP] [--no-connect] <core address> <key>" >&2
  exit 2
fi
core=${1%/}
key=$2
case $key in lgv_*) ;; *) echo "logos-vpn install: $key is no VPN key (lgv_…, from the tunnel's VPN tab)" >&2; exit 2 ;; esac

case $(uname -s) in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "logos-vpn install: $(uname -s): logos-vpn is built for Linux, macOS and Windows" >&2; exit 1 ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "logos-vpn install: $(uname -m): logos-vpn is built for x86-64 and ARM64" >&2; exit 1 ;;
esac

dir=${LOGOS_VPN_DIR:-/usr/local/bin}
mkdir -p "$dir" 2>/dev/null || true
if [ ! -w "$dir" ]; then
  echo "logos-vpn install: $dir is not writable: run it as root (sudo sh -s -- …)" >&2
  exit 1
fi
command -v curl >/dev/null 2>&1 || { echo "logos-vpn install: it needs curl" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# fetch <path> <file>: from core, with the key, pinned when asked; a
# refusal says core's why (curl's -f would say its status alone).
fetch() {
  if [ -n "$pin" ]; then
    code=$(curl -sSL --proto '=https' -k --pinnedpubkey "$pin" -H "Authorization: Bearer $key" -o "$2" -w '%{http_code}' "$core$1") || return 1
  else
    code=$(curl -sSL -H "Authorization: Bearer $key" -o "$2" -w '%{http_code}' "$core$1") || return 1
  fi
  [ "$code" = 200 ] && return 0
  echo "logos-vpn install: $core$1: $code $(head -c 400 "$2" 2>/dev/null)" >&2
  return 1
}

name=logos-vpn-$os-$arch
echo "logos-vpn install: $name from $core"
fetch /api/v1/vpn/client/SHA256SUMS "$tmp/SHA256SUMS" || exit 1
fetch "/api/v1/vpn/client/$os-$arch" "$tmp/logos-vpn" || exit 1
want=$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/logos-vpn" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/logos-vpn" | awk '{ print $1 }')
fi
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "logos-vpn install: $name does not match its SHA256SUMS (${want:-not listed}): not installed" >&2
  exit 1
fi
chmod 0755 "$tmp/logos-vpn"
mv -f "$tmp/logos-vpn" "$dir/logos-vpn"
echo "logos-vpn install: $dir/logos-vpn, $("$dir/logos-vpn" -version)"

[ "$connect" = 1 ] || exit 0
rm -rf "$tmp"
trap - EXIT INT TERM
if [ -n "$cert" ]; then
  exec "$dir/logos-vpn" -cert-sha256 "$cert" "$core" "$key"
fi
exec "$dir/logos-vpn" "$core" "$key"
