#!/usr/bin/env bash
# DRAFT (research artifact, not part of the Electrum tree). Smoke test for an
# Electrum.app produced by contrib/osx/make_osx.sh. Bash 3.2 compatible (macOS /bin/bash).
#
# usage: macos_smoke_test.sh <path/to/Electrum.app> <expected archs> <exec arch> [max minos]
#   expected archs: "arm64", "x86_64" or "arm64 x86_64" (universal2)
#   exec arch:      slice to execute: "arm64" (native on Apple Silicon) or "x86_64"
#                   (native on Intel runners; Rosetta 2 on Apple Silicon runners)
#   max minos:      highest allowed LC_BUILD_VERSION minos / LC_VERSION_MIN_MACOSX (default 12.0)
#
# Sources for the non-obvious checks (see notes/ci.md):
#  - `arch -<a> <exe>` never falls back to another slice; it fails if the slice is missing.
#  - P_TRANSLATED = 0x00020000 in p_flag (xnu bsd/sys/proc.h), set at exec for Rosetta processes
#    (xnu bsd/kern/kern_exec.c), exported unmasked via kinfo_proc (kern_sysctl.c
#    fill_user64_externproc) and printed by `ps -o flags=` (adv_cmds ps/keyword.c "f"/"flags").
#  - `version_info` is an offline command that imports Qt, electrum_ecc (libsecp256k1),
#    qrreader (libZXing), usb1 (libusb), hid (hidapi) and cryptography (electrum/commands.py).
set -eu

APP=${1:?app path}
WANT_ARCHS=${2:?expected archs}
EXEC_ARCH=${3:?exec arch}
MAX_MINOS=${4:-12.0}

EXE="$APP/Contents/MacOS/run_electrum"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
errors=0
err() { echo "::error::$*"; errors=$((errors + 1)); }

echo "== host: $(uname -m) $(sw_vers -productVersion) ($(sw_vers -buildVersion))"

# ---------------------------------------------------------------- 1. static checks
want=$(printf '%s\n' $WANT_ARCHS | LC_ALL=C sort | xargs)
n=0
while IFS= read -r -d '' f; do
    case "$(file -b "$f")" in *Mach-O*) ;; *) continue ;; esac
    n=$((n + 1))
    archs=$(lipo -archs "$f" | tr ' ' '\n' | LC_ALL=C sort | xargs)
    [ "$archs" = "$want" ] || err "arch: ${f#$APP/}: '$archs' (want '$want')"
    for a in $archs; do
        minos=$(otool -arch "$a" -l "$f" | awk '
            /cmd LC_BUILD_VERSION/ {b=1} b && $1=="minos"   {print $2; exit}
            /cmd LC_VERSION_MIN_MACOSX/ {v=1} v && $1=="version" {print $2; exit}')
        awk -v m="${minos:-99}" -v x="$MAX_MINOS" 'BEGIN {
                split(m, a, "."); split(x, b, ".");
                exit !((a[1]+0) < (b[1]+0) || ((a[1]+0) == (b[1]+0) && (a[2]+0) <= (b[2]+0))) }' \
            || err "minos: ${f#$APP/} [$a]: ${minos:-missing} > $MAX_MINOS"
    done
    # dependencies must be @rpath/@loader_path/@executable_path or system paths
    if otool -L "$f" | grep -E '^[[:space:]]+(/usr/local/|/opt/homebrew/|/opt/local/|/Users/|/private/|/tmp/)'; then
        err "non-system absolute load path in ${f#$APP/}"
    fi
done < <(find "$APP" -type f -print0)
echo "== checked $n Mach-O files"
[ "$n" -gt 0 ] || err "no Mach-O files found"

# PyInstaller ad-hoc signs every binary and the bundle; this must verify.
codesign --verify --deep --strict --verbose=2 "$APP" || err "codesign --verify failed"
for a in $want; do
    codesign -d --arch "$a" -vvv "$EXE" 2>&1 | grep -E '^(Identifier|Format|CodeDirectory|Hash choices|CDHash|Signature)' || true
done

# ---------------------------------------------------------------- 2. CLI, in the requested slice
run() { arch -"$EXEC_ARCH" "$EXE" --offline -D "$TMP/data" "$@"; }

ver=$(run version) || err "'version' failed"
echo "== version: $ver"

run version_info > "$TMP/version_info.json" || err "'version_info' failed"
cat "$TMP/version_info.json"
/usr/bin/python3 - "$TMP/version_info.json" "$APP" <<'EOF' || err "version_info checks failed"
import json, os, sys
info = json.load(open(sys.argv[1]))
app = os.path.realpath(sys.argv[2])
required = ["qt.version", "pyqt.version", "libsecp256k1.path", "libZXing.path", "libZXing.version",
            "libusb.version", "hidapi.version", "cryptography.version", "openssl.version"]
bad = [k for k in required if not info.get(k)]
# the loaders fall back to system-wide names, so make sure the bundled copies were used
for k in ("libsecp256k1.path", "libZXing.path"):
    p = info.get(k)
    if p and not os.path.realpath(p).startswith(app):
        bad.append(f"{k} not inside the bundle: {p}")
if info.get("libusb.path") and not os.path.realpath(info["libusb.path"]).startswith(app):
    print(f"warning: libusb.path not inside the bundle: {info['libusb.path']}")
if bad:
    sys.exit(f"version_info: {bad}")
EOF

# Offline wallet: BIP32 derivation + libsecp256k1 signing/recovery. Test vector from
# tests/test_wallet_vertical.py::test_electrum_seed_segwit; the signature is RFC6979-deterministic
# (value computed with Electrum 4.8.3 from source on Linux, see evidence/ci/cli-smoke-prototype.log).
SEED='bitter grass shiver impose acquire brush forget axis eager alone wine silver'
ADDR=bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af
SIG_EXPECTED='IC3DsAKQhCWiihkOEGrLHwJPvKGvVRWp6C5pRZCtCxKlZz9/GnGqeXApodxjZqcwA+eSNNYPlCMaNfQgvEBzkp0='
run restore --password pw "$SEED" > /dev/null || err "restore failed"
W="$TMP/data/wallets/default_wallet"
sig=$(run -w "$W" signmessage --password pw "$ADDR" hello < /dev/null) || err "signmessage failed"
[ "$sig" = "$SIG_EXPECTED" ] || err "signmessage: got '$sig'"
[ "$(run verifymessage "$ADDR" "$sig" hello)" = "true" ] || err "verifymessage did not return true"

# ---------------------------------------------------------------- 3. GUI start (headless)
# libqoffscreen.dylib is bundled (PyInstaller collects every plugin in plugins/platforms;
# present in the electrum-4.8.3 release). The first-run wizard just waits for input.
QT_QPA_PLATFORM=offscreen arch -"$EXEC_ARCH" "$EXE" --offline -D "$TMP/gui" > "$TMP/gui.log" 2>&1 &
pid=$!
sleep 25
if kill -0 "$pid" 2>/dev/null; then
    flags=$(ps -o flags= -p "$pid" | tr -d ' ')
    translated=$(( 0x$flags & 0x20000 ))
    echo "== GUI pid $pid alive, p_flag=0x$flags translated=$([ $translated -ne 0 ] && echo yes || echo no)"
    if [ "$EXEC_ARCH" = "$(uname -m)" ] && [ $translated -ne 0 ]; then
        err "process runs under Rosetta although the native slice was requested"
    fi
    kill "$pid"; wait "$pid" 2>/dev/null || true
else
    wait "$pid" 2>/dev/null || true
    cat "$TMP/gui.log"
    err "GUI exited within 25 s"
fi

if [ "$errors" -ne 0 ]; then
    echo "$errors check(s) failed"
    exit 1
fi
echo "== all smoke tests passed"
