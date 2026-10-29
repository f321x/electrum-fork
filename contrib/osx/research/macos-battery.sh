#!/usr/bin/env bash
# Research battery for the Electrum macOS arm64 plan (see ../REPORT.md, section 6). Not part of the build.
#
# Host: x86_64 macOS with one candidate toolchain selected:
#   Tahoe >= 26.2 + CLT 26.6, or Sequoia >= 15.3 + CLT 16.4.
#   Works in a builder VM or on GitHub macos-26-intel / macos-15-intel. Needs no Homebrew.
#
# Usage: macos-battery.sh <electrum checkout with submodules> <output dir> [stages]
#   stages: any of "host toolchain build" (default: all). "build" = native libs, C extensions, both apps.
#
# The build runs twice at the same path (builders use a fixed path too), with different TMPDIRs.
# Each run writes <part>.<run>.manifest; summary.txt says SAME/DIFF/MISSING per pair.
# To compare two machines, run on both and diff the *.manifest files.
#
# Side effects: installs the pinned python.org 3.12.10 pkg with sudo (as make_osx.sh does).
# Everything else is written to <output dir>, /tmp/eb, /tmp/eb-tc1, /tmp/electrum-battery-tc2,
# /tmp/eb-t1, /tmp/electrum-battery-tmp-2 and /tmp/eb-tools.
# Bash 3.2 compatible (macOS /bin/bash).
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <electrum checkout> <output dir> [stages]" >&2; exit 1; }
SRC=$(cd "$1" && pwd)
mkdir -p "$2"; OUT=$(cd "$2" && pwd)
STAGES=${3:-host toolchain build}

# Same environment as make_osx.sh: SOURCE_DATE_EPOCH, ZERO_AR_DATE, PYTHONHASHSEED, CPU_COUNT, host_strip.
export GCC_STRIP_BINARIES=1 PYTHONDONTWRITEBYTECODE=1
set +u; . "$SRC/contrib/build_tools_util.sh"; set -u   # it reads unset variables
# Proposed additions.
export LC_ALL=C TZ=UTC
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export MACOSX_DEPLOYMENT_TARGET=12.0

ROOT=/tmp/eb                                       # build root, the same for both runs
TMPDIRS="/tmp/eb-t1 /tmp/electrum-battery-tmp-2"   # different lengths on purpose
TCDIRS="/tmp/eb-tc1 /tmp/electrum-battery-tc2"     # toolchain probes: different paths on purpose
TOOLS=/tmp/eb-tools
PY=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12
PY_PKG_SHA=8373e58da4ea146b3eb1c1f9834f19a319440b6b679b06050b1f9ee3237aa8e4
QT_X86_SHA=183b62be49216da80c7df1931d74885610a88f74812489d29610d13b7c215a1c
QT_ARM_SHA=7897fb74ee21bdc87b5ccf84e94f4a551377e792fd180a9211c17eb41c3338a3
PYINSTALLER_COMMIT=306d4d92580fea7be7ff2c89ba112cdc6f73fac1   # v6.13.0, as make_osx.sh
# GNU autotools (the Debian 13 versions). sha256 checked against two GNU mirrors and Debian's orig
# tarballs (Debian repacks libtool, so for libtool only the mirrors).
GNU_MIRROR=https://mirrors.kernel.org/gnu
AUTOTOOLS="m4/m4-1.4.19.tar.xz:63aede5c6d33b6d9b13511cd0be2cac046f2e70fd0a07aa9573a04a82783af96
autoconf/autoconf-2.72.tar.xz:ba885c1319578d6c94d46e9b0dceb4014caafe2490e437a0dbca3f270a223f5a
automake/automake-1.17.tar.xz:8920c1fc411e13b90bf704ef9db6f29d540e76d232cb3b2c9f4dc4cc599bd990
libtool/libtool-2.5.4.tar.xz:f81f5860666b0bc7d84baddefa60d1cb9fa6fceb2398cc3baca6afaa60266675"
UNIVERSAL="-arch x86_64 -arch arm64"

want() { case " $STAGES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
log() { echo "== $*" >&2; }
note() { echo "$*" | tee -a "$OUT/summary.txt"; }
nth() { local n=$1; shift; set -- $*; eval "echo \${$n}"; }

# Runs "$@" in a subshell with errexit in effect (errexit is ignored in subshells whose status is
# tested), logging to $LOG. Notes a failure and always returns 0.
step() {
    set +e
    ( set -e; "$@" ) > "$LOG" 2>&1
    local rc=$?
    set -e
    if [ $rc != 0 ]; then note "FAIL $STEP (see $LOG)"; fi
    return 0
}

# One line per file: path, sha256 prefix, and per Mach-O slice: minos, LC_UUID, codesign identifier.
manifest() {
    (cd "$1" && find . \( -type f -o -type l \) | LC_ALL=C sort | while IFS= read -r f; do
        if [ -L "$f" ]; then echo "$f -> $(readlink "$f")"; continue; fi
        line="$f $(shasum -a 256 "$f" | cut -c1-16)"
        if archs=$(lipo -archs "$f" 2>/dev/null); then
            for a in $archs; do
                minos=$(vtool -arch "$a" -show-build "$f" 2>/dev/null | awk '$1=="minos"{print $2; exit}') || true
                uuid=$(dwarfdump --arch "$a" --uuid "$f" 2>/dev/null | awk '{print $2; exit}') || true
                id=$(codesign -d --arch "$a" "$f" 2>&1 | awk -F= '/^Identifier=/{print $2}') || true
                line="$line [$a minos=$minos uuid=$uuid id=$id]"
            done
        fi
        echo "$line"
    done)
}

compare() {
    local a="$OUT/$1.1.manifest" b="$OUT/$1.2.manifest"
    if [ ! -s "$a" ] || [ ! -s "$b" ]; then note "MISSING $1"; return 0; fi
    if diff -u "$a" "$b" > "$OUT/$1.diff"; then
        note "SAME $1"; rm -f "$OUT/$1.diff"
    else
        note "DIFF $1: $(grep '^-\./' "$OUT/$1.diff" | awk '{print substr($1, 2)}' | tr '\n' ' ')"
    fi
}

# Copy the checkout including submodules, without .git, to $1/electrum.
copy_tree() {
    if [ ! -d "$SRC/electrum/plugins/keepkey/keepkeylib/keepkeylib" ] || [ ! -d "$SRC/electrum/locale/locale" ]; then
        echo "submodules missing: run 'git submodule update --init' in $SRC" >&2; exit 1
    fi
    mkdir -p "$1/electrum"
    (cd "$SRC" && git ls-files -z --recurse-submodules | cpio -0 -pdm "$1/electrum" 2>/dev/null)
}

install_python() {
    if [ -x "$PY" ] && "$PY" -c 'import sys; sys.exit(sys.version_info[:3] != (3, 12, 10))'; then return; fi
    mkdir -p "$TOOLS"
    curl -fsSL -o "$TOOLS/python.pkg" https://www.python.org/ftp/python/3.12.10/python-3.12.10-macos11.pkg
    echo "$PY_PKG_SHA  $TOOLS/python.pkg" | shasum -a 256 -c
    sudo installer -pkg "$TOOLS/python.pkg" -target /
}

# Brew-free build tools, as proposed for make_osx.sh: cmake (universal2 PyPI wheel), delocate,
# GNU autotools from pinned tarballs (libtool as glibtool*, so Apple's libtool keeps its name),
# msgfmt from python.org's Tools/i18n, and a wget shim for download_if_not_exist.
# The Python packages are version-pinned, not hash-pinned: this is a research script.
install_tools() {
    if [ -f "$TOOLS/done" ]; then return; fi
    rm -rf "$TOOLS/venv" "$TOOLS/bin" "$TOOLS/autotools" "$TOOLS/src"
    mkdir -p "$TOOLS/bin" "$TOOLS/src"
    "$PY" -m venv "$TOOLS/venv"
    "$TOOLS/venv/bin/pip" install -q --no-cache-dir cmake==3.31.6 delocate==0.13.0
    ln -s "$TOOLS/venv/bin/cmake" "$TOOLS/venv/bin/delocate-merge" "$TOOLS/bin/"
    msgfmt_py=/Library/Frameworks/Python.framework/Versions/3.12/share/doc/python3.12/examples/Tools/i18n/msgfmt.py
    printf '#!/bin/sh\nexec %s %s "$@"\n' "$PY" "$msgfmt_py" > "$TOOLS/bin/msgfmt"
    printf '#!/bin/sh\n[ "$1" = -O ] || exit 2\nexec curl -fsSL -o "$2" "$3"\n' > "$TOOLS/bin/wget"
    chmod +x "$TOOLS/bin/msgfmt" "$TOOLS/bin/wget"
    echo "$AUTOTOOLS" | while IFS=: read -r path sha; do
        f="$TOOLS/src/$(basename "$path")"
        curl -fsSL -o "$f" "$GNU_MIRROR/$path"
        echo "$sha  $f" | shasum -a 256 -c
        tar -xJf "$f" -C "$TOOLS/src"
        d="${f%.tar.xz}"; extra=""
        case "$path" in libtool/*) extra="--program-prefix=g" ;; esac
        (cd "$d" && PATH="$TOOLS/autotools/bin:$PATH" ./configure -q --prefix="$TOOLS/autotools" $extra \
            && make -s -j"$CPU_COUNT" && make -s install) > "$d.log" 2>&1
    done
    touch "$TOOLS/done"
}

# Prints one problem per line for an app that should contain only $2 slices.
audit_app() {
    find "$1" -type f | while IFS= read -r f; do
        archs=$(lipo -archs "$f" 2>/dev/null) || continue
        [ "$archs" = "$2" ] || echo "ARCH '$archs' ${f#$1/}"
        otool -L "$f" 2>/dev/null | tail -n +2 | awk -v f="${f#$1/}" \
            '$1 ~ /^(\/usr\/local\/|\/opt\/|\/Users\/|\/tmp\/|\/private\/)/{print "LOADPATH " f ": " $1}' || true
        m=$(vtool -show-build "$f" 2>/dev/null | awk '$1=="minos"{print $2; exit}') || true
        if [ -n "$m" ] && [ "$(printf '%s\n12.0\n' "$m" | sort -t. -k1,1n -k2,2n | tail -1)" != "12.0" ]; then
            echo "MINOS $m ${f#$1/}"
        fi
    done
}

# Python extension modules must have both slices and export PyInit_* in each.
audit_ext() {
    find "$1" -name '*.so' | while IFS= read -r f; do
        for a in x86_64 arm64; do
            n=$(nm -arch "$a" -gU "$f" 2>/dev/null | awk '/ _PyInit_/{c++} END{print c+0}') || true
            [ "${n:-0}" -gt 0 ] || echo "NO-PYINIT [$a] ${f#$1/}"
        done
    done
}

pipi() { python3 -m pip install -q --no-cache-dir --no-build-isolation --no-dependencies --no-warn-script-location "$@"; }
strip_ext() { find "$ROOT/venv/lib/python3.12/site-packages" -type f -name '*.so' -print0 | xargs -0 strip -x; }

rm -f "$OUT"/*.manifest "$OUT"/*.audit "$OUT"/*.diff "$OUT"/*.zip
: > "$OUT/summary.txt"

if want host; then
    log host
    {
        sw_vers; uname -m; echo "DEVELOPER_DIR=$DEVELOPER_DIR"
        for p in $(pkgutil --pkgs | grep -i CLTools); do pkgutil --pkg-info "$p" | grep -E '^(package-id|version)'; done
        clang --version | head -1; ld -v 2>&1 | head -1; echo "SDK $(xcrun --show-sdk-version)"
        echo "codesign $(shasum -a 256 /usr/bin/codesign | cut -c1-16)"
        for t in lipo install_name_tool codesign_allocate pagestuff otool vtool strip cmake brew port; do
            echo "$t: $(command -v $t || echo -)"
        done
        if [ -e "$DEVELOPER_DIR/usr/include/c++" ]; then echo "WARNING: stale $DEVELOPER_DIR/usr/include/c++"; fi
        clang -x c -v -E /dev/null -o /dev/null 2>&1 | sed -n '/search starts here/,/End of search/p'
        echo 'int main(void){return 0;}' > /tmp/eb-ld.c
        clang -Wl,-v /tmp/eb-ld.c -o /tmp/eb-ld 2>&1 | sed -n '/Library search paths/,$p'
        rm -f /tmp/eb-ld.c /tmp/eb-ld
    } > "$OUT/host.txt" 2>&1 || true
    note "host: $(sw_vers -productVersion) $(sw_vers -buildVersion), $(clang --version | head -1)"
fi

# --- toolchain: universal C links in two different directories, default and classic linker ---
tc_build() {
    cd "$W"; export TMPDIR="$W/tmp"
    clang -O2 -g0 $UNIVERSAL -dynamiclib -install_name @rpath/libfoo.dylib lib.c -o "$d/libfoo.dylib" $f
    clang -O2 -g0 $UNIVERSAL -bundle -undefined dynamic_lookup lib.c -o "$d/mod.so" $f
    clang -O2 -g0 $UNIVERSAL main.c -L"$d" -lfoo -o "$d/prog" $f
    # with debug info: expected to differ (N_OSO stabs name random temp objects); own manifest
    clang -O2 -g $UNIVERSAL -dynamiclib -install_name @rpath/libdbg.dylib lib.c -o "$d.dbg/libdbg.dylib" $f
}

if want toolchain; then
    for RUN in 1 2; do
        log "toolchain run $RUN"
        W=$(nth $RUN $TCDIRS); rm -rf "$W" "$W.log"; mkdir -p "$W/tmp" "$W.log"
        printf 'int foo(int x){return x*3;}\n' > "$W/lib.c"
        printf '#include <stdio.h>\nint foo(int);\nint main(void){printf("%%d\\n",foo(2));return 0;}\n' > "$W/main.c"
        for ld in default classic; do
            d="$W/out-$ld"; mkdir -p "$d" "$d.dbg"; f=""
            if [ $ld = classic ]; then f="-Wl,-ld_classic"; fi
            STEP="toolchain run $RUN ($ld linker)" LOG="$W.log/$ld.log" step tc_build
        done
        manifest "$W/out-default" > "$OUT/link-default.$RUN.manifest"
        manifest "$W/out-classic" > "$OUT/link-classic.$RUN.manifest"
        { manifest "$W/out-default.dbg"; manifest "$W/out-classic.dbg"; } > "$OUT/link-debug.$RUN.manifest"
    done
    compare link-default; compare link-classic; compare link-debug

    # Ad-hoc codesign as PyInstaller does it. Compare codesign.txt between hosts (Intel vs Apple
    # silicon, macOS majors): identifiers of fat files with dot-less canonical names carry the
    # host slice's UUID, and macOS 26 hashes arm64 slices with 16 KiB pages.
    W=$(nth 1 $TCDIRS); P="$W/probe"; rm -rf "$P"; mkdir -p "$P"
    fat="$W/out-default/libfoo.dylib"
    if [ -f "$fat" ]; then
        lipo "$fat" -thin arm64 -output "$P/libthin-arm64.dylib"
        lipo "$fat" -thin x86_64 -output "$P/libthin-x86_64.dylib"
        for n in libfat.dylib libfat.1.dylib libfat-1.0.dylib libfat.so; do cp "$fat" "$P/$n"; done
        for x in "$P"/*; do /usr/bin/codesign -s - --force --all-architectures --timestamp "$x" 2>/dev/null || true; done
        {
            manifest "$P"
            for x in "$P"/*; do for a in $(lipo -archs "$x"); do
                echo "$(basename "$x") [$a] $(codesign -dvvvv --arch "$a" "$x" 2>&1 \
                    | grep -E '^(Identifier=|CodeDirectory |Page size=|CDHash=)' | tr '\n' ' ')"
            done; done
            echo "fat layout:"
            for x in "$P"/libfat*; do
                echo "$(basename "$x"): $(lipo -detailed_info "$x" | awk '/offset|align/{printf "%s ", $0}')"
            done
        } > "$OUT/codesign.txt" 2>&1 || true
    fi
fi

# --- build: native libs, C extensions from sdist, two thin apps ---
native_build() {
    cd "$ROOT/electrum"
    export PATH="$TOOLS/bin:$TOOLS/autotools/bin:$PATH" LIBTOOLIZE=glibtoolize
    export DLL_TARGET_DIR="$ROOT/dlls" CC=clang CXX=clang++
    # zxing with Apple clang (instead of gcc@14), both archs in one pass
    CMAKE_OSX_ARCHITECTURES="x86_64;arm64" CFLAGS="-O2 -g0" CXXFLAGS="-O2 -g0" \
        ./contrib/make_zxing.sh
    CFLAGS="-O2 -g0 $UNIVERSAL" LDFLAGS="$UNIVERSAL" \
    AUTOCONF_FLAGS="--with-asm=no --disable-dependency-tracking" \
        ./contrib/make_libsecp256k1.sh
    # make_libusb.sh overwrites LDFLAGS on Darwin; the -arch flags reach the link via CFLAGS.
    CFLAGS="-O2 -g0 $UNIVERSAL" AUTOCONF_FLAGS="--disable-dependency-tracking --prefix=$ROOT/usr" \
        ./contrib/make_libusb.sh
}

pyext_build() {
    . "$ROOT/venv/bin/activate"; cd "$ROOT/electrum"
    export ARCHFLAGS="$UNIVERSAL" CFLAGS="$CF" CXXFLAGS="$CF"
    export YARL_NO_EXTENSIONS=1 PROPCACHE_NO_EXTENSIONS=1 ELECTRUM_ECC_DONT_COMPILE=1
    R=contrib/deterministic-build
    pipi -Ir $R/requirements-build-base.txt
    pipi --no-binary :all: -Ir $R/requirements-build-mac.txt
    pipi --no-binary :all: -Ir $R/requirements.txt
    pipi --no-binary :all: --only-binary cryptography -Ir $R/requirements-hw.txt
    strip_ext
}

app_build() {
    . "$ROOT/venv/bin/activate"; cd "$ROOT/electrum"
    export PATH="$TOOLS/bin:$PATH" ARCHFLAGS="$UNIVERSAL" CFLAGS="$CF" CXXFLAGS="$CF"
    N="$ROOT/dlls"
    # Qt 6.9 pins as on Windows/Linux, with PyQt6-Qt6 replaced by the fused wheel.
    awk '/^PyQt6-Qt6==/{s=1} !s{print} s && !/\\$/{s=0}' contrib/deterministic-build/requirements-binaries.txt > "$ROOT/req-bin.txt"
    pipi --no-binary :all: --only-binary PyQt6,cryptography -Ir "$ROOT/req-bin.txt"
    pipi "$QTW"/fused/*.whl
    # bootloader as in make_osx.sh
    rm -rf "$ROOT/pyinstaller"; mkdir "$ROOT/pyinstaller"; cd "$ROOT/pyinstaller"
    git init -q; git remote add origin https://github.com/pyinstaller/pyinstaller.git
    git fetch -q --depth 1 origin $PYINSTALLER_COMMIT; git checkout -q -b pinned "$PYINSTALLER_COMMIT^{commit}"
    rm -f PyInstaller/bootloader/Darwin-*/run*
    echo "const char *electrum_tag = \"tagged by Electrum@$COMMIT\";" >> ./bootloader/src/pyi_main.c
    (cd bootloader && python3 ./waf all CFLAGS="-static")
    echo "bootloader archs: $(lipo -archs PyInstaller/bootloader/Darwin-64bit/runw)"
    pipi "$ROOT/pyinstaller"
    cd "$ROOT/electrum"
    contrib/locale/build_locale.sh electrum/locale/locale electrum/locale/locale > /dev/null
    rm -f electrum/locale/locale/*/electrum.po
    cp "$N"/libsecp256k1.*.dylib "$N"/libZXing.dylib "$N"/libusb-1.0.dylib electrum/
    pipi .
    cp "$N"/libsecp256k1.*.dylib "$ROOT/venv/lib/python3.12/site-packages/electrum_ecc/"
    strip_ext   # cffi and PyQt6-sip were rebuilt above
    find . -exec touch -t 200101220000 {} + || true
    for arch in arm64 x86_64; do
        sed -e "s/target_arch='x86_64',.*/target_arch='$arch',/" \
            -e "s/'LSMinimumSystemVersion': '11'/'LSMinimumSystemVersion': '12'/" \
            contrib/osx/pyinstaller.spec > contrib/osx/pyinstaller-$arch.spec
        ELECTRUM_VERSION=$VERSION pyinstaller --noconfirm --clean --distpath "dist-$arch" --workpath "build-$arch" \
            contrib/osx/pyinstaller-$arch.spec > "$ROOT/pyinstaller-$arch.log" 2>&1 || echo "FAIL pyinstaller $arch"
    done
}

# Does Apple codesign on this macOS lay out thin binaries the way codesign_allocate does?
# Mirrors the current flow with an ad-hoc signature: sign a copy like sign_osx.sh, take the Mach-O
# signature blobs plus the two top-level files extract_sigs.sh takes, replay them onto a fresh copy of
# the unsigned app like apply_sigs.sh (codesign_allocate, then dd without notrunc), and compare.
# Narrower than the release flow: no Developer ID/timestamp, same host and CLT for both sides.
sig_range() {
    otool -l "$1" 2>/dev/null \
        | awk '/cmd LC_CODE_SIGNATURE/{c=1} c && $1=="dataoff"{o=$2} c && $1=="datasize"{print o, $2; exit}'
}
replay_test() { # app arch
    T="$ROOT/replay-$2"; rm -rf "$T"; mkdir -p "$T"
    ditto "$1" "$T/signed.app"; ditto "$1" "$T/replayed.app"
    codesign --force --deep -s - --options runtime \
        --entitlements "$SRC/contrib/osx/entitlements.plist" "$T/signed.app"
    (cd "$T/signed.app" && find . -type f) | while IFS= read -r f; do
        s="$T/signed.app/$f"; u="$T/replayed.app/$f"
        r=$(sig_range "$s")
        if [ -z "$r" ]; then continue; fi
        off=${r% *}; size=${r#* }
        codesign_allocate -i "$u" -a "$2" "$size" -o "$u.tmp"
        newoff=$(sig_range "$u.tmp"); newoff=${newoff% *}
        dd if="$s" of="$u.tmp" bs=1 skip="$off" seek="$newoff" count="$size" 2>/dev/null
        mv "$u.tmp" "$u"
    done
    for f in Contents/_CodeSignature/CodeResources Contents/CodeResources; do
        if [ -f "$T/signed.app/$f" ]; then cp -p "$T/signed.app/$f" "$T/replayed.app/$f"; fi
    done
    if diff -rq "$T/signed.app" "$T/replayed.app" > "$OUT/replay-$2.diff"; then
        note "SAME replay $2"; rm -f "$OUT/replay-$2.diff"
    else
        note "DIFF replay $2: $(wc -l < "$OUT/replay-$2.diff") files (see replay-$2.diff)"
    fi
}

if want build; then
    install_python; install_tools
    VERSION=$(git -C "$SRC" describe --tags --always)
    COMMIT=$(git -C "$SRC" rev-parse HEAD)
    # Proposed flags: python.org's sysconfig CFLAGS with -g -> -g0 and the -arch flags removed
    # (setuptools >= 75.7 replaces sysconfig CFLAGS with an exported CFLAGS), archs via ARCHFLAGS.
    SYSCF=$("$PY" -c 'import sysconfig; print(sysconfig.get_config_var("CFLAGS"))')
    CF=$(echo " $SYSCF " | sed -E 's/ -arch [a-z0-9_]+//g; s/ -g / -g0 /g; s/ -g / -g0 /g; s/^ +//; s/ +$//')
    note "C extension CFLAGS=$CF"
    QTW="$TOOLS/qt"
    if [ ! -d "$QTW/fused" ]; then
        rm -rf "$QTW"; mkdir -p "$QTW"
        for p in macosx_10_14_x86_64 macosx_11_0_arm64; do
            "$TOOLS/venv/bin/pip" download -q --no-cache-dir --no-deps --only-binary :all: --platform $p \
                -d "$QTW/$p" PyQt6-Qt6==6.9.2
        done
        printf '%s  %s\n' "$QT_X86_SHA" "$QTW"/macosx_10_14_x86_64/*.whl "$QT_ARM_SHA" "$QTW"/macosx_11_0_arm64/*.whl \
            | shasum -a 256 -c
        "$TOOLS/bin/delocate-merge" "$QTW"/macosx_10_14_x86_64/*.whl "$QTW"/macosx_11_0_arm64/*.whl -w "$QTW/fused"
    fi
    LOGS="$OUT/logs"; mkdir -p "$LOGS"
    for RUN in 1 2; do
        log "build run $RUN"
        export TMPDIR; TMPDIR=$(nth $RUN $TMPDIRS)
        rm -rf "$ROOT" "$TMPDIR"; mkdir -p "$ROOT/dlls" "$TMPDIR"
        copy_tree "$ROOT"
        STEP="native run $RUN" LOG="$LOGS/native.$RUN.log" step native_build
        manifest "$ROOT/dlls" > "$OUT/native.$RUN.manifest"

        "$PY" -m venv "$ROOT/venv"
        STEP="pyext run $RUN" LOG="$LOGS/pyext.$RUN.log" step pyext_build
        mkdir -p "$ROOT/so"
        (cd "$ROOT/venv/lib/python3.12/site-packages" && find . -name '*.so' -print0 | cpio -0 -pdm "$ROOT/so" 2>/dev/null) || true
        manifest "$ROOT/so" > "$OUT/pyext.$RUN.manifest"
        audit_ext "$ROOT/so" > "$OUT/pyext.$RUN.audit"
        if [ -s "$OUT/pyext.$RUN.audit" ]; then note "AUDIT pyext run $RUN: $(wc -l < "$OUT/pyext.$RUN.audit") problems"; fi

        if [ -f "$(echo "$ROOT"/dlls/libsecp256k1.*.dylib)" ] && [ -f "$ROOT/dlls/libZXing.dylib" ]; then
            STEP="app run $RUN" LOG="$LOGS/app.$RUN.log" step app_build
            grep -E '^(bootloader archs|FAIL)' "$LOGS/app.$RUN.log" | sed "s/^/run $RUN: /" | tee -a "$OUT/summary.txt" || true
        else
            note "SKIP app run $RUN: native libs missing"
        fi
        for arch in x86_64 arm64; do
            app="$ROOT/electrum/dist-$arch/Electrum.app"
            if [ ! -d "$app" ]; then note "MISSING $arch app run $RUN"; continue; fi
            cp "$ROOT/pyinstaller-$arch.log" "$LOGS/pyinstaller-$arch.$RUN.log" || true
            manifest "$app" > "$OUT/app-$arch.$RUN.manifest"
            audit_app "$app" "$arch" > "$OUT/app-$arch.$RUN.audit"
            if [ -s "$OUT/app-$arch.$RUN.audit" ]; then note "AUDIT app-$arch run $RUN: $(wc -l < "$OUT/app-$arch.$RUN.audit") problems"; fi
            if [ "$RUN" = 1 ]; then
                (cd "$(dirname "$app")" && ditto -c -k --keepParent Electrum.app "$OUT/Electrum-$VERSION-$arch-unsigned.zip")
                STEP="replay test $arch" LOG="$LOGS/replay-$arch.log" step replay_test "$app" "$arch"
            fi
        done
    done
    compare native; compare pyext; compare app-x86_64; compare app-arm64
fi

log done; cat "$OUT/summary.txt"
