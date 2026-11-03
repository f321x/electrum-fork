#!/usr/bin/env bash
#
# Builds the unsigned macOS apps and DMGs, one per architecture:
#   dist/x86_64/Electrum.app  and  dist/electrum-$VERSION-x86_64-unsigned.dmg
#   dist/arm64/Electrum.app   and  dist/electrum-$VERSION-arm64-unsigned.dmg
# Both apps come from one build environment with universal2 (x86_64 + arm64) binaries;
# PyInstaller thins each app to its architecture.
#
# It only runs in the builder VM described in contrib/osx/README.md, and checks this.

set -e

# Run in a clean environment. Otherwise compiler, Python and pip settings from the caller's shell,
# or locale variables forwarded by ssh, would reach the build.
if [ -z "$ELECTRUM_MAKE_OSX_CLEAN_ENV" ]; then
    exec /usr/bin/env -i ELECTRUM_MAKE_OSX_CLEAN_ENV=1 \
        HOME="$HOME" USER="$USER" LOGNAME="$LOGNAME" TERM="${TERM:-dumb}" \
        /bin/bash "$(realpath "$0")" "$@"
fi
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C TZ=UTC
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export MACOSX_DEPLOYMENT_TARGET=12.0
export PIP_CONFIG_FILE=/dev/null  # no pip.conf
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null  # no gitconfig
export PYTHONDONTWRITEBYTECODE=1  # don't create __pycache__/ folders with .pyc files
export CONFIG_SITE=/dev/null  # autoconf: no config.site from /usr/local
export GCC_STRIP_BINARIES=1

# Parameterize
PYTHON_VERSION=3.12.10
PY_VER_MAJOR="3.12"  # as it appears in fs paths
PACKAGE=Electrum
ARCHS="x86_64 arm64"
# The builder setup, see contrib/osx/README.md
BUILDER_MACOS_MAJOR=15
BUILDER_CLT_VERSION=16.4.0.0.1.1747106510
BUILDER_PATH=/Users/vagrant/electrum

. "$(dirname "$0")/../build_tools_util.sh"

CONTRIB_OSX="$(dirname "$(realpath "$0")")"
CONTRIB="$CONTRIB_OSX/.."
PROJECT_ROOT="$(cd "$CONTRIB/.." && pwd -P)"
CACHEDIR="$CONTRIB_OSX/.cache"
DOWNLOADS="$CACHEDIR/downloads"  # hash-checked downloads, kept between builds
TOOLS="$CACHEDIR/tools"          # build tools, rebuilt when their pins change
BUILDDIR="$CACHEDIR/build"       # everything else, recreated by every build
export DLL_TARGET_DIR="$BUILDDIR/dlls"
VENV_DIR="$CONTRIB_OSX/build-venv"
PYTHON="/Library/Frameworks/Python.framework/Versions/$PY_VER_MAJOR/bin/python$PY_VER_MAJOR"

cd "$PROJECT_ROOT"

git -C "$PROJECT_ROOT" rev-parse || fail "Building outside a git clone is not supported."


info "Checking the build environment"
PROBLEMS=""
problem() { PROBLEMS="$PROBLEMS"$'\n'"  - $1"; }
[ "$(uname -m)" = x86_64 ] || problem "not an x86_64 Mac (or VM)"
macos_version="$(sw_vers -productVersion)"
[ "${macos_version%%.*}" = "$BUILDER_MACOS_MAJOR" ] \
    || problem "macOS is $macos_version, not $BUILDER_MACOS_MAJOR"
clt_version="$(pkgutil --pkg-info=com.apple.pkg.CLTools_Executables 2>/dev/null | awk '/^version:/ { print $2 }')"
[ "$clt_version" = "$BUILDER_CLT_VERSION" ] \
    || problem "the Command Line Tools are '${clt_version:-not installed}', not $BUILDER_CLT_VERSION"
# left over by old CLT installs, and found by clang before the SDK's headers
[ ! -e "$DEVELOPER_DIR/usr/include/c++" ] || problem "$DEVELOPER_DIR/usr/include/c++ exists (stale C++ headers)"
# clang searches these by default; Homebrew puts its headers and libraries there
for d in /usr/local/include /usr/local/lib; do
    [ -z "$(ls -A "$d" 2>/dev/null)" ] || problem "$d is not empty (Homebrew?)"
done
[ "$PROJECT_ROOT" = "$BUILDER_PATH" ] || problem "the clone is at $PROJECT_ROOT, not $BUILDER_PATH"
# note: --force is less critical in other build scripts, but as the mac build is not doing a fresh clone,
#       it is very useful here for reproducibility
info "resetting git submodules."
git submodule update --init --force
# The checks below do not see files that a submodule's .gitignore hides (e.g. keepkeylib's *.pyc).
git submodule foreach --quiet --recursive git clean -ffdxq
# Remove what earlier builds put into the package directory. Anything else that is not committed
# there would end up in the app.
rm -f electrum/libsecp256k1.*.dylib electrum/libZXing.dylib electrum/libusb-1.0.dylib
changed="$(git status --porcelain --untracked-files=no)"
[ -z "$changed" ] || problem "the clone has local changes:"$'\n'"$changed"
untracked="$(git status --porcelain --untracked-files=all --ignored -- electrum)"
[ -z "$untracked" ] || problem "untracked files in electrum/ (try: git clean -ffdx -- electrum):"$'\n'"$untracked"
writable="$(find electrum \( -perm -g+w -o -perm -o+w \) -print | head -n 3)"
[ -z "$writable" ] || problem "group- or world-writable files; clone with umask 022:"$'\n'"$writable"
git describe --tags --exact-match > /dev/null 2>&1 \
    || warn "HEAD is not a release tag, so the apps cannot match a release."
[ -z "$PROBLEMS" ] || fail "This machine is not set up as a builder VM (see contrib/osx/README.md):$PROBLEMS"

rm -rf "$BUILDDIR"
mkdir -p "$DOWNLOADS" "$TOOLS" "$BUILDDIR" "$DLL_TARGET_DIR"

# curl -q: ignore ~/.curlrc
download() {  # url sha256 file
    if [ ! -f "$3" ]; then
        curl -q -fL --retry 3 -o "$3.part" "$1" || fail "Could not download $1"
        mv "$3.part" "$3"
    fi
    echo "$2  $3" | shasum -a 256 -c > /dev/null || { rm -f "$3"; fail "checksum mismatch: $3"; }
}


info "Installing Python $PYTHON_VERSION"
PKG_FILE="python-${PYTHON_VERSION}-macos11.pkg"
download "https://www.python.org/ftp/python/${PYTHON_VERSION}/$PKG_FILE" \
    8373e58da4ea146b3eb1c1f9834f19a319440b6b679b06050b1f9ee3237aa8e4 "$DOWNLOADS/$PKG_FILE"
sudo installer -pkg "$DOWNLOADS/$PKG_FILE" -target / \
    || fail "failed to install python"

# sanity check the installed Python has the version we just installed.
FOUND_PY_VERSION=$("$PYTHON" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
if [[ "$FOUND_PY_VERSION" != "$PYTHON_VERSION" ]]; then
    fail "python version mismatch: $FOUND_PY_VERSION != $PYTHON_VERSION"
fi

break_legacy_easy_install


info "Installing build tools"
# These replace Homebrew. They run on the build machine and are not part of the app.
mkdir -p "$TOOLS/bin"
export PATH="$TOOLS/bin:$TOOLS/autotools/bin:$PATH"

# GNU autotools, for libsecp256k1 and libusb. libtool is installed as glibtool and glibtoolize,
# as macOS has its own, different libtool.
AUTOTOOLS="m4/m4-1.4.19.tar.xz 63aede5c6d33b6d9b13511cd0be2cac046f2e70fd0a07aa9573a04a82783af96
autoconf/autoconf-2.72.tar.xz ba885c1319578d6c94d46e9b0dceb4014caafe2490e437a0dbca3f270a223f5a
automake/automake-1.17.tar.xz 8920c1fc411e13b90bf704ef9db6f29d540e76d232cb3b2c9f4dc4cc599bd990
libtool/libtool-2.5.4.tar.xz f81f5860666b0bc7d84baddefa60d1cb9fa6fceb2398cc3baca6afaa60266675"
export LIBTOOLIZE=glibtoolize
if [ "$(cat "$TOOLS/autotools/.pins" 2>/dev/null)" != "$AUTOTOOLS" ]; then
    rm -rf "$TOOLS/autotools" "$TOOLS/autotools-src"
    mkdir -p "$TOOLS/autotools-src"
    while read -r path sha256; do
        tarball="$DOWNLOADS/$(basename "$path")"
        download "https://ftp.gnu.org/gnu/$path" "$sha256" "$tarball"
        tar -xJf "$tarball" -C "$TOOLS/autotools-src"
        case "$path" in
            libtool/*) prefix_flag="--program-prefix=g" ;;
            *) prefix_flag="" ;;
        esac
        (
            cd "$TOOLS/autotools-src/$(basename "$path" .tar.xz)"
            ./configure --prefix="$TOOLS/autotools" $prefix_flag > configure.log
            make "-j$CPU_COUNT" > make.log
            make install > install.log
        ) || fail "Could not build $(basename "$path" .tar.xz), see $TOOLS/autotools-src"
    done <<< "$AUTOTOOLS"
    rm -rf "$TOOLS/autotools-src"
    echo "$AUTOTOOLS" > "$TOOLS/autotools/.pins"
fi

# cmake (zxing-cpp) and delocate (to fuse the Qt wheels below), from hash-pinned binary wheels
TOOLS_REQS="$CONTRIB/deterministic-build/requirements-build-mac-tools.txt"
if ! cmp -s "$TOOLS_REQS" "$TOOLS/venv/.pins"; then
    rm -rf "$TOOLS/venv"
    "$PYTHON" -m venv "$TOOLS/venv"
    "$TOOLS/venv/bin/python3" -m pip install --no-cache-dir --no-dependencies --only-binary :all: \
        --no-warn-script-location -qr "$TOOLS_REQS" || fail "Could not install build tools"
    cp "$TOOLS_REQS" "$TOOLS/venv/.pins"
fi
ln -sf "$TOOLS/venv/bin/cmake" "$TOOLS/venv/bin/delocate-merge" "$TOOLS/bin/"

# msgfmt (gettext) for the locale: CPython's msgfmt.py, which the python.org pkg ships
MSGFMT_PY="/Library/Frameworks/Python.framework/Versions/$PY_VER_MAJOR/share/doc/python$PY_VER_MAJOR/examples/Tools/i18n/msgfmt.py"
echo "6e2a25d5ca150ada9b6d3a68d4e37bc861e4f41bea01170a72d39bcb191e2a06  $MSGFMT_PY" | shasum -a 256 -c > /dev/null \
    || fail "unexpected $MSGFMT_PY"
printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$PYTHON" "$MSGFMT_PY" > "$TOOLS/bin/msgfmt"
chmod +x "$TOOLS/bin/msgfmt"


# create a fresh virtualenv
# This helps to avoid older versions of pip-installed dependencies interfering with the build.
rm -rf "$VENV_DIR"
"$PYTHON" -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Settings for C extensions that pip compiles from source:
# - ARCHFLAGS: build universal2 (x86_64 + arm64) binaries, which both apps need.
# - CFLAGS: python.org's own flags (-O3 -DNDEBUG ...), with -g0 instead of -g and without -arch.
#   They must be given in full: setuptools uses an exported CFLAGS instead of them, not in addition.
export ARCHFLAGS="-arch x86_64 -arch arm64"
EXT_CFLAGS="$("$PYTHON" -c 'import sysconfig; print(sysconfig.get_config_var("CFLAGS"))' \
    | sed -E 's/^/ /; s/$/ /; s/ -arch [a-z0-9_]+//g; s/ -g / -g0 /g; s/ -g / -g0 /g; s/^ +//; s/ +$//')"
info "C extensions: ARCHFLAGS=$ARCHFLAGS, CFLAGS=$EXT_CFLAGS"
pip_install() {  # args...: C extensions get EXT_CFLAGS, which no other build should get
    CFLAGS="$EXT_CFLAGS" CXXFLAGS="$EXT_CFLAGS" python3 -m pip install --no-build-isolation --no-dependencies \
        --no-warn-script-location --no-cache-dir "$@"
}

info "Installing build dependencies"
# note: re pip installing from PyPI,
#       we prefer compiling C extensions ourselves, instead of using binary wheels,
#       hence "--no-binary :all:" flags. However, we specifically allow
#       - PyQt6, as it's harder to build from source
#       - cryptography, as it's harder to build from source
#       - the whole of "requirements-build-base.txt", which includes pip and friends, as it also includes "wheel",
#         and I am not quite sure how to break the circular dependence there (I guess we could introduce
#         "requirements-build-base-base.txt" with just wheel in it...)
pip_install -Ir ./contrib/deterministic-build/requirements-build-base.txt \
    || fail "Could not install build dependencies (base)"
pip_install --no-binary :all: -Ir ./contrib/deterministic-build/requirements-build-mac.txt \
    || fail "Could not install build dependencies (mac)"


info "Building native libraries"
# All three as universal2 binaries in one pass, with Apple clang.
(
    export CC=clang CXX=clang++
    CMAKE_OSX_ARCHITECTURES="x86_64;arm64" CFLAGS="-O2 -g0" CXXFLAGS="-O2 -g0" \
        "$CONTRIB"/make_zxing.sh || fail "Could not build zxing-cpp dylib"
    # (multi-arch builds of libsecp256k1 need --with-asm=no)
    CFLAGS="-O2 -g0 $ARCHFLAGS" LDFLAGS="$ARCHFLAGS" \
    AUTOCONF_FLAGS="--with-asm=no --with-valgrind=no --disable-dependency-tracking" \
        "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
    # (make_libusb.sh sets its own LDFLAGS; the -arch flags reach the linker through CFLAGS)
    CFLAGS="-O2 -g0 $ARCHFLAGS" AUTOCONF_FLAGS="--disable-dependency-tracking" \
        "$CONTRIB"/make_libusb.sh || fail "Could not build libusb dylib"
)
cp -f "$DLL_TARGET_DIR"/libsecp256k1.*.dylib "$DLL_TARGET_DIR/libZXing.dylib" "$DLL_TARGET_DIR/libusb-1.0.dylib" \
    "$PROJECT_ROOT/electrum/" || fail "Could not copy the native libraries"


info "Building PyInstaller."
PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="306d4d92580fea7be7ff2c89ba112cdc6f73fac1"
# ^ tag "v6.13.0"
(
    ELECTRUM_COMMIT_HASH=$(git rev-parse HEAD)
    mkdir "$BUILDDIR/pyinstaller"
    cd "$BUILDDIR/pyinstaller"
    # Shallow clone
    git init -q
    git remote add origin $PYINSTALLER_REPO
    git fetch -q --depth 1 origin $PYINSTALLER_COMMIT
    git checkout -q -b pinned "${PYINSTALLER_COMMIT}^{commit}"
    rm -fv PyInstaller/bootloader/Darwin-*/run* || true
    # add reproducible randomness. this ensures we build a different bootloader for each commit.
    # if we built the same one for all releases, that might also get anti-virus false positives
    echo "const char *electrum_tag = \"tagged by Electrum@$ELECTRUM_COMMIT_HASH\";" >> ./bootloader/src/pyi_main.c
    pushd bootloader
    # compile bootloader (universal2 by default)
    python3 ./waf all CFLAGS="-static"
    popd
    # sanity check bootloader is there:
    [ "$(lipo -archs PyInstaller/bootloader/Darwin-64bit/runw)" = "x86_64 arm64" ] \
        || fail "Could not find a universal2 runw in target dir!"
) || fail "Could not build the PyInstaller bootloader"
info "Installing PyInstaller."
pip_install "$BUILDDIR/pyinstaller" || fail "Could not install PyInstaller"

info "Using these versions for building $PACKAGE:"
sw_vers
python3 --version
echo -n "Pyinstaller "
pyinstaller --version

info "preparing electrum-locale."
(
    "$CONTRIB/locale/build_cleanlocale.sh"
    # build_locale.sh ignores msgfmt errors
    n_po=$(ls "$PROJECT_ROOT/electrum/locale/locale"/*/electrum.po | wc -l)
    n_mo=$(ls "$PROJECT_ROOT/electrum/locale/locale"/*/LC_MESSAGES/electrum.mo | wc -l)
    [ "$n_po" -eq "$n_mo" ] || fail "msgfmt failed for $((n_po - n_mo)) of $n_po languages"
    # we want the binary to have only compiled (.mo) locale files; not source (.po) files
    rm -r "$PROJECT_ROOT/electrum/locale/locale"/*/electrum.po
) || fail "Could not prepare the locale"


# opt out of compiling C extensions
export YARL_NO_EXTENSIONS=1
export PROPCACHE_NO_EXTENSIONS=1

export ELECTRUM_ECC_DONT_COMPILE=1

info "Installing requirements..."
pip_install --no-binary :all: \
    -Ir ./contrib/deterministic-build/requirements.txt \
    || fail "Could not install requirements"

info "Installing hardware wallet requirements..."
pip_install --no-binary :all: --only-binary cryptography \
    -Ir ./contrib/deterministic-build/requirements-hw.txt \
    || fail "Could not install hardware wallet requirements"

info "Installing dependencies specific to binaries..."
# PyQt6-Qt6 has separate x86_64 and arm64 wheels. delocate-merge fuses the two (hash-checked) wheels
# into one universal2 wheel, which is installed instead.
awk -v qt="$BUILDDIR/requirements-qt6.txt" -v rest="$BUILDDIR/requirements-binaries-mac.txt" \
    '/^PyQt6-Qt6==/ { in_qt = 1 } { print > (in_qt ? qt : rest) } in_qt && !/\\$/ { in_qt = 0 }' \
    ./contrib/deterministic-build/requirements-binaries-mac.txt
for platform in macosx_10_14_x86_64 macosx_11_0_arm64; do
    python3 -m pip download --no-dependencies --only-binary :all: --platform "$platform" --no-cache-dir \
        -d "$BUILDDIR/qt6-$platform" -r "$BUILDDIR/requirements-qt6.txt" \
        || fail "Could not download the PyQt6-Qt6 wheel for $platform"
done
delocate-merge "$BUILDDIR"/qt6-macosx_10_14_x86_64/*.whl "$BUILDDIR"/qt6-macosx_11_0_arm64/*.whl \
    -w "$BUILDDIR/qt6-universal2" || fail "Could not fuse the PyQt6-Qt6 wheels"
pip_install --no-binary :all: --only-binary PyQt6,cryptography \
    -Ir "$BUILDDIR/requirements-binaries-mac.txt" \
    || fail "Could not install dependencies specific to binaries"
pip_install "$BUILDDIR"/qt6-universal2/*.whl || fail "Could not install the fused PyQt6-Qt6 wheel"

info "Building $PACKAGE..."
rm -rf ./dist ./build ./Electrum.egg-info  # setuptools would reuse a stale build/lib
pip_install . > /dev/null || fail "Could not build $PACKAGE"
# pyinstaller needs to be able to "import electrum_ecc", for which we need libsecp256k1:
# (or could try "pip install -e" instead)
cp "$DLL_TARGET_DIR"/libsecp256k1.*.dylib "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/electrum_ecc/"

# strip debug symbols of some compiled libs
# - hidapi (hid.cpython-39-darwin.so) in particular is not reproducible without this
find "$VENV_DIR/lib/python$PY_VER_MAJOR/site-packages/" -type f -name '*.so' -print0 \
    | xargs -0 -t strip -x

info "Faking timestamps..."
find . -exec touch -t '200101220000' {} + || true

# note: no --dirty, as we have dirtied electrum/locale/ ourselves.
# --abbrev: by default, the hash length depends on how many objects the clone has.
VERSION=$(git describe --tags --always --abbrev=10)

# Prints one line per problem: a Mach-O file with another architecture than $2, a deployment
# target above 12.0, or a library path outside the app and macOS.
audit_app() {
    find "$1" -type f | while read -r f; do
        archs="$(lipo -archs "$f" 2>/dev/null)" || continue
        [ "$archs" = "$2" ] || echo "  ${f#$1/}: architectures $archs"
        minos="$(vtool -show-build "$f" 2>/dev/null | awk '$1 == "minos" { print $2; exit }')"
        if [ -n "$minos" ] && [ "$(printf '%s\n12.0\n' "$minos" | sort -t. -k1,1n -k2,2n | tail -1)" != 12.0 ]; then
            echo "  ${f#$1/}: minos $minos"
        fi
        otool -L "$f" | tail -n +2 | awk -v f="${f#$1/}" \
            '$1 ~ /^\/(usr\/local|opt|Users|tmp|private)\// { print "  " f ": links " $1 }'
    done
}

for arch in $ARCHS; do
    info "Building binary for $arch"
    ELECTRUM_VERSION=$VERSION ELECTRUM_TARGET_ARCH=$arch pyinstaller --noconfirm --clean \
        --distpath "dist/$arch" --workpath "build/$arch" contrib/osx/pyinstaller.spec \
        || fail "Could not build binary for $arch"
    problems="$(audit_app "dist/$arch/$PACKAGE.app" "$arch")"
    [ -z "$problems" ] || fail "dist/$arch/$PACKAGE.app:"$'\n'"$problems"
done

for arch in $ARCHS; do
    info "Creating unsigned .DMG for $arch"
    hdiutil create -fs HFS+ -volname $PACKAGE -srcfolder "dist/$arch/$PACKAGE.app" \
        "dist/electrum-$VERSION-$arch-unsigned.dmg" || fail "Could not create .DMG"
done

info "Finished building unsigned apps. These hashes should be reproducible:"
for arch in $ARCHS; do
    # one hash over all files, directories and symlinks of the app
    "$PYTHON" "$CONTRIB_OSX/codesign_replay.py" manifest "dist/$arch/$PACKAGE.app" > "$BUILDDIR/$arch.manifest" \
        || fail "Could not hash dist/$arch/$PACKAGE.app"
    echo "$(shasum -a 256 < "$BUILDDIR/$arch.manifest" | cut -d ' ' -f 1)  dist/$arch/$PACKAGE.app"
done

info "Apps were built successfully but were not code signed. Users may get security warnings from macOS."
info "Now you also need to run sign_osx.sh to codesign/notarize the binaries."
