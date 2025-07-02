#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_OSX="$CONTRIB/osx"

. "$CONTRIB"/build_tools_util.sh

DARLING_COMMIT_HASH="5faf581f43208c42b45e61c8de9fd412201b83ce"
DARLING_DIR="$HOME/darling"
DARLING_BUILD_DIR="$DARLING_DIR/build"

check_darling() {
    if command -v darling >/dev/null 2>&1; then
        info "Darling is already installed and available in PATH"
        return 0
    else
        info "Darling not found in PATH"
        return 1
    fi
}

install_darling() {
    info "Installing Darling..."
    
    # Check if git lfs is installed
    if ! command -v git-lfs >/dev/null 2>&1; then
        fail "git-lfs is required but not installed. Please install it first."
    fi
        
    # Clone Darling if not already cloned
    if [ ! -d "$DARLING_DIR" ]; then
        info "Cloning Darling repository..."
        cd "$HOME"
        git lfs install
        GIT_CLONE_PROTECTION_ACTIVE=false git clone --recursive https://github.com/darlinghq/darling.git
        cd "$DARLING_DIR"
        git checkout "$DARLING_COMMIT_HASH^{commit}"
        git submodule update --init --recursive
    else
        info "Darling repository already exists"
        cd "$DARLING_DIR"
    fi
    
    # Build Darling if not already built
    if [ ! -d "$DARLING_BUILD_DIR" ]; then
        info "Building Darling (this may take a while)..."
        mkdir -p "$DARLING_BUILD_DIR"
        cd "$DARLING_BUILD_DIR"
        cmake -DTARGET_i386=OFF ..
        make -j"${CPU_COUNT:-1}"
    else
        info "Darling build directory already exists"
        cd "$DARLING_BUILD_DIR"
    fi
    
    info "Installing Darling..."
    sudo make install
    
    # Verify installation
    if ! command -v darling >/dev/null 2>&1; then
        fail "Darling installation failed - darling command not found after installation"
    fi
    
    info "Darling installed successfully"
}

# Check if Darling is available
if ! check_darling; then
    install_darling
fi

info "Running Electrum macOS build in Darling..."

cd "$PROJECT_ROOT"

# Run the macOS build script inside Darling shell
darling shell bash -c "./contrib/osx/make_osx.sh" || fail "macOS build failed"

info "macOS build completed successfully!"
