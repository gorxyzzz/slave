#!/bin/bash
set -e

BUILD_DIR="build"
MSLAVE_PKG="./mslave"
SLAVE_PKG="./slave"

mkdir -p "$BUILD_DIR"

build() {
    local os=$1
    local arch=$2
    local slave_bin="$BUILD_DIR/slave-${os}-${arch}"
    local mslave_bin="$BUILD_DIR/mslave-${os}-${arch}"
    local embed_dir="$MSLAVE_PKG/slave"

    echo "=== Building for ${os}/${arch} ==="

    # Build slave
    echo "  Building slave..."
    GOOS=$os GOARCH=$arch go build -o "$slave_bin" "$SLAVE_PKG/"

    # Prepare embed directory
    echo "  Preparing embed..."
    rm -rf "$embed_dir"
    mkdir -p "$embed_dir"
    cp "$slave_bin" "$embed_dir/slave"

    # Build mslave with embedded slave
    echo "  Building mslave..."
    GOOS=$os GOARCH=$arch go build -o "$mslave_bin" "$MSLAVE_PKG/"

    # Cleanup embed directory
    rm -rf "$embed_dir"

    echo "  Done: $mslave_bin"
    echo ""
}

# Build for linux
build "linux" "arm64"
build "linux" "amd64"

# Also build for current platform (darwin) for testing
echo "=== Building for darwin/amd64 (testing) ==="
# Build slave first
GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/slave-darwin-amd64" "$SLAVE_PKG/"
# Prepare embed
rm -rf "$MSLAVE_PKG/slave"
mkdir -p "$MSLAVE_PKG/slave"
cp "$BUILD_DIR/slave-darwin-amd64" "$MSLAVE_PKG/slave/slave"
# Build mslave
GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/mslave-darwin-amd64" "$MSLAVE_PKG/"
rm -rf "$MSLAVE_PKG/slave"
echo ""

echo "=== Build complete ==="
ls -la "$BUILD_DIR/"
