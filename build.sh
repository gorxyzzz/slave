#!/bin/bash
set -e

BUILD_DIR="build"
MASTER_PKG="./master"
SLAVE_PKG="./slave"
MSLAVE_PKG="./mslave"

mkdir -p "$BUILD_DIR"

build() {
    local os=$1
    local arch=$2
    local master_bin="$BUILD_DIR/master-${os}-${arch}"
    local slave_bin="$BUILD_DIR/slave-${os}-${arch}"
    local mslave_bin="$BUILD_DIR/mslave-${os}-${arch}"
    local embed_dir="$MSLAVE_PKG/slave"

    echo "=== Building for ${os}/${arch} ==="

    echo "  Building master..."
    GOOS=$os GOARCH=$arch go build -o "$master_bin" "$MASTER_PKG/"

    echo "  Building slave..."
    GOOS=$os GOARCH=$arch go build -o "$slave_bin" "$SLAVE_PKG/"

    # Stage the slave binary where mslave's //go:embed expects it.
    echo "  Preparing embed..."
    rm -rf "$embed_dir"
    mkdir -p "$embed_dir"
    cp "$slave_bin" "$embed_dir/slave"

    echo "  Building mslave..."
    GOOS=$os GOARCH=$arch go build -o "$mslave_bin" "$MSLAVE_PKG/"

    # Cleanup embed directory
    rm -rf "$embed_dir"

    echo "  Done: $mslave_bin"
    echo ""
}

build "linux" "arm64"
build "linux" "amd64"
build "darwin" "amd64"

echo "=== Build complete ==="
ls -la "$BUILD_DIR/"
