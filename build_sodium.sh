#!/bin/bash

SDK_INSTALL_DIR="$HOME/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05"
SYSROOT="$SDK_INSTALL_DIR/linux-devkit/sysroots/aarch64-oe-linux"
TOOLCHAIN_DIR="$SDK_INSTALL_DIR/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-oe-linux"
LIBSODIUM_VERSION="1.0.20"
LIBSODIUM_DIR="libsodium-$LIBSODIUM_VERSION"
LIBSODIUM_URL="https://download.libsodium.org/libsodium/releases/libsodium-$LIBSODIUM_VERSION.tar.gz"
WORK_DIR="$PWD"

C_COMPILER="$TOOLCHAIN_DIR/aarch64-oe-linux-gcc"
CXX_COMPILER="$TOOLCHAIN_DIR/aarch64-oe-linux-g++"
AR="$TOOLCHAIN_DIR/aarch64-oe-linux-ar"
RANLIB="$TOOLCHAIN_DIR/aarch64-oe-linux-ranlib"

if [ ! -f "$C_COMPILER" ] || [ ! -f "$CXX_COMPILER" ]; then
    echo "Error: Toolchain not found at $TOOLCHAIN_DIR"
    exit 1
fi
if [ ! -d "$SYSROOT" ]; then
    echo "Error: Sysroot not found at $SYSROOT"
    exit 1
fi

mkdir -p "$WORK_DIR" || { echo "Error: Failed to create $WORK_DIR"; exit 1; }
cd "$WORK_DIR" || { echo "Error: Failed to change to $WORK_DIR"; exit 1; }

# 下载 libsodium
if [ ! -f "$LIBSODIUM_DIR.tar.gz" ]; then
    echo "Downloading libsodium $LIBSODIUM_VERSION..."
    proxychains wget --no-check-certificate "$LIBSODIUM_URL" || { echo "Error: Failed to download libsodium"; exit 1; }
fi

if [ ! -d "$LIBSODIUM_DIR" ]; then
    echo "Extracting libsodium $LIBSODIUM_VERSION..."
    tar -xzf "$LIBSODIUM_DIR.tar.gz" || { echo "Error: Failed to extract libsodium"; exit 1; }
fi
cd "$LIBSODIUM_DIR" || { echo "Error: Failed to change to $LIBSODIUM_DIR"; exit 1; }

echo "Configuring libsodium..."
export CC="$C_COMPILER --sysroot=$SYSROOT"
export CXX="$CXX_COMPILER --sysroot=$SYSROOT"
export CFLAGS="-fPIC -O2"
export LDFLAGS="--sysroot=$SYSROOT"
export AR="$AR"
export RANLIB="$RANLIB"
./configure --host=aarch64-oe-linux --prefix="$SYSROOT/usr" || { echo "Error: Configure failed"; exit 1; }

echo "Building and installing libsodium..."
make -j$(nproc) || { echo "Error: Build failed"; exit 1; }
make install || { echo "Error: Install failed"; exit 1; }

echo "Verifying libsodium installation..."
find "$SYSROOT/usr/lib" -name "libsodium*" | grep -q "libsodium" && \
find "$SYSROOT/usr/include" -name "sodium.h" | grep -q "sodium.h" && \
echo "libsodium installed successfully to $SYSROOT/usr" || \
{ echo "Error: libsodium installation verification failed"; exit 1; }

echo "Cleaning up..."
cd "$WORK_DIR"
rm -rf "$LIBSODIUM_DIR" "$LIBSODIUM_DIR.tar.gz" || { echo "Warning: Cleanup failed"; }

echo "libsodium cross-compilation and installation completed!"
exit 0