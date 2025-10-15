#!/bin/bash

# BSP 版本配置 - 设置为 "0806" 或 "0902" 来切换 BSP 版本
BSP_VERSION="0806"

SDK_DIR_0806="$HOME/opt/ti-processor-sdk-linux-j7-evm-08_06_01_02"
SDK_DIR_0902="$HOME/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05"

# 根据 BSP 版本设置 SDK 目录
if [ "$BSP_VERSION" = "0806" ]; then
    SDK_INSTALL_DIR=$SDK_DIR_0806
elif [ "$BSP_VERSION" = "0902" ]; then
    SDK_INSTALL_DIR=$SDK_DIR_0902
else
    echo "Error: Invalid BSP_VERSION: $BSP_VERSION. Please set to '0806' or '0902'"
    exit 1
fi

# 根据 BSP 版本设置 sysroot 和工具链路径
if [ "$BSP_VERSION" = "0806" ]; then
    SYSROOT="$SDK_INSTALL_DIR/linux-devkit/sysroots/aarch64-linux"
    TOOLCHAIN_DIR="$SDK_INSTALL_DIR/linux-devkit/sysroots/x86_64-arago-linux/usr/bin"
    C_COMPILER="$TOOLCHAIN_DIR/aarch64-none-linux-gnu-gcc"
    CXX_COMPILER="$TOOLCHAIN_DIR/aarch64-none-linux-gnu-g++"
    AR="$TOOLCHAIN_DIR/aarch64-none-linux-gnu-ar"
    RANLIB="$TOOLCHAIN_DIR/aarch64-none-linux-gnu-ranlib"
elif [ "$BSP_VERSION" = "0902" ]; then
    SYSROOT="$SDK_INSTALL_DIR/linux-devkit/sysroots/aarch64-oe-linux"
    TOOLCHAIN_DIR="$SDK_INSTALL_DIR/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-oe-linux"
    C_COMPILER="$TOOLCHAIN_DIR/aarch64-oe-linux-gcc"
    CXX_COMPILER="$TOOLCHAIN_DIR/aarch64-oe-linux-g++"
    AR="$TOOLCHAIN_DIR/aarch64-oe-linux-ar"
    RANLIB="$TOOLCHAIN_DIR/aarch64-oe-linux-ranlib"
fi

OPENSSL_VERSION="1.1.1f"
OPENSSL_DIR="openssl-$OPENSSL_VERSION"
OPENSSL_URL="https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz"
WORK_DIR="$PWD"

# Display current configuration
echo "=========================================="
echo "Cross-compiling OpenSSL for TI Processor SDK"
echo "BSP Version: $BSP_VERSION"
echo "SDK Directory: $SDK_INSTALL_DIR"
echo "OpenSSL Version: $OPENSSL_VERSION"
echo "=========================================="

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

# 下载 OpenSSL
if [ ! -f "$OPENSSL_DIR.tar.gz" ]; then
    echo "Downloading OpenSSL $OPENSSL_VERSION..."
    # Try curl first, fallback to wget if curl fails
    if command -v curl >/dev/null 2>&1; then
        curl -L -o "$OPENSSL_DIR.tar.gz" "$OPENSSL_URL" || { echo "Error: Failed to download OpenSSL with curl"; exit 1; }
    else
        wget --no-check-certificate "$OPENSSL_URL" || { echo "Error: Failed to download OpenSSL with wget"; exit 1; }
    fi
fi

if [ ! -d "$OPENSSL_DIR" ]; then
    echo "Extracting OpenSSL $OPENSSL_VERSION..."
    tar -xzf "$OPENSSL_DIR.tar.gz" || { echo "Error: Failed to extract OpenSSL"; exit 1; }
fi
cd "$OPENSSL_DIR" || { echo "Error: Failed to change to $OPENSSL_DIR"; exit 1; }

echo "Configuring OpenSSL..."

# 根据 BSP 版本设置目标平台
if [ "$BSP_VERSION" = "0806" ]; then
    TARGET_PLATFORM="linux-aarch64"
    CROSS_COMPILE_PREFIX="aarch64-none-linux-gnu-"
elif [ "$BSP_VERSION" = "0902" ]; then
    TARGET_PLATFORM="linux-aarch64"
    CROSS_COMPILE_PREFIX="aarch64-oe-linux-"
fi

# 设置交叉编译环境变量
export CC="$C_COMPILER"
export CXX="$CXX_COMPILER"
export AR="$AR"
export RANLIB="$RANLIB"
export PATH="$TOOLCHAIN_DIR:$PATH"

# 配置 OpenSSL
./Configure \
    $TARGET_PLATFORM \
    --prefix="$SYSROOT/usr" \
    --openssldir="$SYSROOT/usr/ssl" \
    --sysroot="$SYSROOT" \
    shared \
    zlib-dynamic \
    no-ssl3 \
    no-ssl3-method \
    no-weak-ssl-ciphers \
    -fPIC \
    || { echo "Error: Configure failed"; exit 1; }

echo "Building and installing OpenSSL..."
make -j$(nproc) || { echo "Error: Build failed"; exit 1; }
make install_sw || { echo "Error: Install failed"; exit 1; }

echo "Verifying OpenSSL installation..."
find "$SYSROOT/usr/lib" -name "libssl*" | grep -q "libssl" && \
find "$SYSROOT/usr/lib" -name "libcrypto*" | grep -q "libcrypto" && \
find "$SYSROOT/usr/include" -name "openssl" | grep -q "openssl" && \
echo "OpenSSL installed successfully to $SYSROOT/usr" || \
{ echo "Error: OpenSSL installation verification failed"; exit 1; }

echo "Cleaning up..."
cd "$WORK_DIR"
rm -rf "$OPENSSL_DIR" "$OPENSSL_DIR.tar.gz" || { echo "Warning: Cleanup failed"; }

echo "OpenSSL cross-compilation and installation completed!"
exit 0
