#!/bin/bash

# Automated script: Cross-compile Boost and install to TI Processor SDK sysroot

# BSP 版本配置 - 设置为 "0806" 或 "0902" 来切换 BSP 版本
BSP_VERSION="0806"

# Set environment variables
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

BOOST_VERSION="1.78.0"
BOOST_DIR="boost_$(echo $BOOST_VERSION | tr '.' '_')"
BOOST_URL="https://archives.boost.io/release/$BOOST_VERSION/source/$BOOST_DIR.tar.gz"
WORK_DIR="$PWD"

# Display current configuration
echo "=========================================="
echo "Cross-compiling Boost for TI Processor SDK"
echo "BSP Version: $BSP_VERSION"
echo "SDK Directory: $SDK_INSTALL_DIR"
echo "Boost Version: $BOOST_VERSION"
echo "=========================================="

# Check if toolchain and sysroot exist
if [ ! -f "$C_COMPILER" ] || [ ! -f "$CXX_COMPILER" ]; then
    echo "Error: Toolchain not found at $TOOLCHAIN_DIR"
    exit 1
fi
if [ ! -d "$SYSROOT" ]; then
    echo "Error: Sysroot not found at $SYSROOT"
    exit 1
fi

# Create working directory
mkdir -p "$WORK_DIR" || { echo "Error: Failed to create $WORK_DIR"; exit 1; }
cd "$WORK_DIR" || { echo "Error: Failed to change to $WORK_DIR"; exit 1; }

# Download Boost
if [ ! -f "$BOOST_DIR.tar.gz" ]; then
    echo "Downloading Boost $BOOST_VERSION..."
    # Try curl first, fallback to wget if curl fails
    if command -v curl >/dev/null 2>&1; then
        curl -L -o "$BOOST_DIR.tar.gz" "$BOOST_URL" || { echo "Error: Failed to download Boost with curl"; exit 1; }
    else
        wget --no-check-certificate "$BOOST_URL" || { echo "Error: Failed to download Boost with wget"; exit 1; }
    fi
fi

# Extract Boost
if [ ! -d "$BOOST_DIR" ]; then
    echo "Extracting Boost $BOOST_VERSION..."
    tar -xvf "$BOOST_DIR.tar.gz" || { echo "Error: Failed to extract Boost"; exit 1; }
fi
cd "$BOOST_DIR" || { echo "Error: Failed to change to $BOOST_DIR"; exit 1; }

# Create Boost user-config.jam
echo "Creating Boost user-config.jam..."
cat > user-config.jam << EOF
using gcc : crossgcc :
  $CXX_COMPILER :
  <cxxflags>"--sysroot=$SYSROOT -fPIC"
  <linkflags>"--sysroot=$SYSROOT"
  <archiver>$AR
  <ranlib>$RANLIB
;
EOF

# Copy user-config.jam to home directory to ensure b2 can find it
cp user-config.jam "$HOME/user-config.jam" || { echo "Error: Failed to copy user-config.jam to $HOME"; exit 1; }

# Configure Boost
echo "Configuring Boost..."
# Allow bootstrap to use host compiler to build b2
./bootstrap.sh --prefix="$SYSROOT/usr" || { echo "Error: Bootstrap failed"; exit 1; }

# Build and install Boost
echo "Building and installing Boost..."
./b2 \
  --with-log \
  --with-system \
  --with-filesystem \
  --with-program_options \
  toolset=gcc-crossgcc \
  architecture=arm \
  address-model=64 \
  link=shared \
  threading=multi \
  variant=release \
  --user-config=user-config.jam \
  install || { echo "Error: Build or install failed"; exit 1; }

# Verify installation
echo "Verifying Boost installation..."
find "$SYSROOT/usr/lib" -name "libboost_*" | grep -q "libboost" && \
find "$SYSROOT/usr/include" -name "boost" | grep -q "boost" && \
echo "Boost installed successfully to $SYSROOT/usr" || \
{ echo "Error: Boost installation verification failed"; exit 1; }

# Optional: Clean up temporary files
echo "Cleaning up..."
cd "$WORK_DIR"
rm -rf "$BOOST_DIR" "$BOOST_DIR.tar.gz" "$HOME/user-config.jam" || { echo "Warning: Cleanup failed"; }

echo "Boost cross-compilation and installation completed!"
exit 0