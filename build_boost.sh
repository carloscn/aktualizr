#!/bin/bash

# Automated script: Cross-compile Boost and install to TI Processor SDK sysroot

# Set environment variables
SDK_INSTALL_DIR="$HOME/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05"
SYSROOT="$SDK_INSTALL_DIR/linux-devkit/sysroots/aarch64-oe-linux"
TOOLCHAIN_DIR="$SDK_INSTALL_DIR/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-oe-linux"
BOOST_VERSION="1.78.0"
BOOST_DIR="boost_$(echo $BOOST_VERSION | tr '.' '_')"
BOOST_URL="https://archives.boost.io/release/$BOOST_VERSION/source/$BOOST_DIR.tar.gz"
WORK_DIR="$PWD"

# Toolchain paths
C_COMPILER="$TOOLCHAIN_DIR/aarch64-oe-linux-gcc"
CXX_COMPILER="$TOOLCHAIN_DIR/aarch64-oe-linux-g++"
AR="$TOOLCHAIN_DIR/aarch64-oe-linux-ar"
RANLIB="$TOOLCHAIN_DIR/aarch64-oe-linux-ranlib"

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
    proxychains wget --no-check-certificate "$BOOST_URL" || { echo "Error: Failed to download Boost"; exit 1; }
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