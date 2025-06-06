#!/bin/bash

# Automated script: Build aktualizr for TI Processor SDK

# Set environment variables
SDK_DIR="$HOME/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05"
SYSROOT="$SDK_DIR/linux-devkit/sysroots/aarch64-oe-linux"
TOOLCHAIN_FILE="../toolchain.cmake"

# Check if SDK directory exists
if [ ! -d "$SDK_DIR" ]; then
    echo "Error: SDK directory '$SDK_DIR' does not exist"
    exit 1
fi

# Check if sysroot exists
if [ ! -d "$SYSROOT" ]; then
    echo "Error: Sysroot directory '$SYSROOT' does not exist"
    exit 1
fi

# Check if toolchain file exists
if [ ! -f "$TOOLCHAIN_FILE" ]; then
    echo "Error: Toolchain file '$TOOLCHAIN_FILE' does not exist"
    exit 1
fi

# Remove existing build directory
echo "Removing existing build directory..."
rm -rfv build || { echo "Error: Failed to remove build directory"; exit 1; }

# Create and enter build directory
echo "Creating build directory..."
mkdir -p build || { echo "Error: Failed to create build directory"; exit 1; }
pushd build >/dev/null || { echo "Error: Failed to enter build directory"; exit 1; }

# Run CMake configuration
echo "Configuring build with CMake..."
# cmake -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
#       -DCMAKE_PREFIX_PATH="$SYSROOT/usr" \
#       -DBUILD_OSTREE=OFF \
#       -DBUILD_P11=OFF \
#       -DBUILD_SOTA_TOOLS=OFF \
#       .. || { echo "Error: CMake configuration failed"; popd >/dev/null; exit 1; }
cmake -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
      -DCMAKE_PREFIX_PATH="$SYSROOT/usr" \
      .. || { echo "Error: CMake configuration failed"; popd >/dev/null; exit 1; }

# Return to original directory
popd >/dev/null || { echo "Error: Failed to return to original directory"; exit 1; }

echo "Build configuration completed successfully!"
exit 0