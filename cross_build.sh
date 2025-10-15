#!/bin/bash

# Automated script: Build aktualizr for TI Processor SDK

# BSP 版本配置 - 设置为 "0806" 或 "0902" 来切换 BSP 版本
BSP_VERSION="0806"

# Set environment variables
SDK_DIR_0806="$HOME/opt/ti-processor-sdk-linux-j7-evm-08_06_01_02"
SDK_DIR_0902="$HOME/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05"

# 根据 BSP 版本设置 SDK 目录
if [ "$BSP_VERSION" = "0806" ]; then
    SDK_DIR=$SDK_DIR_0806
elif [ "$BSP_VERSION" = "0902" ]; then
    SDK_DIR=$SDK_DIR_0902
else
    echo "Error: Invalid BSP_VERSION: $BSP_VERSION. Please set to '0806' or '0902'"
    exit 1
fi

# 根据 BSP 版本设置 sysroot 路径
if [ "$BSP_VERSION" = "0806" ]; then
    SYSROOT="$SDK_DIR/linux-devkit/sysroots/aarch64-linux"
elif [ "$BSP_VERSION" = "0902" ]; then
    SYSROOT="$SDK_DIR/linux-devkit/sysroots/aarch64-oe-linux"
fi

TOOLCHAIN_FILE="../toolchain.cmake"

# Display current configuration
echo "=========================================="
echo "Building aktualizr for TI Processor SDK"
echo "BSP Version: $BSP_VERSION"
echo "SDK Directory: $SDK_DIR"
echo "=========================================="

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

# Check if toolchain file exists (check the actual file path, not the relative path used in build)
if [ ! -f "toolchain.cmake" ]; then
    echo "Error: Toolchain file 'toolchain.cmake' does not exist in current directory"
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

make -j8

# Return to original directory
popd >/dev/null || { echo "Error: Failed to return to original directory"; exit 1; }

echo "Build configuration completed successfully!"
exit 0