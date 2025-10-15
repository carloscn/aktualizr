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

# 根据 BSP 版本设置 sysroot 路径
if [ "$BSP_VERSION" = "0806" ]; then
    SYSROOT="$SDK_INSTALL_DIR/linux-devkit/sysroots/aarch64-linux"
elif [ "$BSP_VERSION" = "0902" ]; then
    SYSROOT="$SDK_INSTALL_DIR/linux-devkit/sysroots/aarch64-oe-linux"
fi

# 配置变量
PACKAGE_NAME="aktualizr-package"
PACKAGE_DIR="$PWD/$PACKAGE_NAME"
BUILD_DIR="$PWD/build"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PACKAGE_ARCHIVE="aktualizr-${BSP_VERSION}-${TIMESTAMP}.tar.gz"

# Display current configuration
echo "=========================================="
echo "Packaging aktualizr for TI Processor SDK"
echo "BSP Version: $BSP_VERSION"
echo "SDK Directory: $SDK_INSTALL_DIR"
echo "Package Directory: $PACKAGE_DIR"
echo "=========================================="

# 检查构建目录是否存在
if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory '$BUILD_DIR' does not exist. Please run build first."
    exit 1
fi

# 检查 sysroot 是否存在
if [ ! -d "$SYSROOT" ]; then
    echo "Error: Sysroot directory '$SYSROOT' does not exist"
    exit 1
fi

# 清理并创建包目录
echo "Creating package directory structure..."
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"/{bin,lib,appdata}

# 复制二进制文件
echo "Copying binary files..."
BINARIES=(
    "aktualizr_primary/aktualizr"
    "aktualizr_secondary/aktualizr-secondary"
    "aktualizr_info/aktualizr-info"
    "aktualizr_get/aktualizr-get"
    "cert_provider/aktualizr-cert-provider"
    "uptane_generator/uptane-generator"
)

for binary in "${BINARIES[@]}"; do
    src="$BUILD_DIR/src/$binary"
    if [ -f "$src" ]; then
        echo "  Copying $binary"
        cp "$src" "$PACKAGE_DIR/bin/"
        chmod +x "$PACKAGE_DIR/bin/$(basename "$binary")"
    else
        echo "  Warning: $binary not found"
    fi
done

# 复制库文件
echo "Copying library files..."
LIBRARIES=(
    "libaktualizr-c/libaktualizr-c.so"
    "aktualizr_secondary/libaktualizr_secondary.so"
    "libaktualizr/libaktualizr.so"
)

for lib in "${LIBRARIES[@]}"; do
    src="$BUILD_DIR/src/$lib"
    if [ -f "$src" ]; then
        echo "  Copying $lib"
        cp "$src" "$PACKAGE_DIR/lib/"
    else
        echo "  Warning: $lib not found"
    fi
done

# 收集依赖库
echo "Collecting dependency libraries..."

# 获取所有二进制文件的依赖库
ALL_BINARIES="$PACKAGE_DIR/bin/*"
for binary in $ALL_BINARIES; do
    if [ -f "$binary" ]; then
        echo "  Analyzing dependencies for $(basename "$binary")..."
        
        # 使用 ldd 获取依赖库（如果可用）
        if command -v ldd >/dev/null 2>&1; then
            # 注意：ldd 可能不适用于交叉编译的二进制文件，但我们可以尝试
            ldd "$binary" 2>/dev/null | grep -E "lib(ssl|crypto|boost|curl|archive|sodium|sqlite3)" | while read line; do
                lib_path=$(echo "$line" | awk '{print $3}')
                if [ -n "$lib_path" ] && [ -f "$lib_path" ]; then
                    lib_name=$(basename "$lib_path")
                    if [ ! -f "$PACKAGE_DIR/lib/$lib_name" ]; then
                        echo "    Copying dependency: $lib_name"
                        cp "$lib_path" "$PACKAGE_DIR/lib/"
                    fi
                fi
            done
        fi
    fi
done

# 手动复制已知的依赖库
echo "Copying known dependency libraries from sysroot..."
DEPENDENCY_LIBS=(
    "libssl.so.1.1"
    "libcrypto.so.1.1"
    "libboost_system.so.1.78.0"
    "libboost_filesystem.so.1.78.0"
    "libboost_log.so.1.78.0"
    "libboost_log_setup.so.1.78.0"
    "libboost_program_options.so.1.78.0"
    "libcurl.so.4"
    "libarchive.so.13"
    "libsodium.so.23"
    "libsqlite3.so.0"
    "libpthread.so.0"
    "libdl.so.2"
    "libm.so.6"
    "libc.so.6"
    "libgcc_s.so.1"
    "libstdc++.so.6"
)

for lib in "${DEPENDENCY_LIBS[@]}"; do
    # 查找库文件
    lib_path=$(find "$SYSROOT" -name "$lib" 2>/dev/null | head -1)
    if [ -n "$lib_path" ] && [ -f "$lib_path" ]; then
        echo "  Copying $lib"
        cp "$lib_path" "$PACKAGE_DIR/lib/"
    else
        echo "  Warning: $lib not found in sysroot"
    fi
done

# 创建符号链接
echo "Creating library symlinks..."
cd "$PACKAGE_DIR/lib"
for lib in *.so.*; do
    if [ -f "$lib" ]; then
        base_name=$(echo "$lib" | sed 's/\.[0-9].*$//')
        if [ ! -f "$base_name" ]; then
            ln -sf "$lib" "$base_name"
        fi
    fi
done
cd - >/dev/null

# 创建 appdata 目录内容
echo "Creating appdata directory..."
cat > "$PACKAGE_DIR/appdata/README.txt" << EOF
aktualizr Package for TI Processor SDK
=====================================

BSP Version: $BSP_VERSION
Build Date: $(date)
SDK Directory: $SDK_INSTALL_DIR

Contents:
- bin/: Executable files
- lib/: Library files and dependencies
- run.sh: Runtime script with library path configuration

Usage:
1. Extract this package to your target system
2. Run ./run.sh to execute aktualizr with proper library paths
3. Or manually set LD_LIBRARY_PATH to point to the lib/ directory

Dependencies:
- OpenSSL 1.1.1f
- Boost 1.78.0
- libsodium 1.0.20
- libcurl, libarchive, sqlite3
EOF

# 创建运行脚本
echo "Creating run.sh script..."
cat > "$PACKAGE_DIR/run.sh" << 'EOF'
#!/bin/bash

# aktualizr Runtime Script
# This script sets up the library path and runs aktualizr

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
BIN_DIR="$SCRIPT_DIR/bin"

# Set library path
export LD_LIBRARY_PATH="$LIB_DIR:$LD_LIBRARY_PATH"

# Function to show usage
show_usage() {
    echo "aktualizr Runtime Script"
    echo "Usage: $0 <command> [arguments...]"
    echo ""
    echo "Available commands:"
    echo "  aktualizr              - Main aktualizr daemon"
    echo "  aktualizr-secondary    - Secondary aktualizr"
    echo "  aktualizr-info         - Show aktualizr information"
    echo "  aktualizr-get          - Get aktualizr data"
    echo "  aktualizr-cert-provider - Certificate provider"
    echo "  uptane-generator       - Uptane metadata generator"
    echo ""
    echo "Examples:"
    echo "  $0 aktualizr --help"
    echo "  $0 aktualizr-info"
    echo "  $0 uptane-generator --help"
}

# Check if command is provided
if [ $# -eq 0 ]; then
    show_usage
    exit 1
fi

COMMAND="$1"
shift

# Check if the command exists
if [ ! -f "$BIN_DIR/$COMMAND" ]; then
    echo "Error: Command '$COMMAND' not found in $BIN_DIR"
    echo "Available commands:"
    ls -1 "$BIN_DIR" 2>/dev/null | sed 's/^/  /'
    exit 1
fi

# Run the command
echo "Running $COMMAND with library path: $LIB_DIR"
exec "$BIN_DIR/$COMMAND" "$@"
EOF

chmod +x "$PACKAGE_DIR/run.sh"

# 创建安装脚本
echo "Creating install script..."
cat > "$PACKAGE_DIR/install.sh" << 'EOF'
#!/bin/bash

# aktualizr Installation Script

INSTALL_PREFIX="/opt/aktualizr"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing aktualizr to $INSTALL_PREFIX..."

# Create installation directory
sudo mkdir -p "$INSTALL_PREFIX"

# Copy files
sudo cp -r "$SCRIPT_DIR"/* "$INSTALL_PREFIX/"

# Set permissions
sudo chmod +x "$INSTALL_PREFIX/run.sh"
sudo chmod +x "$INSTALL_PREFIX/bin"/*

# Create systemd service (optional)
if command -v systemctl >/dev/null 2>&1; then
    echo "Creating systemd service..."
    sudo tee /etc/systemd/system/aktualizr.service > /dev/null << SERVICEEOF
[Unit]
Description=aktualizr OTA Client
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_PREFIX/run.sh aktualizr
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
SERVICEEOF

    sudo systemctl daemon-reload
    echo "Service created. Use 'sudo systemctl enable aktualizr' to enable it."
fi

echo "Installation completed!"
echo "aktualizr installed to: $INSTALL_PREFIX"
echo "Run with: $INSTALL_PREFIX/run.sh <command>"
EOF

chmod +x "$PACKAGE_DIR/install.sh"

# 创建压缩包
echo "Creating package archive..."
tar -czf "$PACKAGE_ARCHIVE" -C "$PWD" "$PACKAGE_NAME"

# 显示结果
echo ""
echo "=========================================="
echo "Package created successfully!"
echo "Package directory: $PACKAGE_DIR"
echo "Package archive: $PACKAGE_ARCHIVE"
echo "=========================================="
echo ""
echo "Package contents:"
echo "  bin/ - $(ls -1 "$PACKAGE_DIR/bin" | wc -l) executable files"
echo "  lib/ - $(ls -1 "$PACKAGE_DIR/lib" | wc -l) library files"
echo "  appdata/ - Documentation and metadata"
echo "  run.sh - Runtime script"
echo "  install.sh - Installation script"
echo ""
echo "To use the package:"
echo "  1. Extract: tar -xzf $PACKAGE_ARCHIVE"
echo "  2. Run: cd $PACKAGE_NAME && ./run.sh <command>"
echo "  3. Or install: sudo ./install.sh"
echo ""

exit 0
