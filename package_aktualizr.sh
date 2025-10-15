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
mkdir -p "$PACKAGE_DIR"/{bin,lib,appdata,config}

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

# 获取所有 boost 库
echo "  Collecting all boost libraries..."
BOOST_LIBS=$(find "$SYSROOT" -name "libboost_*.so*" 2>/dev/null)
for boost_lib in $BOOST_LIBS; do
    if [ -f "$boost_lib" ]; then
        lib_name=$(basename "$boost_lib")
        echo "    Copying boost library: $lib_name"
        cp "$boost_lib" "$PACKAGE_DIR/lib/"
    fi
done

# 其他依赖库
DEPENDENCY_LIBS=(
    "libssl.so.1.1"
    "libcrypto.so.1.1"
    "libcurl.so.4"
    "libarchive.so.13"
    "libsodium.so.26"
    "libsodium.so.26.2.0"
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

# 复制配置文件
echo "Copying configuration files..."
if [ -f "examples/secondary.toml" ]; then
    echo "  Copying secondary.toml configuration"
    cp "examples/secondary.toml" "$PACKAGE_DIR/config/"
else
    echo "  Warning: examples/secondary.toml not found, creating default configuration"
    cat > "$PACKAGE_DIR/config/secondary.toml" << 'CONFIGEOF'
[logger]
loglevel = 1

[network]
port = 9032
primary_ip = "172.20.15.30"
primary_port = 9020

[uptane]
"ecu_hardware_id" = "cdc-tda4"
"key_source" = "file"
"key_type" = "RSA2048"
"force_install_completion" = true

[pacman]
type = "none"
images_path = "/mnt/autox_app/fota/images"
packages_file = "/mnt/autox_app/fota/package/manifest"

[storage]
path = "/mnt/autox_app/fota/storage"
CONFIGEOF
fi

# 创建部署要求文档
echo "Creating deployment requirements document..."
cat > "$PACKAGE_DIR/appdata/DEPLOYMENT_REQUIREMENTS.md" << 'DEPLOYEOF'
# aktualizr Secondary ECU Deployment Requirements

## Prerequisites

### 1. Directory Structure
Create the following directories on your target system:

```bash
sudo mkdir -p /mnt/autox_app/fota/images
sudo mkdir -p /mnt/autox_app/fota/package/manifest
sudo mkdir -p /mnt/autox_app/fota/storage
```

### 2. Permissions
Set appropriate permissions for the directories:

```bash
# Set ownership (replace 'username' with actual user)
sudo chown -R username:username /mnt/autox_app/fota/

# Set permissions
sudo chmod -R 755 /mnt/autox_app/fota/
sudo chmod 644 /mnt/autox_app/fota/package/manifest  # if file exists
```

### 3. Network Configuration
Ensure network connectivity between Primary and Secondary ECUs:

- **Primary ECU**: Must be accessible on the IP and port specified in secondary.toml
- **Secondary ECU**: Must be able to bind to the port specified in secondary.toml
- **Firewall**: Configure firewall rules to allow communication on specified ports

## Configuration

### 1. Update secondary.toml
Edit `config/secondary.toml` with your specific settings:

```toml
[network]
port = 9032                    # Port for Secondary to listen on
primary_ip = "172.20.15.30"    # IP address of Primary ECU
primary_port = 9020            # Port of Primary ECU

[uptane]
"ecu_hardware_id" = "cdc-tda4" # Hardware ID (must match your hardware)

[pacman]
type = "none"
images_path = "/mnt/autox_app/fota/images"
packages_file = "/mnt/autox_app/fota/package/manifest"

[storage]
path = "/mnt/autox_app/fota/storage"
```

### 2. Primary ECU Configuration
Ensure your Primary ECU is configured to communicate with this Secondary:

- Primary must have the Secondary's IP and port in its configuration
- Primary must be configured to listen on the port specified in secondary.toml

## Deployment Steps

### 1. Extract Package
```bash
tar -xzf aktualizr-0806-*.tar.gz
cd aktualizr-package
```

### 2. Install (Optional)
```bash
sudo ./install.sh
```

### 3. Run Secondary
```bash
# Using run script
./run.sh aktualizr-secondary -c config/secondary.toml

# Or directly
export LD_LIBRARY_PATH=./lib:$LD_LIBRARY_PATH
./bin/aktualizr-secondary -c config/secondary.toml
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Check directory permissions
   - Ensure user has write access to storage directory

2. **Network Connection Failed**
   - Verify IP addresses and ports in configuration
   - Test network connectivity: `ping <primary_ip>`
   - Check firewall settings

3. **Library Loading Errors**
   - Ensure LD_LIBRARY_PATH includes ./lib directory
   - Use the provided run.sh script

4. **Configuration Errors**
   - Validate TOML syntax
   - Check file paths exist and are accessible

### Logging
Enable verbose logging by setting loglevel to 0 in secondary.toml:

```toml
[logger]
loglevel = 0
```

## Security Considerations

1. **File Permissions**: Restrict access to configuration and storage directories
2. **Network Security**: Use secure communication channels in production
3. **Key Management**: Ensure proper key file permissions and storage
4. **Firewall**: Configure appropriate firewall rules for ECU communication

## Support

For additional support, refer to:
- aktualizr documentation
- TI Processor SDK documentation
- Uptane specification
DEPLOYEOF

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
- config/: Configuration files
- run.sh: Runtime script with library path configuration
- install.sh: Installation script

Usage:
1. Extract this package to your target system
2. Run ./run.sh to execute aktualizr with proper library paths
3. Or manually set LD_LIBRARY_PATH to point to the lib/ directory

Deployment Requirements:
1. Create required directories on target system:
   - /mnt/autox_app/fota/images (for firmware images)
   - /mnt/autox_app/fota/package/manifest (for package manifest)
   - /mnt/autox_app/fota/storage (for aktualizr storage)
   
2. Set proper permissions:
   - All directories must have write permissions for the user running aktualizr
   - Recommended: chmod 755 for directories, chmod 644 for files

3. Configure secondary.toml:
   - Update [network] section with correct IP addresses and ports
   - Ensure primary_ip and primary_port match your Primary ECU configuration
   - Verify ecu_hardware_id matches your hardware

4. Network Configuration:
   - Ensure Primary and Secondary ECUs can communicate on specified ports
   - Configure firewall rules if necessary
   - Test network connectivity between ECUs

Dependencies:
- OpenSSL 1.1.1f
- Boost 1.78.0 (all boost libraries included)
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
    echo "  $0 aktualizr-secondary -c config/secondary.toml"
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
echo "  config/ - Configuration files (secondary.toml)"
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
