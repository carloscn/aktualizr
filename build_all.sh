#!/bin/bash

# BSP 版本配置 - 设置为 "0806" 或 "0902" 来切换 BSP 版本
BSP_VERSION="0806"

# 脚本配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/build_all.log"
ERROR_LOG="$SCRIPT_DIR/build_all_errors.log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" | tee -a "$ERROR_LOG"
}

# 错误处理函数
handle_error() {
    local exit_code=$?
    local line_number=$1
    log_error "Command failed at line $line_number with exit code $exit_code"
    log_error "Check $ERROR_LOG for details"
    exit $exit_code
}

# 设置错误陷阱
trap 'handle_error $LINENO' ERR

# 检查命令是否存在
check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Command '$1' not found. Please install it first."
        exit 1
    fi
}

# 运行脚本并检查结果
run_script() {
    local script_name="$1"
    local script_path="$SCRIPT_DIR/$script_name"
    local description="$2"
    
    log_info "Running $description..."
    
    if [ ! -f "$script_path" ]; then
        log_error "Script $script_name not found at $script_path"
        exit 1
    fi
    
    if [ ! -x "$script_path" ]; then
        log_warning "Making $script_name executable..."
        chmod +x "$script_path"
    fi
    
    log_info "Executing: $script_path"
    if "$script_path" 2>&1 | tee -a "$LOG_FILE"; then
        log_success "$description completed successfully"
    else
        log_error "$description failed"
        exit 1
    fi
}

# 显示横幅
show_banner() {
    echo "=================================================="
    echo "    aktualizr One-Click Build Script"
    echo "=================================================="
    echo "BSP Version: $BSP_VERSION"
    echo "Build Date: $(date)"
    echo "Working Directory: $SCRIPT_DIR"
    echo "Log File: $LOG_FILE"
    echo "Error Log: $ERROR_LOG"
    echo "=================================================="
    echo ""
}

# 检查环境
check_environment() {
    log_info "Checking build environment..."
    
    # 检查必要的命令
    check_command "git"
    check_command "make"
    check_command "cmake"
    check_command "curl"
    check_command "tar"
    
    # 检查 BSP 版本配置
    if [ "$BSP_VERSION" != "0806" ] && [ "$BSP_VERSION" != "0902" ]; then
        log_error "Invalid BSP_VERSION: $BSP_VERSION. Please set to '0806' or '0902'"
        exit 1
    fi
    
    # 检查 SDK 目录
    if [ "$BSP_VERSION" = "0806" ]; then
        SDK_DIR="$HOME/opt/ti-processor-sdk-linux-j7-evm-08_06_01_02"
    else
        SDK_DIR="$HOME/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05"
    fi
    
    if [ ! -d "$SDK_DIR" ]; then
        log_error "SDK directory not found: $SDK_DIR"
        log_error "Please ensure the TI Processor SDK is installed"
        exit 1
    fi
    
    log_success "Environment check passed"
}

# 初始化日志
init_logs() {
    log_info "Initializing build logs..."
    echo "aktualizr Build Log - $(date)" > "$LOG_FILE"
    echo "aktualizr Error Log - $(date)" > "$ERROR_LOG"
    log_success "Logs initialized"
}

# 更新 BSP 版本配置
update_bsp_config() {
    log_info "Updating BSP version configuration to $BSP_VERSION..."
    
    # 更新所有脚本中的 BSP 版本
    local scripts=("build_boost.sh" "build_openssl.sh" "build_sodium.sh" "cross_build.sh" "package_aktualizr.sh")
    
    for script in "${scripts[@]}"; do
        local script_path="$SCRIPT_DIR/$script"
        if [ -f "$script_path" ]; then
            # 使用 sed 更新 BSP_VERSION 行
            if grep -q "BSP_VERSION=" "$script_path"; then
                sed -i "s/BSP_VERSION=\"[^\"]*\"/BSP_VERSION=\"$BSP_VERSION\"/" "$script_path"
                log_info "Updated $script BSP_VERSION to $BSP_VERSION"
            fi
        else
            log_warning "Script $script not found, skipping BSP version update"
        fi
    done
    
    log_success "BSP version configuration updated"
}

# 清理之前的构建
cleanup_previous_build() {
    log_info "Cleaning up previous build artifacts..."
    
    # 清理构建目录
    if [ -d "$SCRIPT_DIR/build" ]; then
        log_info "Removing previous build directory..."
        rm -rf "$SCRIPT_DIR/build"
    fi
    
    # 清理包目录
    if [ -d "$SCRIPT_DIR/aktualizr-package" ]; then
        log_info "Removing previous package directory..."
        rm -rf "$SCRIPT_DIR/aktualizr-package"
    fi
    
    # 清理旧的包文件
    rm -f "$SCRIPT_DIR"/aktualizr-*.tar.gz
    
    log_success "Cleanup completed"
}

# 主构建流程
main_build() {
    log_info "Starting main build process..."
    
    # 步骤 1: 初始化 git 子模块
    log_info "Step 1/6: Initializing git submodules..."
    if git submodule status | grep -q "^-"; then
        log_info "Initializing and updating git submodules..."
        git submodule update --init --recursive 2>&1 | tee -a "$LOG_FILE"
        log_success "Git submodules initialized"
    else
        log_success "Git submodules already initialized"
    fi
    
    # 步骤 2: 构建依赖库
    log_info "Step 2/6: Building dependency libraries..."
    
    # 构建 OpenSSL
    run_script "build_openssl.sh" "OpenSSL library build"
    
    # 构建 libsodium
    run_script "build_sodium.sh" "libsodium library build"
    
    # 构建 Boost
    run_script "build_boost.sh" "Boost library build"
    
    # 步骤 3: 构建 aktualizr
    log_info "Step 3/6: Building aktualizr..."
    run_script "cross_build.sh" "aktualizr cross-compilation"
    
    # 步骤 4: 打包
    log_info "Step 4/6: Packaging aktualizr..."
    run_script "package_aktualizr.sh" "aktualizr packaging"
    
    # 步骤 5: 验证构建结果
    log_info "Step 5/6: Verifying build results..."
    
    # 检查构建产物
    local build_success=true
    
    if [ ! -d "$SCRIPT_DIR/build" ]; then
        log_error "Build directory not found"
        build_success=false
    fi
    
    if [ ! -d "$SCRIPT_DIR/aktualizr-package" ]; then
        log_error "Package directory not found"
        build_success=false
    fi
    
    # 检查包文件
    local package_files=("aktualizr-package/bin/aktualizr" "aktualizr-package/bin/aktualizr-secondary" "aktualizr-package/run.sh")
    for file in "${package_files[@]}"; do
        if [ ! -f "$SCRIPT_DIR/$file" ]; then
            log_error "Required file not found: $file"
            build_success=false
        fi
    done
    
    if [ "$build_success" = true ]; then
        log_success "Build verification passed"
    else
        log_error "Build verification failed"
        exit 1
    fi
    
    # 步骤 6: 显示结果
    log_info "Step 6/6: Build completed successfully!"
    
    # 显示包信息
    local package_archive=$(ls -t "$SCRIPT_DIR"/aktualizr-*.tar.gz 2>/dev/null | head -1)
    if [ -n "$package_archive" ]; then
        local package_size=$(du -h "$package_archive" | cut -f1)
        log_success "Package created: $(basename "$package_archive") ($package_size)"
    fi
    
    # 显示包内容统计
    if [ -d "$SCRIPT_DIR/aktualizr-package" ]; then
        local bin_count=$(ls -1 "$SCRIPT_DIR/aktualizr-package/bin" 2>/dev/null | wc -l)
        local lib_count=$(ls -1 "$SCRIPT_DIR/aktualizr-package/lib" 2>/dev/null | wc -l)
        log_info "Package contents: $bin_count binaries, $lib_count libraries"
    fi
}

# 显示使用帮助
show_help() {
    echo "aktualizr One-Click Build Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --version  Show version information"
    echo "  -c, --clean    Clean previous build artifacts before building"
    echo "  -b, --bsp      Set BSP version (0806 or 0902)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Build with default settings"
    echo "  $0 -c                 # Clean and build"
    echo "  $0 -b 0902            # Build for BSP 0902"
    echo "  $0 -c -b 0902         # Clean and build for BSP 0902"
    echo ""
    echo "Current Configuration:"
    echo "  BSP Version: $BSP_VERSION"
    echo "  Working Directory: $SCRIPT_DIR"
}

# 显示版本信息
show_version() {
    echo "aktualizr One-Click Build Script v1.0"
    echo "Build Date: $(date)"
    echo "BSP Version: $BSP_VERSION"
}

# 主函数
main() {
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -c|--clean)
                CLEAN_BUILD=true
                shift
                ;;
            -b|--bsp)
                BSP_VERSION="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 显示横幅
    show_banner
    
    # 初始化日志
    init_logs
    
    # 检查环境
    check_environment
    
    # 更新 BSP 配置
    update_bsp_config
    
    # 清理（如果指定）
    if [ "$CLEAN_BUILD" = true ]; then
        cleanup_previous_build
    fi
    
    # 执行主构建流程
    main_build
    
    # 显示最终结果
    echo ""
    echo "=================================================="
    echo "    Build Completed Successfully!"
    echo "=================================================="
    echo "BSP Version: $BSP_VERSION"
    echo "Build Date: $(date)"
    echo "Log File: $LOG_FILE"
    echo ""
    
    # 显示包文件
    local package_archive=$(ls -t "$SCRIPT_DIR"/aktualizr-*.tar.gz 2>/dev/null | head -1)
    if [ -n "$package_archive" ]; then
        echo "Package: $(basename "$package_archive")"
        echo "Size: $(du -h "$package_archive" | cut -f1)"
        echo ""
        echo "To use the package:"
        echo "  1. Extract: tar -xzf $(basename "$package_archive")"
        echo "  2. Run: cd aktualizr-package && ./run.sh <command>"
        echo "  3. Or install: sudo ./install.sh"
    fi
    
    echo "=================================================="
}

# 运行主函数
main "$@"
