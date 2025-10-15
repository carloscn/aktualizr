# aktualizr 一键构建指南

## 概述

本指南提供了 aktualizr 项目的完整构建流程，从依赖库编译到最终打包的自动化脚本。

## 快速开始

### 一键构建（推荐）

```bash
# 使用默认设置构建（BSP 0806）
./build_all.sh

# 清理并重新构建
./build_all.sh -c

# 构建 BSP 0902 版本
./build_all.sh -b 0902

# 清理并构建 BSP 0902 版本
./build_all.sh -c -b 0902
```

### 分步构建

如果需要分步执行，可以按以下顺序运行：

```bash
# 1. 初始化 git 子模块
git submodule update --init --recursive

# 2. 构建依赖库
./build_boost.sh      # 构建 Boost 1.78.0
./build_openssl.sh    # 构建 OpenSSL 1.1.1f
./build_sodium.sh     # 构建 libsodium 1.0.20

# 3. 构建 aktualizr
./cross_build.sh

# 4. 打包
./package_aktualizr.sh
```

## 脚本说明

### 主要脚本

| 脚本 | 功能 | 说明 |
|------|------|------|
| `build_all.sh` | 一键构建 | 自动化完整构建流程 |
| `build_boost.sh` | 构建 Boost | 交叉编译 Boost 1.78.0 |
| `build_openssl.sh` | 构建 OpenSSL | 交叉编译 OpenSSL 1.1.1f |
| `build_sodium.sh` | 构建 libsodium | 交叉编译 libsodium 1.0.20 |
| `cross_build.sh` | 构建 aktualizr | 交叉编译 aktualizr 主程序 |
| `package_aktualizr.sh` | 打包 | 创建部署包 |

### 配置文件

| 文件 | 功能 | 说明 |
|------|------|------|
| `toolchain.cmake` | CMake 工具链 | 交叉编译配置 |
| `BUILD_GUIDE.md` | 构建指南 | 本文档 |

## BSP 版本支持

### 0806 BSP
- **SDK 路径**: `$HOME/opt/ti-processor-sdk-linux-j7-evm-08_06_01_02`
- **工具链**: `aarch64-none-linux-gnu-*`
- **Sysroot**: `aarch64-linux`

### 0902 BSP
- **SDK 路径**: `$HOME/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05`
- **工具链**: `aarch64-oe-linux-*`
- **Sysroot**: `aarch64-oe-linux`

## 构建产物

### 构建目录结构
```
build/
├── src/
│   ├── aktualizr_primary/aktualizr
│   ├── aktualizr_secondary/aktualizr-secondary
│   ├── aktualizr_info/aktualizr-info
│   ├── aktualizr_get/aktualizr-get
│   ├── cert_provider/aktualizr-cert-provider
│   ├── uptane_generator/uptane-generator
│   └── libaktualizr*/lib*.so
└── ...
```

### 部署包结构
```
aktualizr-package/
├── bin/                    # 可执行文件
│   ├── aktualizr
│   ├── aktualizr-secondary
│   ├── aktualizr-info
│   ├── aktualizr-get
│   ├── aktualizr-cert-provider
│   └── uptane-generator
├── lib/                    # 库文件和依赖
│   ├── libaktualizr.so
│   ├── libssl.so.1.1
│   ├── libcrypto.so.1.1
│   └── ... (其他依赖库)
├── appdata/               # 文档和元数据
│   └── README.txt
├── run.sh                 # 运行时脚本
└── install.sh             # 安装脚本
```

## 使用方法

### 1. 解压部署包
```bash
tar -xzf aktualizr-0806-20251015_091620.tar.gz
cd aktualizr-package
```

### 2. 运行程序
```bash
# 显示帮助
./run.sh

# 运行主程序
./run.sh aktualizr --help

# 显示信息
./run.sh aktualizr-info

# 生成 Uptane 元数据
./run.sh uptane-generator --help
```

### 3. 安装到系统
```bash
sudo ./install.sh
```

## 故障排除

### 常见问题

1. **SDK 路径错误**
   - 检查 TI Processor SDK 是否正确安装
   - 确认 SDK 路径在脚本中配置正确

2. **工具链找不到**
   - 检查交叉编译工具链是否在 SDK 中
   - 确认 BSP 版本配置正确

3. **依赖库缺失**
   - 运行 `build_boost.sh`、`build_openssl.sh`、`build_sodium.sh`
   - 检查 sysroot 中的库文件

4. **构建失败**
   - 查看 `build_all.log` 和 `build_all_errors.log`
   - 检查网络连接（下载依赖时）
   - 确认磁盘空间充足

### 日志文件

- `build_all.log` - 完整构建日志
- `build_all_errors.log` - 错误日志
- 各脚本的输出信息

## 环境要求

### 系统要求
- Linux 系统（推荐 Ubuntu 20.04+）
- 至少 4GB 可用内存
- 至少 10GB 可用磁盘空间

### 必需工具
- git
- make
- cmake
- curl 或 wget
- tar
- 交叉编译工具链（来自 TI SDK）

### 依赖库
- OpenSSL 1.1.1f
- Boost 1.78.0
- libsodium 1.0.20
- libcurl, libarchive, sqlite3

## 更新和维护

### 更新 BSP 版本
```bash
# 修改脚本中的 BSP_VERSION 变量
# 或使用命令行参数
./build_all.sh -b 0902
```

### 清理构建
```bash
# 清理所有构建产物
./build_all.sh -c

# 手动清理
rm -rf build/ aktualizr-package/ aktualizr-*.tar.gz
```

## 支持

如有问题，请检查：
1. 构建日志文件
2. 环境配置
3. SDK 安装
4. 网络连接

---

**构建完成后的包可以直接部署到目标 ARM64 设备上运行！**
