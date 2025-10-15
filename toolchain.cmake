# toolchain.cmake

# 设置目标系统
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# BSP 版本配置 - 设置为 "0806" 或 "0902" 来切换 BSP 版本
set(BSP_VERSION "0806")

# 根据 BSP 版本设置 SDK 安装路径
if(BSP_VERSION STREQUAL "0806")
    set(SDK_INSTALL_DIR $ENV{HOME}/opt/ti-processor-sdk-linux-j7-evm-08_06_01_02)
elseif(BSP_VERSION STREQUAL "0902")
    set(SDK_INSTALL_DIR $ENV{HOME}/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05)
else()
    message(FATAL_ERROR "Invalid BSP_VERSION: ${BSP_VERSION}. Please set to '0806' or '0902'")
endif()

# 根据 BSP 版本设置交叉编译器和 sysroot
if(BSP_VERSION STREQUAL "0806")
    # 0806 BSP 使用 aarch64-none-linux-gnu 工具链
    set(CMAKE_C_COMPILER ${SDK_INSTALL_DIR}/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-none-linux-gnu-gcc)
    set(CMAKE_CXX_COMPILER ${SDK_INSTALL_DIR}/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-none-linux-gnu-g++)
    set(CMAKE_SYSROOT ${SDK_INSTALL_DIR}/linux-devkit/sysroots/aarch64-linux)
elseif(BSP_VERSION STREQUAL "0902")
    # 0902 BSP 使用 aarch64-oe-linux 工具链
    set(CMAKE_C_COMPILER ${SDK_INSTALL_DIR}/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-oe-linux/aarch64-oe-linux-gcc)
    set(CMAKE_CXX_COMPILER ${SDK_INSTALL_DIR}/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-oe-linux/aarch64-oe-linux-g++)
    set(CMAKE_SYSROOT ${SDK_INSTALL_DIR}/linux-devkit/sysroots/aarch64-oe-linux)
endif()

# 确保 CMake 在 sysroot 中查找库和头文件
set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# 配置 pkg-config 以使用 sysroot
set(ENV{PKG_CONFIG_PATH} "${CMAKE_SYSROOT}/usr/lib/pkgconfig:${CMAKE_SYSROOT}/usr/share/pkgconfig")
set(ENV{PKG_CONFIG_LIBDIR} "${CMAKE_SYSROOT}/usr/lib/pkgconfig:${CMAKE_SYSROOT}/usr/share/pkgconfig")
set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CMAKE_SYSROOT})