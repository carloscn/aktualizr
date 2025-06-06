# toolchain.cmake

# 设置目标系统
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# 设置 SDK 安装路径，使用 $ENV{HOME} 获取家目录
set(SDK_INSTALL_DIR $ENV{HOME}/opt/ti-processor-sdk-linux-edgeai-j721e-evm-09_02_00_05)

# 指定交叉编译器
set(CMAKE_C_COMPILER ${SDK_INSTALL_DIR}/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-oe-linux/aarch64-oe-linux-gcc)
set(CMAKE_CXX_COMPILER ${SDK_INSTALL_DIR}/linux-devkit/sysroots/x86_64-arago-linux/usr/bin/aarch64-oe-linux/aarch64-oe-linux-g++)

# 设置 sysroot
set(CMAKE_SYSROOT ${SDK_INSTALL_DIR}/linux-devkit/sysroots/aarch64-oe-linux)

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