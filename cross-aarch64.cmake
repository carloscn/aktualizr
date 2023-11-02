#
# CMake Toolchain file for crosscompiling on ARM.
#
# Target operating system name.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_CROSSCOMPILING TRUE)

# Name of C compiler.
set(CMAKE_C_COMPILER $ENV{CROSS_COMPILE_PATH}/bin/aarch64-none-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER $ENV{CROSS_COMPILE_PATH}/bin/aarch64-none-linux-gnu-g++)

# Where to look for the target environment. (More paths can be added here)
set(CMAKE_FIND_ROOT_PATH $ENV{CROSS_COMPILE_PATH}/bin/../aarch64-none-linux-gnu/libc)
set(CMAKE_INCLUDE_PATH $ENV{CROSS_COMPILE_PATH}/bin/../aarch64-none-linux-gnu/libc/include)
set(CMAKE_LIBRARY_PATH $ENV{CROSS_COMPILE_PATH}/bin/../aarch64-none-linux-gnu/libc/lib)
set(CMAKE_PROGRAM_PATH $ENV{CROSS_COMPILE_PATH}/bin/../aarch64-none-linux-gnu/libc/sbin)

# Adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search headers and libraries in the target environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)