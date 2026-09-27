cmake_minimum_required(VERSION 3.15)
project(libetos VERSION 0.1.0 LANGUAGES C)


set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)


file(GLOB SOURCES "Sources/libetos/*.c")

add_library(libetos STATIC ${SOURCES})


target_include_directories(libetos PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/Sources/libetos/include>
    $<INSTALL_INTERFACE:include>
)
