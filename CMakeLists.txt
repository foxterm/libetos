cmake_minimum_required(VERSION 3.15)
project(libetos VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

file(GLOB SOURCES "Sources/libetos/*.c")
file(GLOB HEADERS "Sources/libetos/include/*.h")

add_library(libetos STATIC ${SOURCES}${HEADERS})

target_include_directories(libetos PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/Sources/libetos/include>$<INSTALL_INTERFACE:include>
)

find_package(Threads REQUIRED)
target_link_libraries(libetos PRIVATE Threads::Threads)

if(WIN32)
    target_link_libraries(libetos PRIVATE ws2_32 iphlpapi)
endif()

add_custom_command(
    TARGET libetos POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/Sources/libetos/include${CMAKE_BINARY_DIR}/include
    COMMENT "Copying include files to build/include"
)
