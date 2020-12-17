cmake_minimum_required(VERSION 3.15)

project(rpnx-djb-crypto)

add_library(rpnx-djb-crypto)

target_sources(rpnx-djb-crypto PRIVATE sources/empty.cpp headers/rpnx/hsalsa.hpp headers/rpnx/xsalsa.hpp headers/rpnx/salsa.hpp)
target_include_directories(rpnx-djb-crypto PUBLIC headers)
set_target_properties(rpnx-djb-crypto PROPERTIES CXX_STANDARD 17)

add_executable(test sources/test.cpp)
target_link_libraries(test rpnx-djb-crypto)
target_link_libraries(test -lsodium)
set_target_properties(test PROPERTIES CXX_STANDARD 17)

target_compile_options(test PRIVATE "-Wall" "-Wextra")