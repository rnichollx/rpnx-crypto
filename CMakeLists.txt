cmake_minimum_required(VERSION 3.15)

project(rpnx-crypto)

add_library(rpnx-crypto)

target_sources(rpnx-crypto PRIVATE sources/empty.cpp headers/rpnx/hsalsa.hpp headers/rpnx/xsalsa.hpp headers/rpnx/salsa.hpp)
target_include_directories(rpnx-crypto PUBLIC headers)
set_target_properties(rpnx-crypto PROPERTIES CXX_STANDARD 17)

add_executable(test sources/test.cpp)
target_link_libraries(test rpnx-crypto)
target_link_libraries(test -lsodium)
set_target_properties(test PROPERTIES CXX_STANDARD 17)

if ("${CMAKE_COMPILER_ID}" STREQUAL "GCC")
  target_compile_options(test PRIVATE "-Wall" "-Wextra")
endif()