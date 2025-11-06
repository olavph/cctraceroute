cmake_minimum_required(VERSION 3.16)
project(cctraceroute)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Werror -Wextra -Wpedantic)

find_package(cxxopts REQUIRED)
find_package(GTest REQUIRED)

include_directories(src)

add_executable(cctraceroute cctraceroute.cpp)
target_link_libraries(cctraceroute cxxopts::cxxopts)

enable_testing()

add_executable(cctraceroute_tests test/test_cctraceroute.cpp)
target_link_libraries(cctraceroute_tests GTest::gtest GTest::gtest_main)
add_test(NAME TracerouteTests COMMAND cctraceroute_tests)
