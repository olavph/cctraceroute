cmake_minimum_required(VERSION 3.16)
project(cctraceroute)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(cxxopts REQUIRED)

add_executable(cctraceroute cctraceroute.cpp)
target_link_libraries(cctraceroute cxxopts::cxxopts)
