cmake_minimum_required(VERSION 3.16)
project(cctraceroute)

# Compiler options
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Werror -Wextra -Wpedantic)

include_directories(lib)

enable_testing()

add_subdirectory(lib)
add_subdirectory(test)
add_subdirectory(bin)
