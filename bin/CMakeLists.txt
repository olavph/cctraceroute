project(cctraceroute_bin)

add_executable(cctraceroute cctraceroute.cpp)
target_link_libraries(cctraceroute cxxopts::cxxopts cctraceroute_lib)
