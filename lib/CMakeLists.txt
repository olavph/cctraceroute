project(cctraceroute_lib)

include(FetchContent)
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.3.1
)
FetchContent_MakeAvailable(cxxopts)

add_library(cctraceroute_lib INTERFACE)
target_include_directories(cctraceroute_lib INTERFACE .)
