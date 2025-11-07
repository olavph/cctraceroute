project(cctraceroute_tests)

include(GoogleTest)
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(cctraceroute_tests test_cctraceroute.cpp)
target_link_libraries(cctraceroute_tests GTest::gtest GTest::gtest_main cctraceroute_lib)

gtest_discover_tests(cctraceroute_tests)
