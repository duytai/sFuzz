################################
# GTest
################################
ADD_SUBDIRECTORY (googletest)
enable_testing()
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

################################
# Unit Tests
################################
# Add test cpp file
file(GLOB sources "*.cpp")
add_executable(testfuzzer ${sources})
# Link test executable against gtest & gtest_main
target_link_libraries(testfuzzer gtest gtest_main libfuzzer liboracle)
add_test(testfuzze testfuzzer)
