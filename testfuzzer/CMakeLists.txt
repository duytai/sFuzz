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
add_executable( testfuzzer testgtest.cpp )
# Link test executable against gtest & gtest_main
target_link_libraries(testfuzzer gtest gtest_main libfuzzer)
add_test(testfuzze testfuzzer)
