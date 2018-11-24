file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

add_executable(fuzzer ${sources} ${headers})
target_link_libraries(fuzzer PRIVATE libfuzzer Boost::program_options)
