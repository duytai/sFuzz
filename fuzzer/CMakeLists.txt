file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

add_executable(fuzzer ${sources} ${headers})

target_link_libraries(fuzzer PRIVATE libfuzzer ethereum evm ethashseal devcore Boost::program_options)

target_include_directories(fuzzer PRIVATE ../utils)

install(TARGETS fuzzer EXPORT alethTargets DESTINATION bin)
