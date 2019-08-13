file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

include_directories(${Boost_INCLUDE_DIRS})
add_library(libfuzzer ${sources} ${headers})
target_link_libraries(libfuzzer ${Boost_LIBRARIES} ethereum evm ethashseal devcore liboracle)
