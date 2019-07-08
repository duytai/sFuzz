file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

include_directories(${Boost_INCLUDE_DIRS})
add_library(libfuzzer ${sources} ${headers} TargetExecutive.cpp TargetExecutive.h TargetContainerResult.cpp TargetContainerResult.h)
target_link_libraries(libfuzzer ${Boost_LIBRARIES} ethereum evm ethashseal devcore liboracle)
