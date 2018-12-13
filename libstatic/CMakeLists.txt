file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

include_directories(${Boost_INCLUDE_DIRS})
add_library(libstatic ${sources} ${headers})
target_link_libraries(libstatic ${Boost_LIBRARIES} ethereum evm devcore)
