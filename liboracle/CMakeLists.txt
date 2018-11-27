file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

include_directories(${Boost_INCLUDE_DIRS})
add_library(liboracle ${sources} ${headers})
target_link_libraries(liboracle ${Boost_LIBRARIES} ethereum evm devcore)
