cmake_minimum_required(VERSION 2.8.4)
project(test)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

set(SDK_DIR "/home/cryptoknight/dev/sdk-1.5.2-281118_1/sdk")

#target_include_directories(test PRIVATE ${SDK_DIR})

file(GLOB_RECURSE SDK_HEADERS "${SDK_DIR}/*.h")
file(GLOB_RECURSE SDK_SRCS "${SDK_DIR}/*.c")

file(GLOB_RECURSE SRCS "*.h")
file(GLOB_RECURSE HEADERS "*.h")

add_executable(test ${SDK_SRCS} ${SDK_HEADERS} )
