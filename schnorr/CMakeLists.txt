cmake_minimum_required(VERSION 3.23)
project(A2L_SCHNORR C)

set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-macro-redefined")
if(APPLE)
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3")
else()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3 -Wno-clobbered")
endif()

# add extra include directories
set(INCLUDE /usr/local/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/include)
include_directories(${INCLUDE})

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(SIMUL "$ENV{SIMUL}" CACHE STRING "Path to call a simulator of the target platform.")
set(SIMAR "$ENV{SIMAR}" CACHE STRING "Arguments to call a simulator of the target platform.")
string(REPLACE " " ";" SIMAR "${SIMAR}")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)
file(GLOB includes "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")