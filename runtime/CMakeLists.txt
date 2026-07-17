cmake_minimum_required(VERSION 3.20)
project(runtime_guard LANGUAGES CXX)

add_library(runtime_guard STATIC guard.cpp)
target_include_directories(runtime_guard PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(runtime_guard PUBLIC cxx_std_20)

add_executable(runtime_demo demo.cpp)
target_link_libraries(runtime_demo PRIVATE runtime_guard)

enable_testing()
add_test(NAME runtime_demo COMMAND runtime_demo)
