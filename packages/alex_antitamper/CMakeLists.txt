cmake_minimum_required(VERSION 3.20)

project(alex_antitamper LANGUAGES CXX)

if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64" AND EXISTS "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3" CACHE PATH "Native OpenSSL prefix" FORCE)
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(alex_antitamper STATIC
    src/antitamper.cpp
    src/owner_protection.cpp
    src/signed_integrity.cpp
)

add_library(alex_antitamper::alex_antitamper ALIAS alex_antitamper)

add_library(alex_antitamper_header_only INTERFACE)
add_library(alex_antitamper::header_only ALIAS alex_antitamper_header_only)

target_include_directories(alex_antitamper_header_only
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/single_include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(alex_antitamper PUBLIC cxx_std_20)
target_link_libraries(alex_antitamper PUBLIC OpenSSL::Crypto)
target_compile_features(alex_antitamper_header_only INTERFACE cxx_std_20)

target_include_directories(alex_antitamper
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(ALEX_ANTITAMPER_BUILD_EXAMPLE)
    add_executable(alex_antitamper_basic examples/basic.cpp)
    target_link_libraries(alex_antitamper_basic PRIVATE alex_antitamper::alex_antitamper)

    add_executable(alex_file_guard examples/easy_file_guard.cpp)
    target_link_libraries(alex_file_guard PRIVATE alex_antitamper::header_only)
endif()

if(BUILD_TESTING)
    add_executable(alex_signed_integrity_test tests/signed_integrity_test.cpp)
    target_link_libraries(alex_signed_integrity_test PRIVATE alex_antitamper::alex_antitamper)
    add_test(NAME alex_signed_integrity_unit COMMAND alex_signed_integrity_test)
    set_tests_properties(alex_signed_integrity_unit PROPERTIES LABELS "unit;security;antitamper" TIMEOUT 30)
endif()
