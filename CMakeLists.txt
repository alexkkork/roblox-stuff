cmake_minimum_required(VERSION 3.20)

project(RobloxLuauRuntime LANGUAGES CXX C)

include(CTest)

set(RBX_RELEASE_729_LUAU_COMMIT "6e9b580e2e24643214caf0f4bbbb3db911ca30f3")
set(RBX_RELEASE_729_STUDIO_BUILD "0.729.0.7290838")
set(RBX_RELEASE_729_API_SHA256 "88de6ce88153b2c7d226d7c2d22752e6e04d266c28b36809d9d61bf8256cf6bd")
set(RBX_RELEASE_729_API_DUMP "${CMAKE_CURRENT_SOURCE_DIR}/data/roblox/release-729/Full-API-Dump.json")
set(RBX_RELEASE_729_ORACLE_PROBE "${CMAKE_CURRENT_SOURCE_DIR}/tests/roblox_oracle/probes/core.luau")
set(RBX_RELEASE_729_ORACLE_PROBE_SHA256 "dbd2d32751a3666858edff70b6831e6a939aac1121dc645740a933c56a0c6aa6")
set(RBX_RELEASE_729_ORACLE_FIXTURE "${CMAKE_CURRENT_SOURCE_DIR}/tests/roblox_oracle/fixtures/release-729/core.json")
set(RBX_RELEASE_729_ORACLE_FIXTURE_SHA256 "aeaba8290d1963f8dc746d7df725149dd66aa2a717f7956d967352c02dfd9047")
set(RBX_RELEASE_729_SUBJECT "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/luraph/subject_ea93959c47e6.luau")
set(RBX_RELEASE_729_SUBJECT_SHA256 "ea93959c47e6ada393fdf3d5ad884b6fd713aa5d76ac7259e84bd18464153e15")
set(RBX_RELEASE_729_LURAPH_PATH2D_SUBJECT "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/luraph/subject_1b642e9523c1.luau")
set(RBX_RELEASE_729_LURAPH_PATH2D_SUBJECT_SHA256 "1b642e9523c17bf0731bc9778294b159933d6786005929a1b576cea3bfd35f24")

function(rbx_verify_file_sha256 path expected label)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "${label} is missing: ${path}")
    endif()
    file(SHA256 "${path}" actual)
    if(NOT actual STREQUAL expected)
        message(FATAL_ERROR "${label} hash mismatch. Expected ${expected}, got ${actual}")
    endif()
endfunction()

rbx_verify_file_sha256("${RBX_RELEASE_729_API_DUMP}" "${RBX_RELEASE_729_API_SHA256}" "Release-729 API dump")
rbx_verify_file_sha256("${RBX_RELEASE_729_ORACLE_PROBE}" "${RBX_RELEASE_729_ORACLE_PROBE_SHA256}" "Release-729 Studio oracle probe")
rbx_verify_file_sha256("${RBX_RELEASE_729_ORACLE_FIXTURE}" "${RBX_RELEASE_729_ORACLE_FIXTURE_SHA256}" "Release-729 Studio oracle fixture")
rbx_verify_file_sha256("${RBX_RELEASE_729_SUBJECT}" "${RBX_RELEASE_729_SUBJECT_SHA256}" "Release-729 Luraph subject")
rbx_verify_file_sha256("${RBX_RELEASE_729_LURAPH_PATH2D_SUBJECT}" "${RBX_RELEASE_729_LURAPH_PATH2D_SUBJECT_SHA256}" "Release-729 Path2D Luraph subject")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

include(FetchContent)

set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)
set(LUAU_WERROR OFF CACHE BOOL "" FORCE)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/luau/CMakeLists.txt")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/luau/.git")
        find_package(Git REQUIRED)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/vendor/luau"
            RESULT_VARIABLE RBX_LUAU_REVISION_RESULT
            OUTPUT_VARIABLE RBX_LUAU_ACTUAL_COMMIT
            ERROR_VARIABLE RBX_LUAU_REVISION_ERROR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT RBX_LUAU_REVISION_RESULT EQUAL 0)
            message(FATAL_ERROR "Cannot verify vendored Luau revision: ${RBX_LUAU_REVISION_ERROR}")
        endif()
        if(NOT RBX_LUAU_ACTUAL_COMMIT STREQUAL RBX_RELEASE_729_LUAU_COMMIT)
            message(FATAL_ERROR
                "Vendored Luau revision mismatch. Expected ${RBX_RELEASE_729_LUAU_COMMIT}, "
                "got ${RBX_LUAU_ACTUAL_COMMIT}")
        endif()
    else()
        # Release source packages omit nested Git metadata. These independent
        # sentinels pin the build graph, VM, and compiler to the 0.729 tree.
        rbx_verify_file_sha256("${CMAKE_CURRENT_SOURCE_DIR}/vendor/luau/CMakeLists.txt"
            "fb7b06c9c98c9461d34bcd6d7e5a3e7f2621cb7c54bd0d7dd4a38fb271ed0583" "Luau build sentinel")
        rbx_verify_file_sha256("${CMAKE_CURRENT_SOURCE_DIR}/vendor/luau/Sources.cmake"
            "71b136eb2e2be88c15a91f7643a6d005193b07b989b58a7005ae0fb9ac9231ca" "Luau source-list sentinel")
        rbx_verify_file_sha256("${CMAKE_CURRENT_SOURCE_DIR}/vendor/luau/VM/src/lvmexecute.cpp"
            "46f3f14d07ac3343170ad8eef25b09b5296b59af1496b6b83d73bef4221f385e" "Luau VM sentinel")
        rbx_verify_file_sha256("${CMAKE_CURRENT_SOURCE_DIR}/vendor/luau/Compiler/src/Compiler.cpp"
            "e377fef714442c4cb83a099376d8d9d22ea0d69336fd9cfec2d2e15b55f475d5" "Luau compiler sentinel")
    endif()
    add_subdirectory(vendor/luau EXCLUDE_FROM_ALL)
else()
    FetchContent_Declare(
        luau
        GIT_REPOSITORY https://github.com/luau-lang/luau.git
        GIT_TAG ${RBX_RELEASE_729_LUAU_COMMIT}
    )
    FetchContent_MakeAvailable(luau)
endif()

FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

option(ALEX_ANTITAMPER_BUILD_EXAMPLE "Build alex_antitamper example" OFF)
option(RBX_RUNTIME_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer for the runtime" OFF)

add_subdirectory(packages/alex_antitamper)

add_executable(rbx_luau_runtime
    src/main.cpp
    src/runtime_v2.cpp
    src/runtime/clock.cpp
    src/runtime/curl_http_transport.cpp
    src/runtime/executor_compat.cpp
    src/runtime/luau_runtime_bridge.cpp
    src/runtime/memory_filesystem.cpp
    src/runtime/module_registry.cpp
    src/runtime/network_broker.cpp
    src/runtime/release729_datatypes.cpp
    src/runtime/release_manifest.cpp
    src/runtime/register_overflow.cpp
    src/runtime/roblox_debug.cpp
    src/runtime/roblox_environment_guard.cpp
    src/runtime/roblox_utf8.cpp
    src/runtime/runtime_context.cpp
    src/runtime/scheduler.cpp
    src/runtime/security.cpp
    src/runtime/signal.cpp
)

add_library(alexfuscator_core STATIC
    src/alexfuscator/alex_language.cpp
)

target_include_directories(alexfuscator_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(alexfuscator
    src/alexfuscator.cpp
)

add_executable(alex_deobfuscator
    src/deobfuscator/main.cpp
    src/deobfuscator/luraph/call_semantics.cpp
    src/deobfuscator/luraph/scan.cpp
    src/deobfuscator/luraph/emit.cpp
    src/deobfuscator/luraph/vm.cpp
    src/deobfuscator/core/deob.cpp
    src/deobfuscator/prometheus/lift.cpp
    src/deobfuscator/passes/flow.cpp
    src/deobfuscator/passes/names.cpp
    src/deobfuscator/passes/fields.cpp
    src/runtime/register_overflow.cpp
)

target_include_directories(alex_deobfuscator PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/deobfuscator
)

target_link_libraries(rbx_luau_runtime
    PRIVATE
        Luau.Compiler
        Luau.Ast
        Luau.VM
        Luau.CodeGen
        CURL::libcurl
        Threads::Threads
        nlohmann_json::nlohmann_json
        alex_antitamper::alex_antitamper
)

target_link_libraries(alexfuscator
    PRIVATE
        alexfuscator_core
        Luau.Compiler
        nlohmann_json::nlohmann_json
        alex_antitamper::alex_antitamper
)

target_link_libraries(alex_deobfuscator
    PRIVATE
        Luau.Ast
        Luau.Compiler
        nlohmann_json::nlohmann_json
        alex_antitamper::alex_antitamper
)

target_compile_definitions(rbx_luau_runtime PRIVATE LUA_USE_LONGJMP=1)

if(APPLE)
    find_library(RBX_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    target_compile_definitions(rbx_luau_runtime PRIVATE RBX_UTF8_USE_COREFOUNDATION=1)
    target_link_libraries(rbx_luau_runtime PRIVATE "${RBX_COREFOUNDATION_FRAMEWORK}")
elseif(WIN32)
    if(MSVC)
        target_link_libraries(rbx_luau_runtime PRIVATE Normaliz)
    else()
        target_link_libraries(rbx_luau_runtime PRIVATE normaliz)
    endif()
else()
    find_package(ICU REQUIRED COMPONENTS uc i18n)
    target_compile_definitions(rbx_luau_runtime PRIVATE RBX_UTF8_USE_ICU=1)
    target_link_libraries(rbx_luau_runtime PRIVATE ICU::uc ICU::i18n)
endif()

if(RBX_RUNTIME_ENABLE_SANITIZERS AND NOT MSVC)
    target_compile_options(rbx_luau_runtime PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(rbx_luau_runtime PRIVATE -fsanitize=address,undefined)
endif()

if(MINGW)
    target_link_options(rbx_luau_runtime PRIVATE -static)
endif()

if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()

if(MSVC)
    target_compile_options(rbx_luau_runtime PRIVATE /W4)
    target_compile_options(alexfuscator PRIVATE /W4)
    target_compile_options(alex_deobfuscator PRIVATE /W4)
else()
    target_compile_options(rbx_luau_runtime PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(alexfuscator PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(alex_deobfuscator PRIVATE -Wall -Wextra -Wpedantic)
endif()
