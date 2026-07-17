find_package(Python3 REQUIRED COMPONENTS Interpreter)

function(rbx_find_host_program output_variable)
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
        find_program("${output_variable}" NAMES ${ARGN} HINTS /opt/homebrew/bin)
    else()
        find_program("${output_variable}" NAMES ${ARGN})
    endif()
endfunction()

add_executable(runtime_foundations_test
    runtime/runtime_foundations_test.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/clock.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/executor_compat.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/luau_runtime_bridge.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/memory_filesystem.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/module_registry.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/network_broker.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/release_manifest.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/runtime_context.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/scheduler.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/security.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/signal.cpp
)
target_include_directories(runtime_foundations_test PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/src/runtime)
target_link_libraries(runtime_foundations_test PRIVATE Luau.Compiler Luau.VM Threads::Threads nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(runtime_foundations_test PRIVATE /W4)
else()
    target_compile_options(runtime_foundations_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME runtime_native_foundations COMMAND runtime_foundations_test)
set_tests_properties(runtime_native_foundations PROPERTIES LABELS "unit;conformance;security" TIMEOUT 60)

add_executable(runtime_v2_isolation_test
    runtime_v2_isolation.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime_v2.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/clock.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/executor_compat.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/memory_filesystem.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/module_registry.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/network_broker.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/release_manifest.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/runtime_context.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/scheduler.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/security.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/signal.cpp
)
target_include_directories(runtime_v2_isolation_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(runtime_v2_isolation_test PRIVATE LUA_USE_LONGJMP=1)
target_link_libraries(runtime_v2_isolation_test PRIVATE Luau.VM Luau.Common Threads::Threads nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(runtime_v2_isolation_test PRIVATE /W4)
else()
    target_compile_options(runtime_v2_isolation_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME runtime_v2_isolation COMMAND runtime_v2_isolation_test)
set_tests_properties(runtime_v2_isolation PROPERTIES LABELS "unit;conformance;security" TIMEOUT 30)

add_executable(roblox_environment_guard_test
    runtime/roblox_environment_guard_test.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/roblox_environment_guard.cpp
    ${PROJECT_SOURCE_DIR}/src/runtime/release_manifest.cpp
)
target_include_directories(roblox_environment_guard_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(roblox_environment_guard_test PRIVATE Luau.VM nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(roblox_environment_guard_test PRIVATE /W4)
else()
    target_compile_options(roblox_environment_guard_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME runtime_roblox_environment_guard_unit COMMAND roblox_environment_guard_test)
set_tests_properties(runtime_roblox_environment_guard_unit PROPERTIES LABELS "unit;security;antitamper" TIMEOUT 30)

option(RBX_RUNTIME_ENABLE_STRESS_TESTS "Enable long-running generated model tests" OFF)
option(RBX_RUNTIME_ENABLE_SUBJECT_TESTS "Enable the bounded supplied Luraph workload" OFF)
option(RBX_RUNTIME_ENABLE_SUBJECT_ACCEPTANCE "Enable the full supplied Luraph acceptance run" OFF)
set(RBX_RUNTIME_MODEL_OPERATIONS "1000" CACHE STRING "Generated lifecycle operations used by the regular fidelity test")

function(rbx_add_python_test name labels timeout script)
    add_test(
        NAME "${name}"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/${script}" ${ARGN}
    )
    set_tests_properties(
        "${name}"
        PROPERTIES
            LABELS "${labels}"
            TIMEOUT "${timeout}"
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    )
endfunction()

add_executable(luraph_adapter_test
    deobfuscator/luraph/scan_test.cpp
    ${PROJECT_SOURCE_DIR}/src/deobfuscator/luraph/scan.cpp
)
target_include_directories(luraph_adapter_test PRIVATE ${PROJECT_SOURCE_DIR}/src/deobfuscator)
if(MSVC)
    target_compile_options(luraph_adapter_test PRIVATE /W4)
else()
    target_compile_options(luraph_adapter_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME deobfuscator_luraph_adapter_unit COMMAND luraph_adapter_test)
set_tests_properties(deobfuscator_luraph_adapter_unit PROPERTIES LABELS "unit;deobfuscator;security" TIMEOUT 30)

add_executable(luraph_vm_test
    deobfuscator/luraph/vm_test.cpp
    ${PROJECT_SOURCE_DIR}/src/deobfuscator/luraph/vm.cpp
)
target_include_directories(luraph_vm_test PRIVATE ${PROJECT_SOURCE_DIR}/src/deobfuscator)
if(MSVC)
    target_compile_options(luraph_vm_test PRIVATE /W4)
else()
    target_compile_options(luraph_vm_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME deobfuscator_luraph_vm_unit COMMAND luraph_vm_test)
set_tests_properties(deobfuscator_luraph_vm_unit PROPERTIES LABELS "unit;deobfuscator;security" TIMEOUT 30)

add_executable(luraph_semantic_emitter_test
    deobfuscator/luraph/emit_test.cpp
    ${PROJECT_SOURCE_DIR}/src/deobfuscator/luraph/emit.cpp
)
target_include_directories(luraph_semantic_emitter_test PRIVATE ${PROJECT_SOURCE_DIR}/src/deobfuscator)
target_link_libraries(luraph_semantic_emitter_test PRIVATE nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(luraph_semantic_emitter_test PRIVATE /W4)
else()
    target_compile_options(luraph_semantic_emitter_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME deobfuscator_luraph_semantic_emitter_unit COMMAND luraph_semantic_emitter_test)
set_tests_properties(deobfuscator_luraph_semantic_emitter_unit PROPERTIES LABELS "unit;deobfuscator;security" TIMEOUT 30)

if(TARGET alex_deobfuscator)
    rbx_add_python_test(
        deobfuscator_luraph_adapter_integration
        "integration;deobfuscator;security"
        60
        test_luraph_adapter_integration.py
        --deobfuscator "$<TARGET_FILE:alex_deobfuscator>"
    )

    rbx_add_python_test(
        deobfuscator_luraph_nested_activation_truthfulness
        "conformance;integration;security;subject;deobfuscator"
        30
        test_luraph_nested_activation_truthfulness.py
        --deobfuscator "$<TARGET_FILE:alex_deobfuscator>"
    )
endif()

rbx_add_python_test(
    release_729_manifest
    "unit;conformance"
    30
    verify_release_manifest.py
)

rbx_add_python_test(
    release_729_subject_identity
    "unit;subject"
    15
    verify_release_manifest.py
    --subject-only
)

rbx_add_python_test(
    deobfuscator_luraph_trace_probe
    "unit;deobfuscator;subject"
    30
    test_luraph_trace_probe.py
)

if(TARGET rbx_luau_runtime)
    rbx_add_python_test(
        runtime_probe_trace_channel
        "unit;integration;security;deobfuscator"
        30
        test_probe_trace_channel.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_native_environment_trace
        "unit;integration;security;antitamper"
        30
        test_native_environment_trace.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_register_overflow
        "unit;conformance;integration"
        30
        test_register_overflow.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_release729_debug_extensions
        "unit;conformance;integration"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/release729_debug_extensions.luau"
        --profile roblox-client
        --marker release729-debug-extensions-ok
    )

    rbx_add_python_test(
        runtime_release729_utf8_extensions
        "unit;conformance;integration"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/release729_utf8_extensions.luau"
        --profile roblox-client
        --marker release729-utf8-extensions-ok
    )

    rbx_add_python_test(
        runtime_release729_coroutine_close_scheduler
        "unit;conformance;integration"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/release729_coroutine_close_scheduler.luau"
        --profile executor-client
        --marker release729-coroutine-close-scheduler-ok
    )

    rbx_add_python_test(
        runtime_instance_reflection_v3
        "conformance;integration"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/instance_reflection_v3.luau"
        --marker instance-reflection-v3-ok
        --allow-unsupported
    )

    rbx_add_python_test(
        runtime_native_values_v3
        "unit;conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/native_values_v3.luau"
        --profile roblox-client
        --marker native-values-v3-ok
    )

    rbx_add_python_test(
        runtime_native_random_roblox
        "unit;conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/native_random_v3.luau"
        --profile roblox-client
        --marker native-random-v3-ok
    )

    rbx_add_python_test(
        runtime_native_random_executor
        "unit;conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/native_random_v3.luau"
        --profile executor-client
        --marker native-random-v3-ok
    )

    rbx_add_python_test(
        runtime_release729_datatypes_roblox
        "unit;conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/release729_datatypes_native.luau"
        --profile roblox-client
        --marker release729-datatypes-native-ok
    )

    rbx_add_python_test(
        runtime_release729_datatypes_executor
        "unit;conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/release729_datatypes_native.luau"
        --profile executor-client
        --marker release729-datatypes-native-ok
    )

    rbx_add_python_test(
        runtime_release729_vector_instance_globals
        "unit;conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/release729_vector_instance_globals.luau"
        --profile roblox-client
        --marker release729-vector-instance-globals-ok
    )

    rbx_add_python_test(
        runtime_instance_constructor_native
        "unit;conformance;integration"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/instance_constructor_native_v3.luau"
        --profile executor-client
        --marker instance-constructor-native-v3-ok
    )

    rbx_add_python_test(
        runtime_release729_datatype_catalog
        "unit;conformance;integration"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/release729_datatype_catalog_probe.luau"
        --profile roblox-client
        --marker release729-datatype-catalog-ok
    )

    rbx_add_python_test(
        runtime_executor_mutable_namespaces
        "conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/executor_mutable_namespaces_v3.luau"
        --profile executor-client
        --marker executor-mutable-namespaces-v3-ok
    )

    rbx_add_python_test(
        runtime_roblox_readonly_namespaces
        "conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/executor_mutable_namespaces_v3.luau"
        --profile roblox-client
        --marker roblox-readonly-namespaces-v3-ok
    )

    rbx_add_python_test(
        runtime_luraph_report_truthfulness
        "conformance;integration;security;subject"
        90
        test_luraph_report_truthfulness.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_luraph_path2d_release729
        "unit;conformance;integration;subject"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/luraph_path2d_length_fidelity.luau"
        --profile roblox-client
        --marker luraph-path2d-release729-ok
    )

    rbx_add_python_test(
        runtime_luraph_subject_1b642e
        "conformance;integration;security;subject"
        60
        test_luraph_subject_1b642e.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_luraph_bridge_truthfulness
        "conformance;integration;security;subject;deobfuscator"
        60
        test_luraph_bridge_truthfulness.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_luraph_generated_interpreter_truthfulness
        "conformance;integration;security;subject;deobfuscator"
        60
        test_luraph_generated_interpreter_truthfulness.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    if(TARGET alex_deobfuscator)
        rbx_add_python_test(
            deobfuscator_luraph_trace_reconstruction
            "conformance;integration;security;subject;deobfuscator"
            90
            test_luraph_trace_reconstruction.py
            --deobfuscator "$<TARGET_FILE:alex_deobfuscator>"
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        )
        rbx_add_python_test(
            deobfuscator_luraph_auto_trace_pipeline
            "conformance;integration;security;subject;deobfuscator"
            90
            test_luraph_auto_trace_pipeline.py
            --deobfuscator "$<TARGET_FILE:alex_deobfuscator>"
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        )
        rbx_add_python_test(
            deobfuscator_luraph_runtime_structure_pipeline
            "conformance;integration;security;subject;deobfuscator"
            90
            test_luraph_runtime_structure_pipeline.py
            --deobfuscator "$<TARGET_FILE:alex_deobfuscator>"
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        )
        rbx_add_python_test(
            deobfuscator_luraph_closure_descriptor_trace
            "conformance;integration;security;subject;deobfuscator"
            30
            test_luraph_closure_descriptor_trace.py
            --deobfuscator "$<TARGET_FILE:alex_deobfuscator>"
        )
    endif()

    rbx_add_python_test(
        runtime_release_729_cli
        "conformance;integration;security"
        120
        test_release_729_cli.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_blackbox_release_729_hardening
        "conformance;integration;security"
        120
        blackbox_release729_hardening.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_executor_memory_filesystem
        "integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/executor_memory_filesystem_v3.luau"
        --scenario "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/executor_filesystem_v2.json"
        --profile executor-client
        --marker executor-memory-filesystem-v3-ok
    )

    rbx_add_python_test(
        runtime_roblox_filesystem_absent
        "conformance;security"
        30
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/roblox_filesystem_absent_v3.luau"
        --profile roblox-client
        --marker roblox-filesystem-absent-v3-ok
    )

    rbx_add_python_test(
        runtime_module_sidecar_v2
        "conformance;integration;security"
        30
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/module_sidecar_v2.luau"
        --scenario "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/module_sidecar_v2.json"
        --profile roblox-client
        --marker module-sidecar-v2-ok
    )

    rbx_add_python_test(
        runtime_module_concurrency_v2
        "conformance;integration;security"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/module_concurrency_v2.luau"
        --scenario "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/module_concurrency_v2.json"
        --profile roblox-client
        --marker module-concurrency-v2-ok
    )

    rbx_add_python_test(
        runtime_scenario_v2_lifecycle
        "conformance;integration"
        60
        run_luau_contract.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --script "${CMAKE_CURRENT_SOURCE_DIR}/scenario_v2_lifecycle.luau"
        --scenario "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/scenario_v2_lifecycle.json"
        --profile roblox-client
        --marker scenario-v2-lifecycle-ok
    )

    rbx_add_python_test(
        runtime_fidelity_release_729
        "conformance;integration"
        180
        run_roblox_fidelity.py
        --operations "${RBX_RUNTIME_MODEL_OPERATIONS}"
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        runtime_instance_retention
        "integration;stress;security"
        120
        test_instance_retention.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        --iterations 2500
    )

    rbx_add_python_test(
        runtime_network_security
        "integration;security"
        90
        test_runtime_network.py
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_find_host_program(NODE_EXECUTABLE node nodejs)
    if(NODE_EXECUTABLE)
        rbx_add_python_test(
            runtime_web_artifact_download
            "integration;security"
            90
            test_web_artifact_download.py
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        )
        rbx_add_python_test(
            runtime_web_heavy_jobs
            "integration;security;site"
            120
            test_web_runtime_jobs.py
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        )
    endif()

    if(RBX_RUNTIME_ENABLE_SUBJECT_TESTS)
        rbx_add_python_test(
            runtime_release_729_subject_bounded
            "integration;subject"
            60
            run_release_729_subject.py
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        )
    endif()

    if(RBX_RUNTIME_ENABLE_SUBJECT_ACCEPTANCE)
        rbx_add_python_test(
            runtime_release_729_subject_acceptance
            "integration;subject;stress"
            320
            run_release_729_subject.py
            --acceptance
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
        )
    endif()

    if(RBX_RUNTIME_ENABLE_STRESS_TESTS)
        rbx_add_python_test(
            runtime_instance_retention_100k
            "integration;stress;security"
            600
            test_instance_retention.py
            --runtime "$<TARGET_FILE:rbx_luau_runtime>"
            --iterations 100000
            --timeout 480
        )
    endif()
endif()

if(TARGET alexfuscator AND RBX_RUNTIME_ENABLE_STRESS_TESTS)
    rbx_add_python_test(
        runtime_vnext_model_stress
        "conformance;stress"
        900
        run_vnext_differential.py
        --programs 10000
        --alexfuscator "$<TARGET_FILE:alexfuscator>"
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )
endif()

if(TARGET alexfuscator AND TARGET rbx_luau_runtime)
    rbx_add_python_test(
        alexfuscator_alex_language
        "unit;conformance;alexfuscator"
        240
        test_alex_language.py
        --alexfuscator "$<TARGET_FILE:alexfuscator>"
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        alexfuscator_alex_language_edges
        "unit;conformance;alexfuscator"
        240
        test_alex_language_edges.py
        --alexfuscator "$<TARGET_FILE:alexfuscator>"
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        alexfuscator_semantic_corpus
        "conformance;alexfuscator"
        3600
        run_vnext_differential.py
        --programs 500
        --alexfuscator "$<TARGET_FILE:alexfuscator>"
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        alexfuscator_vm6_structure
        "conformance;security;alexfuscator"
        900
        test_alexfuscator_v5.py
        --seeds 100
        --alexfuscator "$<TARGET_FILE:alexfuscator>"
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )

    rbx_add_python_test(
        alexfuscator_vm6_contract
        "conformance;security;alexfuscator"
        300
        test_alexvm6_contract.py
        --alexfuscator "$<TARGET_FILE:alexfuscator>"
        --runtime "$<TARGET_FILE:rbx_luau_runtime>"
    )
endif()

rbx_find_host_program(NPM_EXECUTABLE npm npm.cmd)
if(NPM_EXECUTABLE)
    add_test(NAME runtime_site_check COMMAND "${NPM_EXECUTABLE}" run check)
    add_test(NAME runtime_site_unit COMMAND "${NPM_EXECUTABLE}" test)
    set_tests_properties(
        runtime_site_check runtime_site_unit
        PROPERTIES
            LABELS "unit;site"
            TIMEOUT 90
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/web/rbx-runtime-runner"
    )
endif()

if(TARGET alex_deobfuscator)
    rbx_add_python_test(
        deobfuscator_luraph_luaauth_lph_dollar
        "integration;deobfuscator;security;luraph"
        90
        test_luraph_luaauth_lph_dollar.py
        --deobfuscator "$<TARGET_FILE:alex_deobfuscator>"
    )
endif()
