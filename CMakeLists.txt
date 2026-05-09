cmake_minimum_required(VERSION 3.15)
project(ByeByeVPN LANGUAGES CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BYEBYEVPN_STATIC "Build with static libraries" ON)
option(BYEBYEVPN_ENABLE_TESTS "Build unit tests" ON)
option(BYEBYEVPN_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)
option(BYEBYEVPN_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(BYEBYEVPN_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(BYEBYEVPN_ENABLE_MSAN "Enable MemorySanitizer (Clang/Linux only)" OFF)
option(BYEBYEVPN_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

if(BYEBYEVPN_ENABLE_MSAN AND (BYEBYEVPN_ENABLE_ASAN OR BYEBYEVPN_ENABLE_TSAN))
    message(FATAL_ERROR "MemorySanitizer cannot be combined with AddressSanitizer/ThreadSanitizer")
endif()

if(BYEBYEVPN_ENABLE_TSAN AND BYEBYEVPN_ENABLE_ASAN)
    message(FATAL_ERROR "ThreadSanitizer cannot be combined with AddressSanitizer")
endif()

if(MSVC AND (BYEBYEVPN_ENABLE_ASAN OR BYEBYEVPN_ENABLE_UBSAN OR BYEBYEVPN_ENABLE_MSAN OR BYEBYEVPN_ENABLE_TSAN))
    message(FATAL_ERROR "Sanitizers are currently configured for non-MSVC toolchains only")
endif()

set(BYEBYEVPN_SANITIZER_FLAGS "")
if(NOT MSVC)
    if(BYEBYEVPN_ENABLE_ASAN)
        list(APPEND BYEBYEVPN_SANITIZER_FLAGS -fsanitize=address)
    endif()
    if(BYEBYEVPN_ENABLE_UBSAN)
        list(APPEND BYEBYEVPN_SANITIZER_FLAGS -fsanitize=undefined)
    endif()
    if(BYEBYEVPN_ENABLE_MSAN)
        list(APPEND BYEBYEVPN_SANITIZER_FLAGS -fsanitize=memory -fsanitize-memory-track-origins=2)
    endif()
    if(BYEBYEVPN_ENABLE_TSAN)
        list(APPEND BYEBYEVPN_SANITIZER_FLAGS -fsanitize=thread)
    endif()
endif()

function(byebyevpn_apply_common_warnings target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4 /permissive-)
        if(BYEBYEVPN_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
        if(BYEBYEVPN_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE -Werror)
        endif()
    endif()
endfunction()

function(byebyevpn_apply_sanitizers target_name)
    if(BYEBYEVPN_SANITIZER_FLAGS)
        target_compile_options(${target_name} PRIVATE ${BYEBYEVPN_SANITIZER_FLAGS} -fno-omit-frame-pointer)
        target_link_options(${target_name} PRIVATE ${BYEBYEVPN_SANITIZER_FLAGS})
    endif()
endfunction()

set(BYEBYEVPN_RUNTIME_LINK_OPTIONS "")
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND BYEBYEVPN_STATIC)
    list(APPEND BYEBYEVPN_RUNTIME_LINK_OPTIONS -static-libgcc -static-libstdc++)
endif()

function(byebyevpn_apply_runtime_link_options target_name)
    if(BYEBYEVPN_RUNTIME_LINK_OPTIONS)
        target_link_options(${target_name} PRIVATE ${BYEBYEVPN_RUNTIME_LINK_OPTIONS})
    endif()
endfunction()

if(BYEBYEVPN_STATIC)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
    set(OPENSSL_USE_STATIC_LIBS FALSE)
endif()

find_package(OpenSSL 3.0 REQUIRED)

set(BYEBYEVPN_CORE_SOURCES
    src/analysis/brand_cert.cpp
    src/analysis/ct_check.cpp
    src/analysis/geoip.cpp
    src/analysis/sni_consistency.cpp
    src/analysis/verdict.cpp
    src/cli/orchestrator.cpp
    src/core/utils.cpp
    src/network/dns.cpp
    src/network/http_client.cpp
    src/network/https_probe.cpp
    src/network/j3_probes.cpp
    src/network/openssl_runtime.cpp
    src/network/port_scan.cpp
    src/network/service_probes.cpp
    src/network/tcp_scanner.cpp
    src/network/tcp_async_scan.cpp
    src/network/tls_probe.cpp
    src/network/udp_scanner.cpp
    src/network/vpn_probes.cpp
)

set(BYEBYEVPN_PLATFORM_LIBS "")
if(WIN32)
    list(APPEND BYEBYEVPN_PLATFORM_LIBS ws2_32 iphlpapi crypt32 advapi32 user32 gdi32)
else()
    list(APPEND BYEBYEVPN_PLATFORM_LIBS pthread dl)
endif()

add_library(byebyevpn_core STATIC ${BYEBYEVPN_CORE_SOURCES})
target_include_directories(byebyevpn_core PRIVATE ${OPENSSL_INCLUDE_DIR})
if(WIN32)
    target_compile_definitions(byebyevpn_core PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()
target_compile_options(byebyevpn_core PRIVATE
    $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<CONFIG:Debug>>:-g;-O0;-fno-omit-frame-pointer>
)
byebyevpn_apply_common_warnings(byebyevpn_core)
byebyevpn_apply_sanitizers(byebyevpn_core)

add_executable(byebyevpn src/main.cpp)
target_link_libraries(byebyevpn PRIVATE byebyevpn_core OpenSSL::SSL OpenSSL::Crypto ${BYEBYEVPN_PLATFORM_LIBS})
if(WIN32)
    target_compile_definitions(byebyevpn PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()
target_compile_options(byebyevpn PRIVATE
    $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<CONFIG:Debug>>:-g;-O0;-fno-omit-frame-pointer>
)
byebyevpn_apply_common_warnings(byebyevpn)
byebyevpn_apply_sanitizers(byebyevpn)
byebyevpn_apply_runtime_link_options(byebyevpn)

if(BYEBYEVPN_ENABLE_TESTS AND BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(
        catch2
        URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.8.1.tar.gz
    )
    FetchContent_MakeAvailable(catch2)

    if(TARGET Catch2)
        byebyevpn_apply_sanitizers(Catch2)
    endif()
    if(TARGET Catch2WithMain)
        byebyevpn_apply_sanitizers(Catch2WithMain)
    endif()

    add_subdirectory(tests)
endif()
