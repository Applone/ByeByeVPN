cmake_minimum_required(VERSION 3.15)
project(ByeByeVPN)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3.0 REQUIRED)

set(BYEBYEVPN_SOURCES
    src/analysis/brand_cert.cpp
    src/analysis/ct_check.cpp
    src/analysis/geoip.cpp
    src/analysis/local_env.cpp
    src/analysis/sni_consistency.cpp
    src/analysis/snitch.cpp
    src/analysis/traceroute.cpp
    src/analysis/tspu.cpp
    src/analysis/verdict.cpp
    src/cli/orchestrator.cpp
    src/core/utils.cpp
    src/main.cpp
    src/network/dns.cpp
    src/network/http_client.cpp
    src/network/https_probe.cpp
    src/network/j3_probes.cpp
    src/network/port_scan.cpp
    src/network/service_probes.cpp
    src/network/tcp_scanner.cpp
    src/network/tls_probe.cpp
    src/network/udp_scanner.cpp
    src/network/vpn_probes.cpp
    src/network/vpn_probes2.cpp
)

add_executable(byebyevpn ${BYEBYEVPN_SOURCES})

target_include_directories(byebyevpn PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(byebyevpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(byebyevpn PRIVATE ws2_32 iphlpapi crypt32 advapi32 user32 gdi32)
    target_compile_definitions(byebyevpn PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)

    if(MSVC)
        target_compile_options(byebyevpn PRIVATE /W3)
    elseif(MINGW)
        target_compile_options(byebyevpn PRIVATE -Wall -Wextra)
        target_link_options(byebyevpn PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
else()
    target_link_libraries(byebyevpn PRIVATE pthread dl)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_options(byebyevpn PRIVATE -static-libgcc -static-libstdc++)
    endif()

    target_compile_options(byebyevpn PRIVATE
        $<$<CONFIG:Debug>:-g;-O0;-fno-omit-frame-pointer>
    )
endif()
