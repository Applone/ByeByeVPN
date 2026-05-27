set(BYEBYEVPN_TEST_SOURCES
    test_utils.cpp
    test_port_scan.cpp
    test_ct_check.cpp
    test_dns.cpp
    test_tcp_scanner.cpp
    test_tcp_async_scan.cpp
    test_udp_scanner.cpp
    test_http_client.cpp
    test_service_probes.cpp
    test_vpn_probes.cpp
    test_openssl_runtime.cpp
    test_brand_cert.cpp
    test_j3_probes.cpp
)

add_executable(byebyevpn_tests ${BYEBYEVPN_TEST_SOURCES})
target_link_libraries(byebyevpn_tests PRIVATE
    byebyevpn_core
    Catch2::Catch2WithMain
    OpenSSL::SSL
    OpenSSL::Crypto
    ${BYEBYEVPN_PLATFORM_LIBS}
)
target_include_directories(byebyevpn_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(byebyevpn_tests PRIVATE CATCH_CONFIG_NO_COUNTER)

if(WIN32)
    target_compile_definitions(byebyevpn_tests PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()

target_compile_options(byebyevpn_tests PRIVATE
    $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<CONFIG:Debug>>:-g;-O0;-fno-omit-frame-pointer>
)

byebyevpn_apply_common_warnings(byebyevpn_tests)
byebyevpn_apply_sanitizers(byebyevpn_tests)
byebyevpn_apply_runtime_link_options(byebyevpn_tests)

if(BYEBYEVPN_TEST_SHARDS LESS 1)
    set(BYEBYEVPN_TEST_SHARDS 1)
endif()

if(BYEBYEVPN_TEST_SHARDS EQUAL 1)
    add_test(NAME byebyevpn_tests COMMAND byebyevpn_tests)
else()
    math(EXPR BYEBYEVPN_LAST_TEST_SHARD "${BYEBYEVPN_TEST_SHARDS} - 1")
    foreach(shard RANGE 0 ${BYEBYEVPN_LAST_TEST_SHARD})
        add_test(
            NAME byebyevpn_tests_shard_${shard}
            COMMAND byebyevpn_tests --shard-count ${BYEBYEVPN_TEST_SHARDS} --shard-index ${shard}
        )
    endforeach()
endif()
