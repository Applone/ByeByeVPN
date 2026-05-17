#!/bin/bash
./local_build.sh --windows < /dev/null
build-win/tests/byebyevpn_tests.exe "tcp_connect reports refused" -s
build-win/tests/byebyevpn_tests.exe "resolve_host reports invalid host errors" -s
build-win/tests/byebyevpn_tests.exe "resolve_host nonexistent domain" -s
