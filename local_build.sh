#!/bin/bash
# WARNING: This build script is OUTDATED and DEPRECATED, and will be deleted soon.
# Please use the Python version instead: python3 local_build.py
set -euo pipefail

# ANSI color codes
RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
CYAN="\033[36m"
YELLOW="\033[33m"
DIM="\033[2m"
ITALIC="\033[3m"

# CLI parsing
KEEP_ARTIFACTS=0
BUILD_LINUX=1
BUILD_WINDOWS=1
EXPLICIT_BUILD_TARGET=0

while [ $# -gt 0 ]; do
    case $1 in
        --keep) KEEP_ARTIFACTS=1; shift ;;
        --linux)
            if [ "$EXPLICIT_BUILD_TARGET" -eq 0 ]; then BUILD_WINDOWS=0; EXPLICIT_BUILD_TARGET=1; fi
            BUILD_LINUX=1; shift ;;
        --windows)
            if [ "$EXPLICIT_BUILD_TARGET" -eq 0 ]; then BUILD_LINUX=0; EXPLICIT_BUILD_TARGET=1; fi
            BUILD_WINDOWS=1; shift ;;
        *)
            echo -e "${RED}Unknown option: $1${RESET}" >&2
            exit 2 ;;
    esac
done

STATE_FILE="$(mktemp "/tmp/bbvpn_state.XXXXXX.sh")"
chmod 600 "$STATE_FILE"
RUNNING_PID=""
STAGE_LOGS=""

# Append a shell-safe `export NAME=VALUE` line to STATE_FILE.
# The value is escaped with printf %q so embedded $(), backticks, quotes,
# spaces or newlines cannot be executed when the state file is later sourced.
write_state() {
    local name="$1" value="$2"
    printf 'export %s=%q\n' "$name" "$value" >> "$STATE_FILE"
}

cleanup() {
    if [ -n "${UI_LINES:-}" ]; then
        tput rc 2>/dev/null || true
        printf "\033[%dB\n" "$UI_LINES" 2>/dev/null || true
    fi
    
    if [ -n "$RUNNING_PID" ] && kill -0 "$RUNNING_PID" 2>/dev/null; then
        kill -9 "$RUNNING_PID" 2>/dev/null || true
    fi
    
    if [ "$KEEP_ARTIFACTS" -eq 1 ]; then
        echo -e "${YELLOW}Skipping cleanup (--keep flag provided).${RESET}"
    else
        echo -e "${CYAN}Cleaning up build artifacts...${RESET}"
        rm -rf build staging build-cov coverage.info coverage-html \
               deps build-asan-ubsan build-tsan build-msan build-win
    fi
    rm -f "$STATE_FILE" $STAGE_LOGS
}

trap 'echo -e "\n${RED}Interrupted${RESET}"; exit 130' INT
trap cleanup EXIT

# Initialize state file
> "$STATE_FILE"
OPENSSL_VERSION="3.5.6"
CONTAINER_IMAGE="localhost/helpers/sans:latest"
STATIC_FLAG="-DBYEBYEVPN_STATIC=OFF"

write_state OPENSSL_VERSION "$OPENSSL_VERSION"
write_state CONTAINER_IMAGE "$CONTAINER_IMAGE"
write_state STATIC_FLAG "$STATIC_FLAG"
write_state CC clang
write_state CXX clang++
TEST_PARALLEL_JOBS=$(nproc)
[ "$TEST_PARALLEL_JOBS" -lt 1 ] && TEST_PARALLEL_JOBS=1
write_state TEST_PARALLEL_JOBS "$TEST_PARALLEL_JOBS"

# Stages definition
STAGES=()
STAGE_KEYS=()
STAGE_CMDS=()
STAGE_STATUS=()
STAGE_TIME=()

add_stage() {
    STAGES+=("$1")
    STAGE_KEYS+=("$2")
    STAGE_CMDS+=("$3")
    STAGE_STATUS+=("WAIT")
    STAGE_TIME+=("")
}

add_stage "Dependency checks" "deps" "do_deps_check"
add_stage "vcpkg setup" "vcpkg" "do_vcpkg_setup"

if [ "$BUILD_LINUX" -eq 1 ]; then
    add_stage "Static analysis (cppcheck)" "cppcheck" "do_cppcheck"
    add_stage "Static analysis (clang-tidy)" "clangtidy" "do_clangtidy"
    add_stage "Debug build" "build_debug" "do_build_debug"
    add_stage "Coverage build & tests" "cov" "do_cov"
    add_stage "Sanitizer: asan-ubsan" "asan" "do_asan"
    add_stage "Sanitizer: tsan" "tsan" "do_tsan"
    add_stage "Sanitizer: msan" "msan" "do_msan"
else
    add_stage "Linux phases" "linux" "true"
    STAGE_STATUS[${#STAGE_STATUS[@]}-1]="SKIP"
fi

if [ "$BUILD_WINDOWS" -eq 1 ]; then
    add_stage "Windows cross-compile" "win_build" "do_win_build"
    add_stage "Windows tests" "win_test" "do_win_test"
else
    add_stage "Windows phases" "win" "true"
    STAGE_STATUS[${#STAGE_STATUS[@]}-1]="SKIP"
fi

NUM_STAGES=${#STAGES[@]}
UI_LINES=$(( NUM_STAGES + 3 ))
CURRENT_ACTION=""
SPINNER_FRAME=""

setup_ui() {
    for (( i=0; i<$UI_LINES; i++ )); do echo ""; done
    printf "\033[%dA" "$UI_LINES"
    tput sc
}

pause_ui() {
    tput rc
    printf "\033[%dB\n" "$UI_LINES"
}

clear_ui() {
    tput rc
    printf "\033[J"
}

draw_ui() {
    tput rc
    echo -e "${BOLD}${CYAN}Stages:${RESET}\033[K"
    for i in "${!STAGES[@]}"; do
        local status="${STAGE_STATUS[$i]}"
        local name="${STAGES[$i]}"
        local time_str="${STAGE_TIME[$i]}"
        
        local icon=""
        local color=""
        local tcolor="${DIM}${CYAN}"
        local frame_text=""
        
        case "$status" in
            WAIT) icon="WAIT"; color="${DIM}"; tcolor="" ;;
            RUN)  icon="RUN "; color="${BOLD}${CYAN}" ;;
            OK)   icon="OK  "; color="${BOLD}${GREEN}" ;;
            FAIL) icon="FAIL"; color="${BOLD}${RED}" ;;
            SKIP) icon="SKIP"; color="${DIM}${YELLOW}" ;;
        esac

        if [ "$status" == "RUN" ] && [ -n "$SPINNER_FRAME" ]; then
            frame_text="${BOLD}${CYAN}${SPINNER_FRAME}${RESET} "
        else
            frame_text="  "
        fi
        
        local cols=$(tput cols 2>/dev/null || echo 80)
        [ -z "$cols" ] && cols=80
        
        local max_name_len=$(( cols - 25 ))
        [ $max_name_len -lt 10 ] && max_name_len=10
        local disp_name="$name"
        if [ ${#disp_name} -gt $max_name_len ]; then
            disp_name="${disp_name:0:$max_name_len-1}…"
        fi
        
        local v_len=$(( 13 + ${#disp_name} ))
        local prefix="  [ ${color}${icon}${RESET} ] ${frame_text}${disp_name}"
        
        if [ -n "$time_str" ]; then
            local target_col=60
            [ $cols -lt $target_col ] && target_col=$cols
            local pad=$(( target_col - v_len - ${#time_str} ))
            [ $pad -lt 1 ] && pad=1
            printf "%b%*s%b%s%b\033[K\n" "$prefix" "$pad" "" "$tcolor" "$time_str" "${RESET}"
        else
            printf "%b\033[K\n" "$prefix"
        fi
    done
    
    echo -e "\033[K"
    if [ -n "$CURRENT_ACTION" ]; then
        local cols=$(tput cols 2>/dev/null || echo 80)
        [ -z "$cols" ] && cols=80
        local max_len=$(( cols - 6 ))
        [ $max_len -lt 10 ] && max_len=10
        local act="${CURRENT_ACTION}"
        if [ ${#act} -gt $max_len ]; then
            act="${act:0:$max_len-1}…"
        fi
        echo -e "${DIM}${ITALIC}  → ${act}${RESET}\033[K"
    else
        echo -e "\033[K"
    fi
}

TOTAL_TIME_START=$(date +%s.%N)
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

fail_summary() {
    local name="$1"
    local log="$2"
    
    pause_ui
    local total_end=$(date +%s.%N)
    local total_elapsed=$(awk -v t1="$TOTAL_TIME_START" -v t2="$total_end" 'BEGIN{printf "%.1fs", t2-t1}')
    
    echo -e "\n${BOLD}${CYAN}==================================================${RESET}"
    echo -e "${BOLD}Build Summary${RESET}"
    echo -e "${BOLD}${CYAN}==================================================${RESET}"
    echo -e "Total Time:  ${BOLD}${total_elapsed}${RESET}"
    echo -e "Passed:      ${BOLD}${GREEN}${TOTAL_PASS}${RESET}"
    echo -e "Skipped:     ${BOLD}${YELLOW}${TOTAL_SKIP}${RESET}"
    echo -e "Failed:      ${BOLD}${RED}${TOTAL_FAIL}${RESET}"
    echo -e "${BOLD}${CYAN}==================================================${RESET}\n"

    echo -e "${BOLD}${RED}==================================================${RESET}"
    echo -e "${BOLD}${RED}  FAILURE IN STAGE: ${name}${RESET}"
    echo -e "${BOLD}${RED}==================================================${RESET}\n"
    
    if [ -f "$log" ]; then
        cat "$log"
    else
        echo -e "${DIM}(No log file found)${RESET}"
    fi
    echo -e "\n${BOLD}${RED}==================================================${RESET}"
    echo -e "${BOLD}${RED}Build aborted.${RESET}\n"
}

final_summary() {
    pause_ui
    local total_end=$(date +%s.%N)
    local total_elapsed=$(awk -v t1="$TOTAL_TIME_START" -v t2="$total_end" 'BEGIN{printf "%.1fs", t2-t1}')
    
    echo -e "\n${BOLD}${CYAN}==================================================${RESET}"
    echo -e "${BOLD}Build Summary${RESET}"
    echo -e "${BOLD}${CYAN}==================================================${RESET}"
    echo -e "Total Time:  ${BOLD}${total_elapsed}${RESET}"
    echo -e "Passed:      ${BOLD}${GREEN}${TOTAL_PASS}${RESET}"
    echo -e "Skipped:     ${BOLD}${YELLOW}${TOTAL_SKIP}${RESET}"
    echo -e "Failed:      ${BOLD}${RED}${TOTAL_FAIL}${RESET}"
    echo -e "${BOLD}${CYAN}==================================================${RESET}\n"
    
    if [ $TOTAL_FAIL -eq 0 ]; then
        echo -e "${BOLD}${GREEN}Build completed successfully!${RESET}\n"
    fi
}

run_stage() {
    local index=$1
    if [ "${STAGE_STATUS[$index]}" == "SKIP" ]; then
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        return
    fi
    
    local name="${STAGES[$index]}"
    local key="${STAGE_KEYS[$index]}"
    local cmd="${STAGE_CMDS[$index]}"
    
    STAGE_STATUS[$index]="RUN"
    draw_ui
    
    local log
    log="$(mktemp "/tmp/bbvpn_stage_${key}.XXXXXX.log")"
    chmod 600 "$log"
    STAGE_LOGS="$STAGE_LOGS $log"

    local start_time=$(date +%s.%N)
    
    eval "source '$STATE_FILE' && $cmd" > "$log" 2>&1 &
    local pid=$!
    RUNNING_PID=$pid
    
    local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local f=0
    
    while kill -0 $pid 2>/dev/null; do
        local tail_line=$(tail -n 1 "$log" 2>/dev/null | tr -d '\r\n' | tr -cd '\040-\176' || true)
        if [ -n "$tail_line" ]; then
            CURRENT_ACTION="$tail_line"
        fi
        
        SPINNER_FRAME="${frames[$f]}"
        f=$(( (f + 1) % 10 ))
        
        draw_ui
        sleep 0.1
    done
    
    local exit_code=0
    wait $pid || exit_code=$?
    RUNNING_PID=""
    
    local end_time=$(date +%s.%N)
    local elapsed=$(awk -v t1="$start_time" -v t2="$end_time" 'BEGIN{printf "%.1fs", t2-t1}')
    STAGE_TIME[$index]="$elapsed"
    
    SPINNER_FRAME=""
    CURRENT_ACTION=""
    
    if [ $exit_code -eq 0 ]; then
        STAGE_STATUS[$index]="OK"
        TOTAL_PASS=$((TOTAL_PASS + 1))
        rm -f "$log"
    else
        STAGE_STATUS[$index]="FAIL"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        draw_ui
        fail_summary "$name" "$log"
        exit 1
    fi
    draw_ui
}

# --- Command functions ---

do_deps_check() {
    local ce=""
    if command -v podman &>/dev/null; then
        ce="podman"
    elif command -v docker &>/dev/null; then
        ce="docker"
    else
        echo "ERROR: Neither podman nor docker is installed." >&2
        return 1
    fi
    write_state CONTAINER_ENGINE "$ce"

    # Array literals with fixed, non-user-controlled contents — safe as-is.
    if [ ! -e /dev/net/tun ]; then
        echo "export CONTAINER_NETWORK_ARGS=(--network=host)" >> "$STATE_FILE"
    else
        echo "export CONTAINER_NETWORK_ARGS=()" >> "$STATE_FILE"
    fi

    local MISSING_DEPS=()
    if ! command -v perl &>/dev/null; then MISSING_DEPS+=("perl"); else
        if ! perl -e 'use IPC::Cmd;' &>/dev/null; then MISSING_DEPS+=("perl-IPC-Cmd"); fi
        if ! perl -e 'use FindBin;' &>/dev/null; then MISSING_DEPS+=("perl-FindBin"); fi
        if ! perl -e 'use File::Compare;' &>/dev/null; then MISSING_DEPS+=("perl-File-Compare"); fi
    fi
    if [ ! -d /usr/include/linux ]; then MISSING_DEPS+=("kernel-headers"); fi
    if ! command -v make &>/dev/null; then MISSING_DEPS+=("make"); fi
    if ! command -v cmake &>/dev/null; then MISSING_DEPS+=("cmake"); fi
    if ! command -v ninja &>/dev/null; then MISSING_DEPS+=("ninja-build"); fi
    if ! command -v clang &>/dev/null; then MISSING_DEPS+=("clang"); fi
    if [ "$BUILD_WINDOWS" -eq 1 ]; then
        if ! command -v x86_64-w64-mingw32-g++ &>/dev/null; then MISSING_DEPS+=("x86_64-w64-mingw32-g++"); fi
    fi

    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        echo "ERROR: Missing dependencies: ${MISSING_DEPS[*]}" >&2
        return 1
    fi
}

check_vcpkg_prompt() {
    if [ -n "${VCPKG_ROOT:-}" ] && [ -d "$VCPKG_ROOT" ]; then
        write_state VCPKG_ROOT "$VCPKG_ROOT"
        return 0
    elif command -v vcpkg &>/dev/null; then
        local vr="$(dirname "$(command -v vcpkg)")"
        if [ ! -f "$vr/scripts/buildsystems/vcpkg.cmake" ]; then
            if [ -f "/usr/share/vcpkg/scripts/buildsystems/vcpkg.cmake" ]; then
                vr="/usr/share/vcpkg"
            else
                echo -e "${RED}ERROR: vcpkg binary found but cannot locate vcpkg root directory.${RESET}" >&2
                exit 1
            fi
        fi
        write_state VCPKG_ROOT "$vr"
        return 0
    else
        local vr="$(pwd)/deps/vcpkg"
        if [ ! -f "$vr/vcpkg" ]; then
            clear_ui
            read -rp "Proceed with vcpkg installation? [y/N] " answer </dev/tty
            setup_ui
            if [[ ! "$answer" =~ ^[Yy]$ ]]; then
                echo -e "${RED}Aborted. Please install vcpkg manually.${RESET}" >&2
                exit 1
            fi
        fi
        write_state VCPKG_ROOT "$vr"
    fi
}

do_vcpkg_setup() {
    if [ ! -f "$VCPKG_ROOT/vcpkg" ] && [[ "$VCPKG_ROOT" == *"deps/vcpkg"* ]]; then
        mkdir -p deps
        git clone --depth 1 https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
        "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
    fi
    write_state VCPKG_FORCE_SYSTEM_BINARIES 1
    write_state VCPKG_TOOLCHAIN "$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
    write_state VCPKG_TRIPLET "x64-linux-static"
    write_state OVERLAY_TRIPLETS "$(pwd)/triplets"
}

do_cppcheck() {
    cmake -S . -B build -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$VCPKG_TOOLCHAIN" \
        -DVCPKG_TARGET_TRIPLET="$VCPKG_TRIPLET" \
        -DVCPKG_OVERLAY_TRIPLETS="$OVERLAY_TRIPLETS" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBYEBYEVPN_ENABLE_TESTS=OFF \
        -DBYEBYEVPN_WARNINGS_AS_ERRORS=ON \
        "$STATIC_FLAG"
        
    cppcheck --std=c++20 --enable=warning,style,performance,portability \
        --error-exitcode=1 --inline-suppr --quiet src
}

do_clangtidy() {
    run-clang-tidy -p build -j $(nproc) \
        -checks='clang-analyzer-*,clang-diagnostic-*' -warnings-as-errors='*'
}

do_build_debug() {
    cmake --build build --parallel
    mkdir -p staging
    cp build/byebyevpn staging/
}

do_cov() {
    cmake -S . -B build-cov -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$VCPKG_TOOLCHAIN" \
        -DVCPKG_TARGET_TRIPLET="$VCPKG_TRIPLET" \
        -DVCPKG_OVERLAY_TRIPLETS="$OVERLAY_TRIPLETS" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBYEBYEVPN_ENABLE_TESTS=ON \
        -DBYEBYEVPN_WARNINGS_AS_ERRORS=ON \
        -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate" \
        "$STATIC_FLAG"

    cmake --build build-cov --parallel

    mkdir -p build-cov/profiles
    export LLVM_PROFILE_FILE="$(pwd)/build-cov/profiles/byebyevpn_tests-%p.profraw"
    ctest --test-dir build-cov --output-on-failure --parallel "$TEST_PARALLEL_JOBS"

    llvm-profdata merge -sparse build-cov/profiles/*.profraw -o build-cov/coverage.profdata
    llvm-cov export -format=lcov \
        -instr-profile=build-cov/coverage.profdata \
        -ignore-filename-regex='.*/(_deps|tests|build-cov)/.*' \
        build-cov/tests/byebyevpn_tests > coverage.info

    llvm-cov show \
        -format=html \
        -output-dir=coverage-html \
        -instr-profile=build-cov/coverage.profdata \
        -ignore-filename-regex='.*/(_deps|tests|build-cov)/.*' \
        build-cov/tests/byebyevpn_tests
}

run_sanitizer() {
    local SAN=$1
    $CONTAINER_ENGINE run -i --rm "${CONTAINER_NETWORK_ARGS[@]}" --privileged \
        -v "$(pwd):/workspace" -w /workspace "$CONTAINER_IMAGE" \
        bash -s "$SAN" "$OPENSSL_VERSION" "$STATIC_FLAG" << 'EOF'
set -euo pipefail

SAN=$1
OPENSSL_VERSION=$2
STATIC_FLAG=$3

export CC=clang
export CXX=clang++

apt-get update -y && apt-get install -y perl make curl

OPENSSL_PREFIX="/workspace/deps/openssl-${SAN}-${OPENSSL_VERSION}"
LIBCXX_ROOT="/opt/libcxx_${SAN//-/_}"
BUILD_DIR="build-${SAN}"

case "$SAN" in
    asan-ubsan)
        SAN_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
        CMAKE_SAN_FLAGS="-DBYEBYEVPN_ENABLE_ASAN=ON -DBYEBYEVPN_ENABLE_UBSAN=ON"
        ;;
    tsan)
        SAN_FLAGS="-fsanitize=thread -fno-omit-frame-pointer"
        CMAKE_SAN_FLAGS="-DBYEBYEVPN_ENABLE_TSAN=ON"
        ;;
    msan)
        SAN_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer"
        CMAKE_SAN_FLAGS="-DBYEBYEVPN_ENABLE_MSAN=ON"
        ;;
esac

if [ ! -d "$OPENSSL_PREFIX" ]; then
    mkdir -p "/workspace/deps"
    if [ ! -f "/workspace/deps/openssl-${OPENSSL_VERSION}.tar.gz" ]; then
        curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o "/workspace/deps/openssl-${OPENSSL_VERSION}.tar.gz"
    fi
    rm -rf "/workspace/deps/openssl-${OPENSSL_VERSION}"
    tar -xzf "/workspace/deps/openssl-${OPENSSL_VERSION}.tar.gz" -C "/workspace/deps"

    cd "/workspace/deps/openssl-${OPENSSL_VERSION}"
    export CFLAGS="$SAN_FLAGS"
    export CXXFLAGS="$SAN_FLAGS"
    export LDFLAGS="$SAN_FLAGS"
    ./Configure linux-x86_64 no-shared no-tests no-module no-asm \
        --prefix="$OPENSSL_PREFIX" \
        --openssldir="$OPENSSL_PREFIX/ssl"
    make -j"$(nproc)"
    make install_sw
    cd /workspace
fi

cmake -S . -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBYEBYEVPN_ENABLE_TESTS=ON \
    $CMAKE_SAN_FLAGS \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DBYEBYEVPN_WARNINGS_AS_ERRORS=ON \
    "$STATIC_FLAG" \
    -DCMAKE_CXX_FLAGS="${SAN_FLAGS} -stdlib=libc++ -isystem ${LIBCXX_ROOT}/include/c++/v1" \
    -DCMAKE_EXE_LINKER_FLAGS="${SAN_FLAGS} -stdlib=libc++ -L${LIBCXX_ROOT}/lib -Wl,-rpath,${LIBCXX_ROOT}/lib"

PARALLEL_JOBS=$(( $(nproc) / 2 ))
[ "$PARALLEL_JOBS" -lt 1 ] && PARALLEL_JOBS=1
cmake --build "$BUILD_DIR" --parallel "$PARALLEL_JOBS"

export LD_LIBRARY_PATH="${LIBCXX_ROOT}/lib:${LD_LIBRARY_PATH:-}"
ctest --test-dir "$BUILD_DIR" --output-on-failure --parallel "$PARALLEL_JOBS"
EOF
}

do_asan() { run_sanitizer "asan-ubsan"; }
do_tsan() { run_sanitizer "tsan"; }
do_msan() { run_sanitizer "msan"; }

do_win_build() {
    cmake -S . -B build-win -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$VCPKG_TOOLCHAIN" \
        -DVCPKG_TARGET_TRIPLET="x64-mingw-static" \
        -DCMAKE_SYSTEM_NAME=Windows \
        -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
        -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
        -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
        -DCMAKE_EXE_LINKER_FLAGS="-static" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBYEBYEVPN_ENABLE_TESTS=ON \
        -DBYEBYEVPN_WARNINGS_AS_ERRORS=ON \
        "$STATIC_FLAG"

    cmake --build build-win --parallel

    mkdir -p staging/windows-Release
    if [ -f build-win/byebyevpn.exe ]; then
        cp build-win/byebyevpn.exe staging/windows-Release/
    fi
}

do_win_test() {
    if [ "$TEST_CMD" == "skip" ]; then
        return 0
    fi
    if [ -n "$TEST_CMD" ] && [ "$TEST_CMD" != "native" ]; then
        $TEST_CMD build-win/tests/byebyevpn_tests.exe
    else
        build-win/tests/byebyevpn_tests.exe
    fi
}

# --- Main Execution ---

echo -e "${BOLD}${CYAN}ByeByeVPN Local Build${RESET}"
echo -e "=================================================="

echo -e "${BOLD}${YELLOW}WARNING: local_build.sh is deprecated and outdated.${RESET}" >&2
echo -e "${YELLOW}Please use the Python version instead: ${BOLD}python3 local_build.py${RESET}" >&2
echo -e "${DIM}This script will be removed in a future release.${RESET}" >&2
echo >&2

setup_ui
draw_ui

check_vcpkg_prompt

TEST_CMD="native"
if [ "$BUILD_WINDOWS" -eq 1 ]; then
    if grep -qi "microsoft" /proc/version 2>/dev/null || [ -n "${WSL_DISTRO_NAME:-}" ] || [ -n "${WSL_INTEROP:-}" ]; then
        clear_ui
        read -rp "Is it okay to proceed and run unit tests directly? (y/n) " answer </dev/tty
        setup_ui
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            TEST_CMD=""
        else
            if command -v wine &>/dev/null; then TEST_CMD="wine"; else TEST_CMD="skip"; fi
        fi
    else
        if command -v wine &>/dev/null; then TEST_CMD="wine"; else TEST_CMD="skip"; fi
    fi
    
    if [ "$TEST_CMD" == "skip" ]; then
        for i in "${!STAGE_KEYS[@]}"; do
            if [ "${STAGE_KEYS[$i]}" == "win_test" ]; then
                STAGE_STATUS[$i]="SKIP"
            fi
        done
    fi
fi
write_state TEST_CMD "$TEST_CMD"
draw_ui

for i in "${!STAGES[@]}"; do
    run_stage $i
done

final_summary
