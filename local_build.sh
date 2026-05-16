#!/bin/bash
set -euo pipefail

KEEP_ARTIFACTS=0

while [ $# -gt 0 ]; do
    case $1 in
        --keep)
        KEEP_ARTIFACTS=1
        shift
        ;;
        *)
        echo "Unknown option: $1" >&2
        echo "Usage: $0 [--keep]" >&2
        exit 2
        ;;
    esac
done

cleanup() {
    if [ "$KEEP_ARTIFACTS" -eq 1 ]; then
        echo "Skipping cleanup (--keep flag provided)."
        return 0
    fi

    echo "Cleaning up build artifacts..."
    rm -rf build staging build-cov coverage.info coverage-html \
           deps build-asan-ubsan build-tsan build-msan
}

trap cleanup EXIT

# --- Container engine discovery ---
CONTAINER_ENGINE=""
if command -v podman &>/dev/null; then
    CONTAINER_ENGINE="podman"
elif command -v docker &>/dev/null; then
    CONTAINER_ENGINE="docker"
else
    echo "ERROR: Neither podman nor docker is installed. Please install one of them." >&2
    exit 1
fi
echo "Using container engine: $CONTAINER_ENGINE"

# --- TUN interface check ---
CONTAINER_NETWORK_ARGS=()
if [ ! -e /dev/net/tun ]; then
    echo "TUN interface not available, using --network=host for containers."
    CONTAINER_NETWORK_ARGS+=(--network=host)
fi

# --- vcpkg setup ---
if [ -n "${VCPKG_ROOT:-}" ] && [ -d "$VCPKG_ROOT" ]; then
    echo "Using existing vcpkg at: $VCPKG_ROOT"
elif command -v vcpkg &>/dev/null; then
    VCPKG_ROOT="$(dirname "$(command -v vcpkg)")"
    if [ ! -f "$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ]; then
        # System package managers (dnf, apt) install vcpkg data to /usr/share/vcpkg
        if [ -f "/usr/share/vcpkg/scripts/buildsystems/vcpkg.cmake" ]; then
            VCPKG_ROOT="/usr/share/vcpkg"
        else
            echo "ERROR: vcpkg binary found but cannot locate vcpkg root directory." >&2
            echo "Please set the VCPKG_ROOT environment variable." >&2
            exit 1
        fi
    fi
    echo "Found vcpkg in PATH, using: $VCPKG_ROOT"
else
    VCPKG_ROOT="$(pwd)/deps/vcpkg"
    if [ ! -f "$VCPKG_ROOT/vcpkg" ]; then
        echo "vcpkg not found. It will be cloned and bootstrapped into $VCPKG_ROOT."
        read -rp "Proceed with vcpkg installation? [y/N] " answer
        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
            echo "Aborted. Please install vcpkg manually or set VCPKG_ROOT." >&2
            exit 1
        fi
        mkdir -p deps
        git clone --depth 1 https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
        "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
    else
        echo "Using previously cloned vcpkg at: $VCPKG_ROOT"
    fi
fi
export VCPKG_ROOT
export VCPKG_FORCE_SYSTEM_BINARIES=1

VCPKG_TOOLCHAIN="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
VCPKG_TRIPLET="x64-linux-static"
OVERLAY_TRIPLETS="$(pwd)/triplets"

# --- Check build prerequisites ---
MISSING_DEPS=()

if ! command -v perl &>/dev/null; then
    MISSING_DEPS+=("perl")
else
    if ! perl -e 'use IPC::Cmd;' &>/dev/null; then
        MISSING_DEPS+=("perl-IPC-Cmd (Fedora/RHEL) or libperl-dev (Debian/Ubuntu)")
    fi
    if ! perl -e 'use FindBin;' &>/dev/null; then
        MISSING_DEPS+=("perl-FindBin (Fedora/RHEL)")
    fi
fi

if [ ! -d /usr/include/linux ]; then
    MISSING_DEPS+=("kernel-headers (Fedora/RHEL) or linux-libc-dev (Debian/Ubuntu)")
fi

if ! command -v make &>/dev/null; then
    MISSING_DEPS+=("make")
fi

if ! command -v cmake &>/dev/null; then
    MISSING_DEPS+=("cmake")
fi

if ! command -v ninja &>/dev/null; then
    MISSING_DEPS+=("ninja-build")
fi

if ! command -v clang &>/dev/null; then
    MISSING_DEPS+=("clang")
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "ERROR: The following system dependencies are missing:" >&2
    for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep" >&2
    done
    echo "" >&2
    echo "Please install them via your system package manager before running this script." >&2
    exit 1
fi

# Config
OPENSSL_VERSION="3.5.6"
CONTAINER_IMAGE="localhost/helpers/sans:latest"
STATIC_FLAG="-DBYEBYEVPN_STATIC=OFF"

export CC=clang
export CXX=clang++

echo "Running static analysis..."
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

# Run clang-tidy on cpp files (NUL-delimited to handle paths with whitespace)
find src -name '*.cpp' -print0 | xargs -0 -r clang-tidy -p build \
    --checks='clang-analyzer-*,clang-diagnostic-*' -warnings-as-errors='*'

echo "Building debug artifacts..."
cmake --build build --parallel
mkdir -p staging
cp build/byebyevpn staging/

echo "Running coverage..."
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
ctest --test-dir build-cov --output-on-failure

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

echo "Running sanitizers via $CONTAINER_ENGINE..."
for SAN in asan-ubsan tsan msan; do
    echo "Running ${SAN}..."
    $CONTAINER_ENGINE run -i --rm "${CONTAINER_NETWORK_ARGS[@]}" --privileged \
        -v "$(pwd):/workspace" -w /workspace "$CONTAINER_IMAGE" \
        bash -s "$SAN" "$OPENSSL_VERSION" "$STATIC_FLAG" << 'EOF'
set -euo pipefail

SAN=$1
OPENSSL_VERSION=$2
STATIC_FLAG=$3

export CC=clang
export CXX=clang++

# Install OpenSSL build deps
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

# Cache OpenSSL locally
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

# Build and test project with sanitizers
cmake -S . -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBYEBYEVPN_ENABLE_TESTS=ON \
    $CMAKE_SAN_FLAGS \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DBYEBYEVPN_WARNINGS_AS_ERRORS=ON \
    "$STATIC_FLAG" \
    -DCMAKE_CXX_FLAGS="${SAN_FLAGS} -stdlib=libc++ -isystem ${LIBCXX_ROOT}/include/c++/v1" \
    -DCMAKE_EXE_LINKER_FLAGS="${SAN_FLAGS} -stdlib=libc++ -L${LIBCXX_ROOT}/lib -Wl,-rpath,${LIBCXX_ROOT}/lib"

# MSan/ASan/TSan inflate memory 3-5x per TU; cap parallelism to avoid OOM crashes
PARALLEL_JOBS=$(( $(nproc) / 2 ))
[ "$PARALLEL_JOBS" -lt 1 ] && PARALLEL_JOBS=1
cmake --build "$BUILD_DIR" --parallel "$PARALLEL_JOBS"

export LD_LIBRARY_PATH="${LIBCXX_ROOT}/lib:${LD_LIBRARY_PATH:-}"
ctest --test-dir "$BUILD_DIR" --output-on-failure
EOF

done

echo "Local CI run finished successfully."
