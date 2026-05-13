#!/bin/bash
set -euo pipefail

KEEP_ARTIFACTS=0

for arg in "$@"; do
    case $arg in
        --keep)
        KEEP_ARTIFACTS=1
        shift
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

# Config
OPENSSL_VERSION="3.3.2"
PODMAN_IMAGE="localhost/helpers/sans:latest"
STATIC_FLAG="-DBYEBYEVPN_STATIC=OFF"

export CC=clang
export CXX=clang++

echo "Running static analysis..."
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBYEBYEVPN_ENABLE_TESTS=OFF \
    -DBYEBYEVPN_WARNINGS_AS_ERRORS=ON \
    "$STATIC_FLAG"

cppcheck --std=c++20 --enable=warning,style,performance,portability \
    --error-exitcode=1 --inline-suppr --quiet src

# Run clang-tidy if cpp files exist
CPP_FILES=$(find src -name '*.cpp' -print)
if [ -n "$CPP_FILES" ]; then
    clang-tidy -p build --checks='clang-analyzer-*,clang-diagnostic-*' -warnings-as-errors='*' $CPP_FILES
fi

echo "Building debug artifacts..."
cmake --build build --parallel
mkdir -p staging
cp build/byebyevpn staging/

echo "Running coverage..."
cmake -S . -B build-cov -G Ninja \
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

echo "Running sanitizers via Podman..."
for SAN in asan-ubsan tsan msan; do
    echo "Running ${SAN}..."
    podman run -i --rm --network=host --privileged -v "$(pwd):/workspace" -w /workspace "$PODMAN_IMAGE" bash -s "$SAN" "$OPENSSL_VERSION" "$STATIC_FLAG" << 'EOF'
set -euo pipefail

SAN=$1
OPENSSL_VERSION=$2
STATIC_FLAG=$3

export CC=clang
export CXX=clang++

# Install OpenSSL build deps
apt-get update -y && apt-get install -y perl make curl

OPENSSL_PREFIX="/workspace/deps/openssl-${SAN}"
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

cmake --build "$BUILD_DIR" --parallel

export LD_LIBRARY_PATH="${LIBCXX_ROOT}/lib:${LD_LIBRARY_PATH:-}"
ctest --test-dir "$BUILD_DIR" --output-on-failure
EOF

done

echo "Local CI run finished successfully."
