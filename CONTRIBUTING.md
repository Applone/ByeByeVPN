# ByeByeVPN Contributing Guide

Welcome, and thank you for contributing! 🎉

ByeByeVPN is a highly optimized, cross-platform **C++20** network profiler. The bar
for merged code is deliberately high: it must be modern, fast, and pass every static
analyzer, sanitizer, and test **without a single warning or error**. This document
explains exactly what that means and how to get there.

---

## Overview

**Readable > Useful > High performance but poorly readable.**

Truly readable code is more than just clear — it's understandable even without context
(**contextless readability**). In a codebase full of raw sockets, OpenSSL handles, and
hand-rolled wire formats, that discipline is what keeps the project maintainable.

---

## The non-negotiables

These are enforced by CI and by `local_build.py`. A PR that violates any of them will
not pass review.

1. **C++20, no compiler extensions.** `CMAKE_CXX_STANDARD` is `20` and
   `CMAKE_CXX_EXTENSIONS` is `OFF`. Write portable standard C++.
2. **Rule of Zero. No custom destructors. Ever.** Resources are owned by RAII types
   built on `std::unique_ptr` with a deleter; you never write `~Foo()`.
3. **Zero warnings, zero errors, everywhere.** clang-tidy runs with
   `WarningsAsErrors: '*'`, and the compilers run with `-Werror` / `/WX`. cppcheck,
   ASan+UBSan, TSan, MSan, and the unit tests must all be green.
4. **Event-driven scanning is `epoll` (Linux) or `IOCP` (Windows).** The many-socket
   connect-scan event loop never uses `poll`, and `WSAPoll` is forbidden outright.
5. **Hot-path / wire parsing is allocation-free.** Parse over `std::string_view` and
   `std::span`, into fixed `std::array` buffers, using index cursors — not freshly
   allocated owning containers.
6. **Run `local_build.py` before you open a PR.** No exceptions.

---

## Coding Details

### Common guidelines

* Use **English** for all comments.
* Stay **polite** in code comments. You can be grumpy, but express it with **decent
  wording**.
* Comments explain **why**, not **what**. If a line needs a comment to say what it does,
  rename things until it doesn't. Comments earn their place by capturing a decision the
  reader cannot see in the code, e.g. from `tls_probe.cpp`:

  ```cpp
  // IP SANs intentionally ignored - SNI consistency matches DNS names only
  ```

* **Redundant comments are as useless as this sentence.**
* Avoid **confusing abbreviations**. `dialer`, not `dl`.
* Strive for **readability through naming**, not excessive comments.
* Use **named constants**, never bare magic numbers. Constants are
  `inline constexpr`, `k`-prefixed, and live in an anonymous namespace or a config
  namespace (`vpn_probes.cpp`):

  ```cpp
  inline constexpr std::size_t kWireGuardPacketSize{148};
  inline constexpr std::size_t kWireGuardRandomOffset{4};
  inline constexpr int          kProbeTimeoutMs{1500};
  ```

---

## C++20 standards

### Use the modern toolbox

The codebase leans hard on C++20. Prefer these over their legacy equivalents:

* `std::ranges` algorithms over raw loops and iterator pairs:

  ```cpp
  std::ranges::sort(open, [](const TcpOpen& a, const TcpOpen& b) { return a.port < b.port; });
  if (std::ranges::find(v4_ips, ip) == v4_ips.end()) { /* ... */ }
  ```

* `std::span` and `std::string_view` for non-owning views into buffers and strings.
  Read-only string parameters are `std::string_view`; byte buffers are `std::span`:

  ```cpp
  [[nodiscard]] bool fill_random(std::span<unsigned char> data) noexcept;
  [[nodiscard]] UdpResult wireguard_probe(std::string_view host, int port);
  ```

* `std::jthread` + `std::stop_token` for cancellable workers — never a bare
  `std::thread` you have to remember to join (`tcp_async_scan.cpp`):

  ```cpp
  workers_.emplace_back([this](const std::stop_token& stoken) {
      while (true) {
          if (!cv_.wait(lock, stoken, [this] { return !tasks_.empty(); })) {
              return;
          }
          /* ... */
      }
  });
  ```

* `std::cmp_less` / `std::cmp_equal` for mixed signed/unsigned comparisons, so the
  `-Wsign-compare` family stays silent:

  ```cpp
  while (next_idx < ports.size() && std::cmp_less(active.size(), max_inflight)) { /* ... */ }
  ```

* **Concepts** to constrain templates instead of unconstrained `typename T`
  (`utils.h`, `socket_sys.h`):

  ```cpp
  template<typename T>
  concept StringLike = std::convertible_to<T, std::string_view>;
  ```

* Brace initialization throughout: `int day{0};`, `std::array<char, 512> buf{};`,
  `sockaddr_in sa{};`. It zero-initializes and rejects narrowing.

### `[[nodiscard]]`, `constexpr`, `consteval`

* **`[[nodiscard]]` is the default** for any function that returns a value the caller
  must inspect — which is nearly all of them. Probes, parsers, and predicates all carry
  it. If you add a function that returns a result or an error, mark it `[[nodiscard]]`.

* **`constexpr` everything that can be.** Compile-time tables and helpers are
  `constexpr` so they cost nothing at runtime (`orchestrator.cpp`):

  ```cpp
  constexpr std::array<int, 8> kHttpPorts{{80, 81, 8080, 8081, 8088, 8888, 3128, 8000}};

  template <size_t N>
  [[nodiscard]] constexpr bool in_ports(const int port, const std::array<int, N>& ports) noexcept {
      return std::ranges::find(ports, port) != ports.end();
  }
  ```

* **`consteval`** is the right tool when a computation *must* happen at compile time
  (e.g. building a fixed lookup table or validating a literal). Reach for it where you
  want to guarantee no runtime evaluation can sneak in. Don't sprinkle it where plain
  `constexpr` already does the job.

* Add `noexcept` to leaf utilities and anything that genuinely cannot throw — the
  RAII deleters, predicates, and platform shims all do.

---

## Memory management — the Rule of Zero

**This is the rule contributors most often get wrong, so read it twice.**

Every type that owns a resource expresses that ownership through a member that already
knows how to clean itself up — almost always a `std::unique_ptr` with a custom deleter.
You do **not** write a destructor, a copy constructor, a copy assignment operator, or
their move counterparts. The compiler-generated ones are correct because every member is
already self-cleaning.

### The pattern: deleter + `unique_ptr` alias

Wrapping a C API handle (OpenSSL, addrinfo, sockets) looks like this every single time
(`tls_probe.cpp`):

```cpp
// RAII wrapper for SSL_CTX
struct SslCtxDeleter {
    void operator()(SSL_CTX* ctx) const noexcept {
        if (ctx) SSL_CTX_free(ctx);
    }
};
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
```

Use it and forget about cleanup — the handle is freed on every return path, including
exceptions:

```cpp
SSL_CTX* raw_ctx{SSL_CTX_new(TLS_client_method())};
if (!raw_ctx) {
    r.err = "ssl_ctx_new";
    return r;          // nothing leaked: there is nothing to free yet
}
SslCtxPtr ctx{raw_ctx};
// ... 200 lines of early returns ...
// ctx frees the context automatically; no manual SSL_CTX_free anywhere
```

Sockets follow the same model via `SocketGuard` (`socket_sys.h`), which is itself a
thin wrapper over `std::unique_ptr<SocketHandle, SocketDeleter>`:

```cpp
SocketGuard socket_guard{s};   // closesocket(s) happens on scope exit, always
```

For one-off cleanup you can use a `unique_ptr` with a lambda deleter rather than a named
struct (`main.cpp`):

```cpp
struct OpenSSLGuard {
    std::unique_ptr<void, decltype([](void*){
        openssl_runtime_cleanup();
        fflush(stdout);
        fflush(stderr);
    })> guard{this};
};
```

### What this buys you

Because cleanup rides on member destruction, functions can `return` early at the first
sign of an error without a single `goto cleanup:` or manual free. That is *why* the hot
paths in `tcp_async_scan.cpp` can bail out of `launch_connect` at any of a dozen points
and never leak a socket — the `SocketGuard` does it.

### What is forbidden

* `~ClassName()` — if you find yourself writing one, you are managing a resource by hand.
  Wrap that resource in a `unique_ptr` + deleter instead.
* Raw `new`/`delete` for ownership.
* `malloc`/`free` outside of interop with a C API that demands it (and then it goes
  behind a deleter immediately).

---

## Networking — `epoll` and `IOCP` only

The asynchronous connect-scanner multiplexes thousands of in-flight sockets. That
multiplexing is done with **`epoll` on Linux** (`scan_connect_worker_epoll`) and
**`IOCP` on Windows** (`scan_connect_worker_iocp`), selected at compile time:

```cpp
#ifdef _WIN32
    return scan_connect_worker_iocp(/* ... */);
#else
    return scan_connect_worker_epoll(/* ... */);
#endif
```

* **`WSAPoll` is forbidden.** It has well-known correctness bugs and does not scale; do
  not introduce it under any circumstances.
* **Do not add `poll()` to the connection-multiplexing event loop.** The scalable
  many-socket path is `epoll`/`IOCP`, full stop. (The Linux raw-socket SYN receiver
  waits on a *single* file descriptor — and it too uses `epoll`. There is no `poll()`
  anywhere; do not introduce one.)
* Sockets are non-blocking (`set_nonblocking`), connect errors are classified
  explicitly (`is_connect_in_progress_error`, `is_refused_error`), and every socket is
  owned by a `SocketGuard` so a mid-scan abort leaks nothing.

Cross-platform socket code goes through the shim in `socket_sys.h`, which aliases
`SOCKET`, `closesocket`, `WSAGetLastError`, and the `WSAE*` error codes onto their POSIX
equivalents so the worker bodies read almost identically on both platforms.

---

## Parsing — zero allocation on the hot path

Wire parsing and probe construction must not allocate. The patterns to use:

* Parse over `std::string_view` and index cursors, slicing with `substr`/`find`
  instead of copying (`tls_probe.cpp`):

  ```cpp
  [[nodiscard]] std::string extract_cn_from_subject(std::string_view subj) {
      const auto p{subj.find("CN=")};
      if (p == std::string_view::npos) return {};
      const auto start{p + 3};
      const auto e{subj.find_first_of("/,", start)};
      return std::string{subj.substr(start, e == std::string_view::npos ? std::string_view::npos : e - start)};
  }
  ```

* Build and inspect packets in fixed `std::array` buffers over `std::span`, never a
  `std::vector` you grow byte by byte (`vpn_probes.cpp`):

  ```cpp
  std::array<unsigned char, kWireGuardPacketSize> pkt{};
  pkt.at(0) = 0x01;  // MessageInitiation
  if (!fill_random(std::span{pkt.data() + kWireGuardRandomOffset, kWireGuardRandomSize})) {
      return make_rng_error();
  }
  ```

* When you must touch raw bytes, `reinterpret_cast` to the right header type and read
  fields in place (the relevant clang-tidy `reinterpret-cast` check is disabled for
  exactly this reason). Bounds-check with `std::cmp_less` against the buffer length
  before dereferencing.

The structured JSON used for GeoIP responses (`json_get_str` in `utils.cpp`) is *not* a
hot path and is allowed owning containers — keep that distinction in mind, but default
to allocation-free for anything on the scanning path.

---

## Bounds, casts, and `NOLINT`

* Prefer `.at()` over `operator[]` for indexed access — the cppcoreguidelines bounds
  checks are on. When you have *measured* that `operator[]` is needed and proven the
  index safe, suppress the check **narrowly and with a reason**, as in `main.cpp`:

  ```cpp
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
  if (pos.size() >= 2 && cmds.count(pos[0])) { /* ... */ }
  // NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
  ```

* Every suppression names the exact check and is as tight as possible. A bare
  `// NOLINT` with no check name will not pass review. The same applies to
  `cppcheck-suppress`, which must carry a justification comment.

---

## Error handling

* Hot paths return result structs carrying an `err` field rather than throwing
  (`TlsProbe`, `UdpResult`, `Resolved`, `WorkerResult`). Callers check `ok` / `err`.
* Exceptions are caught at the top level only — `main()` wraps `main_impl` in a
  `try/catch` that turns any escapee into a clean non-zero exit. Do not let exceptions
  drive control flow inside the scanners.
* Follow the existing root-cause discipline: don't paper over a failure with a fallback
  branch or a nil guard before you understand why it happened.

---

## Tests

* Tests use **Catch2 v3** (`TEST_CASE` / `REQUIRE` / `SECTION`), live in `tests/`, and
  are registered in `tests/CMakeLists.txt`. CTest shards the suite across cores.
* Add tests for new networking, parsing, and utility code. Keep them hermetic — the DNS
  tests, for example, only rely on loopback and IP-literal behavior:

  ```cpp
  TEST_CASE("resolve_host bypasses DNS for IP literals") {
      const auto v4 = resolve_host("127.0.0.1");
      REQUIRE(v4.err.empty());
      REQUIRE(v4.family == "v4");
      REQUIRE(v4.primary_ip == "127.0.0.1");
  }
  ```

* The full suite must pass clean under **ASan+UBSan, TSan, and MSan**. Threading code
  (the `ThreadPool`, the atomics in the scan workers) is held to TSan-clean; data shared
  across workers uses `std::atomic` with explicit memory orders, as it already does.

---

## Before you open a PR

Run the full local pipeline. It reproduces CI: dependency checks, vcpkg setup, cppcheck,
clang-tidy, debug build, coverage build + tests, and the three sanitizer matrices
(asan-ubsan, tsan, msan), plus the Windows cross-build where applicable.

```bash
python3 local_build.py
```

It must finish with **every stage green**. If a stage fails, fix the root cause — do not
disable the check. A PR is ready when:

* [ ] `python3 local_build.py` passes every stage with zero warnings and zero errors.
* [ ] No custom destructors, no raw `new`/`delete` ownership.
* [ ] New public functions are `[[nodiscard]]` where appropriate; constants are named.
* [ ] Any `NOLINT` / `cppcheck-suppress` is narrow and justified.
* [ ] New behavior is covered by Catch2 tests, and they pass under all sanitizers.
* [ ] The change reads like the surrounding code.

Thank you for keeping ByeByeVPN modern, fast, and clean. 🚀
