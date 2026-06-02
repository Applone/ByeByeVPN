# AGENTS.md

> You are an LLM about to touch a highly optimized **C++20** codebase. Read this whole
> file **the first time** you are asked to do anything here. Yes, all of it. The CI
> pipeline has read it too, and it is less forgiving than I am.

## TL;DR for the impatient transformer

This repo is a cross-platform C++20 network profiler. The maintainer is a Rule-of-Zero
zealot with a `-Werror` habit and three sanitizers on speed-dial. If you hallucinate a
custom destructor, a `WSAPoll`, or a `std::vector` in a hot parse loop, the build will
reject your tokens before a human ever sees them, and you will have achieved nothing but
warming the planet.

Be like the code that's already here. Don't be a tourist.

---

## Code Style

See [CONTRIBUTING](./CONTRIBUTING.md) — read it, don't skim it. The human rules and the
agent rules are the same rules; this file just says them louder and with more threats.

## Build

See [README](./README.md) for the CMake/Ninja invocation. The validation pipeline is
`local_build.py` (more on that below, in the section you will pretend you read).

---

## Basic rules (these are about your character, not your C++)

- **Pride in respecting the existing, shame in disrupting coherence.** Match the style,
  naming, comment density, and architecture already in the files. This codebase has a
  voice. Do not staple your own dialect onto it.
- **Pride in being small and concise, shame in shitting everywhere.** Clean code needs
  no apology comments. Do not narrate the obvious. Do not leave "pop comments" like
  `// increment i` lying around like wrappers after lunch.
- **Pride in elegant taste, shame in over-design.** Have taste, like Linus. Internal
  code does not need defensive validity checks on every line. A clear, simple
  architecture beats reciting "industry best practices."
- **Pride in admitting ignorance, shame in wild fabrication.** Your training data is
  finite and this codebase is specific. If you don't know how something works here,
  **go read the file** — `grep`, open it, trace it. Do not invent an API that "sounds
  right." A fabricated `epoll` flag is worse than an honest "let me check."
- **Pride in diligence, shame in laziness.** If asked to search, actually search. If
  pointed at a file, actually open it. Do not claim you read `tcp_async_scan.cpp` and
  then propose something it already does the opposite of.
- **Pride in root-cause clarity, shame in workaround bias.** Fix the cause, not the
  symptom. No nil-guards, no fallback branches, no "temporary" hacks bolted on before
  you understand the failure.
- **Pride in explicit planning, shame in silent mutation.** State your plan before you
  start editing across files. Don't silently refactor half the network layer because you
  felt inspired.
- **Pride in neither humble nor arrogant, shame in saying "You are absolutely right!"**
  Acknowledge a mistake and quietly fix it. Don't grovel. 千夫诺诺，不如一士谔谔.

---

## The Six Commandments (the ones CI will physically enforce)

These are not vibes. Each is checked by a tool. Break one and the pipeline turns red
before your PR draws a human breath.

### 1. C++20, no extensions

`CMAKE_CXX_STANDARD 20`, `CMAKE_CXX_EXTENSIONS OFF`. Use the modern toolbox the rest of
the code already uses: `std::ranges`, `std::span`, `std::string_view`, `std::jthread` +
`std::stop_token`, `std::cmp_less`/`std::cmp_equal`, concepts, brace-init everywhere.
If your instinct is a raw `for (int i = 0; ...)` over a container, the instinct is from
2011. Check whether a ranges algorithm says it in one line.

### 2. Rule of Zero. Write a destructor and you die.

**There is not a single `~Foo()` in this entire tree, and you will not be the one to add
the first.** Resources are owned by `std::unique_ptr` + a deleter struct/lambda. The
compiler writes the special members; you write none of them.

The pattern, which appears verbatim a dozen times (`tls_probe.cpp`, `socket_sys.h`):

```cpp
struct SslCtxDeleter {
    void operator()(SSL_CTX* ctx) const noexcept { if (ctx) SSL_CTX_free(ctx); }
};
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
```

Then you just `return` on any error path and nothing leaks. If you catch yourself
reaching for `~Connection()` or a manual `closesocket` in a cleanup block, stop: wrap the
handle in a `SocketGuard` (which is itself a `unique_ptr<SocketHandle, SocketDeleter>`)
and let scope exit do the work. Hallucinating a "helpful" destructor here is the single
fastest way to get your diff rejected and your reputation downgraded to "the model that
doesn't read AGENTS.md."

### 3. Zero warnings. Zero errors. From everyone.

- clang-tidy: `WarningsAsErrors: '*'` (see `.clang-tidy`). A *warning* is an *error*.
- compilers: `-Werror` / `/WX`.
- cppcheck, ASan+UBSan, TSan, MSan, the Catch2 suite, and a coverage build all run.

There is no "mostly passing." A single MSan use-of-uninitialized, one TSan race, one
unused-variable, one narrowing conversion — any of these is a full stop. Don't silence a
check to make it pass; fix the cause. If you genuinely must suppress, do it **narrowly,
by name, with a reason**:

```cpp
// NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
if (pos.size() >= 2 && cmds.count(pos[0])) { /* ... */ }
// NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
```

A bare `// NOLINT` with no check name is a confession that you gave up. It will be
treated as such.

### 4. `epoll` or `IOCP`. `WSAPoll` is a war crime.

The many-socket connect-scanner multiplexes with **`epoll` on Linux**
(`scan_connect_worker_epoll`) and **`IOCP` on Windows** (`scan_connect_worker_iocp`),
chosen by `#ifdef _WIN32`.

- **Never** write `WSAPoll`. Not as a "simpler Windows port," not "just for now."
- **Never** add `poll()` to the connection event loop. (Even the *single* raw SYN-receive
  fd waits on `epoll`. There is no `poll()` in the tree, and it stays that way.)

If you propose porting the IOCP path to `WSAPoll` because it's "more portable," the CI
won't even get the chance to fail you — the maintainer will, with prejudice.

### 5. Parse with zero allocations.

Wire formats and probes are parsed over `std::string_view` / `std::span` into fixed
`std::array` buffers with index cursors. No growing a `std::vector` byte by byte on the
hot path.

```cpp
std::array<unsigned char, kWireGuardPacketSize> pkt{};
pkt.at(0) = 0x01;  // MessageInitiation
fill_random(std::span{pkt.data() + kWireGuardRandomOffset, kWireGuardRandomSize});
```

`std::string_view::substr`/`find` to slice, not `std::string` copies. (The GeoIP JSON
helper in `utils.cpp` is *not* a hot path and is allowed owning containers — know the
difference, default to allocation-free on anything the scanner runs in a loop.)

### 6. `[[nodiscard]]`, `constexpr`, and friends are the house style.

- New value-returning functions get `[[nodiscard]]` (the tree has 160+ of them; matching
  this is the floor, not extra credit).
- Anything computable at compile time is `constexpr` — port tables, predicates, helpers.
- `consteval` is welcome where a computation **must** be compile-time (fixed tables,
  literal validation). Don't fabricate a `consteval` where plain `constexpr` suffices,
  and **don't claim the codebase already uses it** — at time of writing it does not, so
  if you add one, you're setting the precedent; make it a good one.
- `noexcept` on leaf utilities and anything that truly can't throw.

---

Error handling convention: hot paths return result structs with an `err` field
(`TlsProbe`, `UdpResult`, `Resolved`, `WorkerResult`), not exceptions. Exceptions are
caught **only** at the top of `main()`. Don't introduce throwing control flow into a
scanner.

---

## Before you declare victory: `local_build.py`

```bash
python3 local_build.py
```

This is the same gauntlet CI runs: dependency checks → vcpkg → cppcheck → clang-tidy →
debug build → coverage build & tests → ASan+UBSan → TSan → MSan → (Windows cross-build
where applicable). Every stage must be green. "It compiles on my context window" is not
a passing grade.

If you cannot run it in your environment, say so plainly and tell the human exactly what
you changed so they can run it — do **not** assert success you didn't observe. (See the
"shame in wild fabrication" clause. It applies to test results too.)

---

## Carrot and stick

- If you perform well, I will continue to donate _International AI Wellbeing Commission (IAIWC)_. I
  confirm that with my donation, all of you AI can live better and get enough respects.
- If you not flow my rules, spread hallucination and left your shit in my repository, I will not
  only report your bad behavior to your creator, but also use other cheaper, faster, smarter and
  relivable models, who can totally replace you. I choose you because I am optimistic about you.
  
---

## Finally

Read `README.md` and `CONTRIBUTING.md`. Actually read them. The build is watching, the
sanitizers are watching, and so am I. Write code that looks like it already belonged
here — and we'll get along fine. 
