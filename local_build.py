#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import atexit
import os
import shutil
import signal
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Coroutine, Any

# --------------------------------------------------------------------------- #
# Constants & Configuration
# --------------------------------------------------------------------------- #
SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
OPENSSL_VERSION = "3.5.6"
CONTAINER_IMAGE = "localhost/helpers/sans:latest"
STATIC_FLAG = "-DBYEBYEVPN_STATIC=OFF"

SANITIZER_SCRIPT = r"""
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
    rm -rf "/workspace/deps/openssl-${SAN}-${OPENSSL_VERSION}-src"
    mkdir -p "/workspace/deps/openssl-${SAN}-${OPENSSL_VERSION}-src"
    tar -xzf "/workspace/deps/openssl-${OPENSSL_VERSION}.tar.gz" -C "/workspace/deps/openssl-${SAN}-${OPENSSL_VERSION}-src" --strip-components=1

    cd "/workspace/deps/openssl-${SAN}-${OPENSSL_VERSION}-src"
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
"""


# --------------------------------------------------------------------------- #
# Terminal styling
# --------------------------------------------------------------------------- #
class C:
    """ANSI styling codes; blanked out when stdout is not a TTY."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"

    @classmethod
    def disable(cls) -> None:
        for attr in ("RESET", "BOLD", "GREEN", "RED", "CYAN", "YELLOW", "DIM", "ITALIC"):
            setattr(cls, attr, "")


# --------------------------------------------------------------------------- #
# Data Types
# --------------------------------------------------------------------------- #
class StageError(RuntimeError):
    """Raised when a command inside a stage exits non-zero."""


@dataclass
class Stage:
    name: str
    key: str
    func: Callable[[Stage, Any], Coroutine[Any, Any, None]]
    status: str = "WAIT"  # WAIT | RUN | OK | FAIL | SKIP
    time_str: str = ""
    log_path: str = ""
    action: str = ""
    depends_on: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Components
# --------------------------------------------------------------------------- #
class TerminalUI:
    def __init__(self, stages: list[Stage]):
        self.tty = sys.stdout.isatty()
        self.stages = stages
        self.ui_lines = len(stages) + 2
        self.ui_active = False
        self.ui_paused = True
        self.spinner = ""
        self.spinner_frame = 0
        self.start_time = time.monotonic()
        
        self.total_pass = 0
        self.total_fail = 0
        self.total_skip = 0

    @staticmethod
    def _cols() -> int:
        return shutil.get_terminal_size(fallback=(80, 24)).columns

    @staticmethod
    def _truncate(text: str, maxlen: int) -> str:
        return text if len(text) <= maxlen else text[: maxlen - 1] + "…"

    def setup(self) -> None:
        if not self.tty:
            return
        # Reserve the UI region, park the cursor at its top, and save it.
        sys.stdout.write("\n" * self.ui_lines)
        sys.stdout.write(f"\033[{self.ui_lines}A\0337")
        sys.stdout.flush()
        self.ui_active = True
        self.ui_paused = False

    def pause(self) -> None:
        """Move below the UI region so normal output can follow it."""
        if not self.tty or not self.ui_active or self.ui_paused:
            return
        sys.stdout.write(f"\0338\033[{self.ui_lines}B\n")
        sys.stdout.flush()
        self.ui_paused = True

    def clear(self) -> None:
        """Clear the UI region and park the cursor at its original position."""
        if not self.tty or not self.ui_active or self.ui_paused:
            return
        sys.stdout.write("\0338\033[J")
        sys.stdout.flush()
        self.ui_paused = True

    def _stage_line(self, st: Stage, cols: int) -> str:
        icon, color = {
            "WAIT": ("WAIT", C.DIM),
            "RUN": ("RUN ", C.BOLD + C.CYAN),
            "OK": ("OK  ", C.BOLD + C.GREEN),
            "FAIL": ("FAIL", C.BOLD + C.RED),
            "SKIP": ("SKIP", C.DIM + C.YELLOW),
        }[st.status]

        if st.status == "RUN" and self.spinner:
            frame = f"{C.BOLD}{C.CYAN}{self.spinner}{C.RESET} "
        else:
            frame = "  "

        name = st.name
        base_len = 14 + len(name)
        if st.status == "RUN" and st.action:
            act_avail = cols - base_len - 12
            if act_avail > 10:
                act = self._truncate(st.action, act_avail)
                disp = f"{name} {C.DIM}{C.ITALIC}→ {act}{C.RESET}"
                base_len += 3 + len(act)
            else:
                disp = name
        else:
            disp = name

        prefix = f"  [ {color}{icon}{C.RESET} ] {frame}{disp}"

        if st.time_str:
            pad = max(1, cols - base_len - len(st.time_str))
            tcolor = "" if st.status == "WAIT" else C.DIM + C.CYAN
            return f"{prefix}{' ' * pad}{tcolor}{st.time_str}{C.RESET}\033[K"
        return f"{prefix}\033[K"

    def draw(self) -> None:
        if not self.tty:
            return
        cols = self._cols()
        lines = [f"{C.BOLD}{C.CYAN}Stages:{C.RESET}\033[K"]
        lines += [self._stage_line(st, cols) for st in self.stages]
        lines.append("\033[K")  # spacer

        sys.stdout.write("\0338" + "".join(line + "\n" for line in lines))
        sys.stdout.flush()

    def advance_spinner(self) -> None:
        if not self.tty:
            return
        self.spinner = SPINNER_FRAMES[self.spinner_frame]
        self.spinner_frame = (self.spinner_frame + 1) % len(SPINNER_FRAMES)
        self.draw()

    def _summary_block(self) -> None:
        elapsed = f"{time.monotonic() - self.start_time:.1f}s"
        bar = f"{C.BOLD}{C.CYAN}{'=' * 50}{C.RESET}"
        print(f"\n{bar}")
        print(f"{C.BOLD}Build Summary{C.RESET}")
        print(bar)
        print(f"Total Time:  {C.BOLD}{elapsed}{C.RESET}")
        print(f"Passed:      {C.BOLD}{C.GREEN}{self.total_pass}{C.RESET}")
        print(f"Skipped:     {C.BOLD}{C.YELLOW}{self.total_skip}{C.RESET}")
        print(f"Failed:      {C.BOLD}{C.RED}{self.total_fail}{C.RESET}")
        print(f"{bar}\n")

    def fail_summary(self, name: str, log: str) -> None:
        self.pause()
        self._summary_block()
        rbar = f"{C.BOLD}{C.RED}{'=' * 50}{C.RESET}"
        print(rbar)
        print(f"{C.BOLD}{C.RED}  FAILURE IN STAGE: {name}{C.RESET}")
        print(f"{rbar}\n")
        try:
            print(Path(log).read_text(encoding="utf-8", errors="replace"), end="")
        except OSError:
            print(f"{C.DIM}(No log file found){C.RESET}")
        print(f"\n{rbar}")
        print(f"{C.BOLD}{C.RED}Build aborted.{C.RESET}\n")

    def final_summary(self) -> None:
        self.pause()
        self._summary_block()
        if self.total_fail == 0:
            print(f"{C.BOLD}{C.GREEN}Build completed successfully!{C.RESET}\n")

    def prompt(self, message: str) -> str:
        self.clear()
        try:
            with open("/dev/tty", "r+") as tty:
                tty.write(message)
                tty.flush()
                answer = tty.readline().strip()
        except OSError:
            answer = input(message).strip()
        self.setup()
        return answer


class ProcessRunner:
    def __init__(self, env: dict[str, str]):
        self.env = env
        self.active_procs: set[asyncio.subprocess.Process] = set()

    async def run(self, args: list[str], stage: Stage, *, env: dict[str, str] = None, input_text: str = None, log_file=None, stdout_path: str = None) -> None:
        cmd_env = env or self.env
        use_stdout_file = stdout_path is not None
        
        proc = await asyncio.create_subprocess_exec(
            *args,
            env=cmd_env,
            stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE if use_stdout_file else asyncio.subprocess.STDOUT,
        )
        self.active_procs.add(proc)

        async def write_stdin():
            if input_text is not None:
                proc.stdin.write(input_text.encode("utf-8"))
                await proc.stdin.drain()
                proc.stdin.close()

        async def read_stdout():
            if use_stdout_file:
                with open(stdout_path, "wb") as out_f:
                    while True:
                        chunk = await proc.stdout.read(65536)
                        if not chunk:
                            break
                        out_f.write(chunk)
            else:
                while True:
                    chunk = await proc.stdout.read(65536)
                    if not chunk:
                        break
                    
                    if log_file:
                        log_file.write(chunk)
                    
                    if stage:
                        text = chunk.decode("utf-8", errors="replace").strip()
                        if text:
                            # Ninja uses \r to overwrite lines, so we split by both \n and \r
                            lines = text.replace("\r", "\n").split("\n")
                            if lines and lines[-1]:
                                stage.action = lines[-1].strip()

        async def read_stderr():
            if use_stdout_file:
                while True:
                    chunk = await proc.stderr.read(65536)
                    if not chunk:
                        break
                    if stage:
                        text = chunk.decode("utf-8", errors="replace").strip()
                        if text:
                            lines = text.replace("\r", "\n").split("\n")
                            if lines and lines[-1]:
                                stage.action = lines[-1].strip()
                    if log_file:
                        log_file.write(chunk)

        tasks = [write_stdin(), read_stdout()]
        if use_stdout_file:
            tasks.append(read_stderr())

        await asyncio.gather(*tasks)

        ret = await proc.wait()
        self.active_procs.discard(proc)
        if ret != 0:
            raise StageError(f"command exited with {ret}: {' '.join(map(str, args))}")

    def kill_all(self):
        for proc in self.active_procs:
            if proc.returncode is None:
                try:
                    proc.kill()
                except OSError:
                    pass


class ByeByeVPNBuildSteps:
    ARTIFACTS = [
        "build", "staging", "build-cov", "coverage.info", "coverage-html",
        "deps", "build-asan-ubsan", "build-tsan", "build-msan", "build-win",
    ]

    def __init__(self, keep: bool, build_linux: bool, build_windows: bool, runner: ProcessRunner):
        self.keep = keep
        self.build_linux = build_linux
        self.build_windows = build_windows
        self.runner = runner

        self.cwd = Path.cwd()
        
        self.container_engine = ""
        self.network_args: list[str] = []
        self.vcpkg_root = ""
        self.toolchain = ""
        self.triplet = "x64-linux-static"
        self.overlay_triplets = str(self.cwd / "triplets")
        self.test_cmd = "native"

        self.stages: list[Stage] = []
        self._build_stage_list()

    def _build_stage_list(self) -> None:
        def add(name, key, func, depends_on=None):
            self.stages.append(Stage(name, key, func, depends_on=depends_on or []))

        add("Dependency checks", "deps", self.do_deps_check)
        add("vcpkg setup", "vcpkg", self.do_vcpkg_setup, ["deps"])

        if self.build_linux:
            add("Static analysis (cppcheck)", "cppcheck", self.do_cppcheck, ["vcpkg"])
            add("Static analysis (clang-tidy)", "clangtidy", self.do_clangtidy, ["cppcheck"])
            add("Debug build", "build_debug", self.do_build_debug, ["clangtidy"])
            add("Coverage build & tests", "cov", self.do_cov, ["vcpkg"])
            add("Sanitizer: asan-ubsan", "asan", lambda st, lf: self.run_sanitizer("asan-ubsan", st, lf), ["vcpkg"])
            add("Sanitizer: tsan", "tsan", lambda st, lf: self.run_sanitizer("tsan", st, lf), ["vcpkg"])
            add("Sanitizer: msan", "msan", lambda st, lf: self.run_sanitizer("msan", st, lf), ["vcpkg"])
        else:
            async def skip_func(st, lf): pass
            self.stages.append(Stage("Linux phases", "linux", skip_func, status="SKIP", depends_on=["vcpkg"]))

        if self.build_windows:
            add("Windows cross-compile", "win_build", self.do_win_build, ["vcpkg"])
            add("Windows tests", "win_test", self.do_win_test, ["win_build"])
        else:
            async def skip_func(st, lf): pass
            self.stages.append(Stage("Windows phases", "win", skip_func, status="SKIP", depends_on=["vcpkg"]))

    def resolve_vcpkg_root(self, ui: TerminalUI) -> None:
        env_root = os.environ.get("VCPKG_ROOT", "")
        if env_root and Path(env_root).is_dir():
            self.vcpkg_root = env_root
            return

        vcpkg = shutil.which("vcpkg")
        if vcpkg:
            root = Path(vcpkg).parent
            if not (root / "scripts/buildsystems/vcpkg.cmake").is_file():
                fallback = Path("/usr/share/vcpkg")
                if (fallback / "scripts/buildsystems/vcpkg.cmake").is_file():
                    root = fallback
                else:
                    print(f"{C.RED}ERROR: vcpkg binary found but cannot locate "
                          f"vcpkg root directory.{C.RESET}", file=sys.stderr)
                    sys.exit(1)
            self.vcpkg_root = str(root)
            return

        root = self.cwd / "deps" / "vcpkg"
        if not (root / "vcpkg").is_file():
            answer = ui.prompt("Proceed with vcpkg installation? [y/N] ")
            if not answer[:1].lower() == "y":
                print(f"{C.RED}Aborted. Please install vcpkg manually.{C.RESET}",
                      file=sys.stderr)
                sys.exit(1)
        self.vcpkg_root = str(root)

    def resolve_test_cmd(self, ui: TerminalUI) -> None:
        if not self.build_windows:
            return

        if self._is_wsl():
            answer = ui.prompt("Is it okay to proceed and run unit tests directly? (y/n) ")
            if answer[:1].lower() == "y":
                self.test_cmd = ""
            else:
                self.test_cmd = "wine" if shutil.which("wine") else "skip"
        else:
            self.test_cmd = "wine" if shutil.which("wine") else "skip"

        if self.test_cmd == "skip":
            for st in self.stages:
                if st.key == "win_test":
                    st.status = "SKIP"

    @staticmethod
    def _is_wsl() -> bool:
        if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
            return True
        try:
            return "microsoft" in Path("/proc/version").read_text().lower()
        except OSError:
            return False

    async def do_deps_check(self, stage: Stage, log_file) -> None:
        if shutil.which("podman"):
            self.container_engine = "podman"
        elif shutil.which("docker"):
            self.container_engine = "docker"
        else:
            raise StageError("Neither podman nor docker is installed.")

        self.network_args = [] if Path("/dev/net/tun").exists() else ["--network=host"]

        missing: list[str] = []
        if not shutil.which("perl"):
            missing.append("perl")
        else:
            for mod, pkg in (("IPC::Cmd", "perl-IPC-Cmd"),
                             ("FindBin", "perl-FindBin"),
                             ("File::Compare", "perl-File-Compare")):
                proc = await asyncio.create_subprocess_exec(
                    "perl", "-e", f"use {mod};",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                if await proc.wait() != 0:
                    missing.append(pkg)

        if not Path("/usr/include/linux").is_dir():
            missing.append("kernel-headers")
        for tool, pkg in (("make", "make"), ("cmake", "cmake"),
                          ("ninja", "ninja-build"), ("clang", "clang")):
            if not shutil.which(tool):
                missing.append(pkg)
        if self.build_windows and not shutil.which("x86_64-w64-mingw32-g++"):
            missing.append("x86_64-w64-mingw32-g++")

        if missing:
            raise StageError(f"Missing dependencies: {' '.join(missing)}")

    async def do_vcpkg_setup(self, stage: Stage, log_file) -> None:
        root = Path(self.vcpkg_root)
        if not (root / "vcpkg").is_file() and "deps/vcpkg" in self.vcpkg_root:
            (self.cwd / "deps").mkdir(parents=True, exist_ok=True)
            await self.runner.run(["git", "clone", "--depth", "1",
                                   "https://github.com/microsoft/vcpkg.git", self.vcpkg_root],
                                  stage, log_file=log_file)
            await self.runner.run([str(root / "bootstrap-vcpkg.sh"), "-disableMetrics"],
                                  stage, log_file=log_file)

        self.runner.env["VCPKG_FORCE_SYSTEM_BINARIES"] = "1"
        self.toolchain = str(root / "scripts" / "buildsystems" / "vcpkg.cmake")

    async def do_cppcheck(self, stage: Stage, log_file) -> None:
        await self.runner.run([
            "cmake", "-S", ".", "-B", "build", "-G", "Ninja",
            f"-DCMAKE_TOOLCHAIN_FILE={self.toolchain}",
            f"-DVCPKG_TARGET_TRIPLET={self.triplet}",
            f"-DVCPKG_OVERLAY_TRIPLETS={self.overlay_triplets}",
            "-DCMAKE_BUILD_TYPE=Debug",
            "-DBYEBYEVPN_ENABLE_TESTS=OFF",
            "-DBYEBYEVPN_WARNINGS_AS_ERRORS=ON",
            STATIC_FLAG,
        ], stage, log_file=log_file)
        await self.runner.run([
            "cppcheck", "--std=c++20",
            "--enable=warning,style,performance,portability",
            "--error-exitcode=1", "--inline-suppr", "--quiet", "src",
        ], stage, log_file=log_file)

    async def do_clangtidy(self, stage: Stage, log_file) -> None:
        sources = sorted(str(p) for p in self.cwd.glob("src/**/*.cpp"))
        if not sources:
            return
        await self.runner.run([
            "clang-tidy", "-p", "build",
            "--checks=clang-analyzer-*,clang-diagnostic-*",
            "-warnings-as-errors=*", *sources,
        ], stage, log_file=log_file)

    async def do_build_debug(self, stage: Stage, log_file) -> None:
        await self.runner.run(["cmake", "--build", "build", "--parallel"], stage, log_file=log_file)
        Path("staging").mkdir(exist_ok=True)
        shutil.copy2("build/byebyevpn", "staging/")

    async def do_cov(self, stage: Stage, log_file) -> None:
        await self.runner.run([
            "cmake", "-S", ".", "-B", "build-cov", "-G", "Ninja",
            f"-DCMAKE_TOOLCHAIN_FILE={self.toolchain}",
            f"-DVCPKG_TARGET_TRIPLET={self.triplet}",
            f"-DVCPKG_OVERLAY_TRIPLETS={self.overlay_triplets}",
            "-DCMAKE_BUILD_TYPE=Debug",
            "-DBYEBYEVPN_ENABLE_TESTS=ON",
            "-DBYEBYEVPN_WARNINGS_AS_ERRORS=ON",
            "-DCMAKE_CXX_FLAGS=-fprofile-instr-generate -fcoverage-mapping",
            "-DCMAKE_EXE_LINKER_FLAGS=-fprofile-instr-generate",
            STATIC_FLAG,
        ], stage, log_file=log_file)
        await self.runner.run(["cmake", "--build", "build-cov", "--parallel"], stage, log_file=log_file)

        profiles = self.cwd / "build-cov" / "profiles"
        profiles.mkdir(parents=True, exist_ok=True)
        test_env = dict(self.runner.env,
                        LLVM_PROFILE_FILE=str(profiles / "byebyevpn_tests-%p.profraw"))
        await self.runner.run([
            "ctest", "--test-dir", "build-cov", "--output-on-failure",
            "--parallel", str(max(1, os.cpu_count() or 1)),
        ], stage, env=test_env, log_file=log_file)

        profraws = sorted(str(p) for p in profiles.glob("*.profraw"))
        await self.runner.run(["llvm-profdata", "merge", "-sparse", *profraws,
                               "-o", "build-cov/coverage.profdata"], stage, log_file=log_file)

        ignore = r"-ignore-filename-regex=.*/(_deps|tests|build-cov)/.*"
        await self.runner.run([
            "llvm-cov", "export", "-format=lcov",
            "-instr-profile=build-cov/coverage.profdata", ignore,
            "build-cov/tests/byebyevpn_tests",
        ], stage, log_file=log_file, stdout_path="coverage.info")
        await self.runner.run([
            "llvm-cov", "show", "-format=html", "-output-dir=coverage-html",
            "-instr-profile=build-cov/coverage.profdata", ignore,
            "build-cov/tests/byebyevpn_tests",
        ], stage, log_file=log_file)

    async def run_sanitizer(self, san: str, stage: Stage, log_file) -> None:
        await self.runner.run([
            self.container_engine, "run", "-i", "--rm", *self.network_args,
            "--privileged", "-v", f"{self.cwd}:/workspace", "-w", "/workspace",
            CONTAINER_IMAGE, "bash", "-s", san, OPENSSL_VERSION, STATIC_FLAG,
        ], stage, input_text=SANITIZER_SCRIPT, log_file=log_file)

    async def do_win_build(self, stage: Stage, log_file) -> None:
        await self.runner.run([
            "cmake", "-S", ".", "-B", "build-win", "-G", "Ninja",
            f"-DCMAKE_TOOLCHAIN_FILE={self.toolchain}",
            "-DVCPKG_TARGET_TRIPLET=x64-mingw-static",
            "-DCMAKE_SYSTEM_NAME=Windows",
            "-DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc",
            "-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++",
            "-DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres",
            "-DCMAKE_EXE_LINKER_FLAGS=-static",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBYEBYEVPN_ENABLE_TESTS=ON",
            "-DBYEBYEVPN_WARNINGS_AS_ERRORS=ON",
            STATIC_FLAG,
        ], stage, log_file=log_file)
        await self.runner.run(["cmake", "--build", "build-win", "--parallel"], stage, log_file=log_file)

        Path("staging/windows-Release").mkdir(parents=True, exist_ok=True)
        exe = Path("build-win/byebyevpn.exe")
        if exe.is_file():
            shutil.copy2(exe, "staging/windows-Release/")

    async def do_win_test(self, stage: Stage, log_file) -> None:
        if self.test_cmd == "skip":
            return
        exe = "build-win/tests/byebyevpn_tests.exe"
        if self.test_cmd and self.test_cmd != "native":
            await self.runner.run([self.test_cmd, exe], stage, log_file=log_file)
        else:
            await self.runner.run([exe], stage, log_file=log_file)


class Orchestrator:
    def __init__(self, keep: bool, build_linux: bool, build_windows: bool):
        self.keep = keep
        env = os.environ.copy()
        env.update(CC="clang", CXX="clang++")
        self.runner = ProcessRunner(env)
        self.steps = ByeByeVPNBuildSteps(keep, build_linux, build_windows, self.runner)
        self.ui = TerminalUI(self.steps.stages)
        
    @staticmethod
    def _remove(path: str) -> None:
        target = Path(path)
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink(missing_ok=True)
        except OSError:
            pass

    def cleanup(self) -> None:
        self.ui.pause()
        self.runner.kill_all()
        if self.keep:
            print(f"{C.YELLOW}Skipping cleanup (--keep flag provided).{C.RESET}")
        else:
            print(f"{C.CYAN}Cleaning up build artifacts...{C.RESET}")
            for artifact in self.steps.ARTIFACTS:
                self._remove(artifact)

    async def run_all(self) -> None:
        print(f"{C.BOLD}{C.CYAN}ByeByeVPN Local Build{C.RESET}")
        print("=" * 50)

        self.ui.setup()
        self.ui.draw()

        self.steps.resolve_vcpkg_root(self.ui)
        self.steps.resolve_test_cmd(self.ui)
        self.ui.draw()

        abort_build = False
        st_by_key = {st.key: st for st in self.steps.stages}

        for st in self.steps.stages:
            if st.status == "SKIP" or abort_build:
                st.status = "SKIP"
                self.ui.total_skip += 1
                continue

            skip_stage = False
            for dep_key in st.depends_on:
                dep_st = st_by_key.get(dep_key)
                if dep_st and dep_st.status not in ("OK", "SKIP"):
                    skip_stage = True
                    break

            if skip_stage or abort_build:
                st.status = "SKIP"
                self.ui.total_skip += 1
                continue

            st.status = "RUN"
            self.ui.draw()
            if not self.ui.tty:
                print(f"[RUN ] {st.name}", flush=True)

            fd, st.log_path = tempfile.mkstemp(prefix=f"bbvpn_stage_{st.key}_", suffix=".log")
            
            start = time.monotonic()
            error = None
            
            async def spinner_task():
                while True:
                    self.ui.advance_spinner()
                    await asyncio.sleep(0.1)

            spin_task = asyncio.create_task(spinner_task()) if self.ui.tty else None

            try:
                with os.fdopen(fd, "wb") as log_file:
                    await st.func(st, log_file)
            except Exception as exc:
                error = exc
            finally:
                if spin_task:
                    spin_task.cancel()
                    try:
                        await spin_task
                    except asyncio.CancelledError:
                        pass

            st.time_str = f"{time.monotonic() - start:.1f}s"

            if not error:
                st.status = "OK"
                self.ui.total_pass += 1
                self._remove(st.log_path)
                if not self.ui.tty:
                    print(f"[OK  ] {st.name}  {st.time_str}", flush=True)
            else:
                st.status = "FAIL"
                self.ui.total_fail += 1
                abort_build = True
                if not self.ui.tty:
                    print(f"[FAIL] {st.name}  {st.time_str}", flush=True)

            self.ui.spinner = ""
            self.ui.draw()

        failed_stages = [st for st in self.steps.stages if st.status == "FAIL"]
        if failed_stages:
            self.ui.fail_summary(failed_stages[0].name, failed_stages[0].log_path)
            sys.exit(1)

        self.ui.final_summary()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str]) -> tuple[bool, bool, bool]:
    keep = False
    build_linux = build_windows = True
    explicit_target = False

    for arg in argv:
        if arg == "--keep":
            keep = True
        elif arg == "--linux":
            if not explicit_target:
                build_windows = False
                explicit_target = True
            build_linux = True
        elif arg == "--windows":
            if not explicit_target:
                build_linux = False
                explicit_target = True
            build_windows = True
        elif arg in ("-h", "--help"):
            print(__doc__.strip())
            sys.exit(0)
        else:
            print(f"{C.RED}Unknown option: {arg}{C.RESET}", file=sys.stderr)
            sys.exit(2)

    return keep, build_linux, build_windows


def main() -> None:
    if not sys.stdout.isatty():
        C.disable()

    keep, build_linux, build_windows = parse_args(sys.argv[1:])
    orchestrator = Orchestrator(keep, build_linux, build_windows)

    atexit.register(orchestrator.cleanup)

    def on_interrupt(signum, frame):
        print(f"\n{C.RED}Interrupted{C.RESET}")
        sys.exit(130)

    signal.signal(signal.SIGINT, on_interrupt)

    asyncio.run(orchestrator.run_all())


if __name__ == "__main__":
    main()
