# ByeByeVPN

```text
 ____             ____           __     ______  _   _ 
| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |
|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |
| |_) | |_| |  __/ |_) | |_| |  __/\ V / |  __/| |\  |
|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|
       |___/            |___/                          
   Remote signature-less VPN profiler   v1.1.0
```

**Discussion / report issues:**
[ntc.party/t/byebyevpn/24325](https://ntc.party/t/byebyevpn/24325) ·
[GitHub Issues](https://github.com/Applone/ByeByeVPN/issues)

## Purpose

Given an IP or hostname, run a remote detectability methodology focused on modern signature-less VPN stacks from an external vantage point. Output: a weighted detection score, identified stack hypothesis, and an emulated DPI-class classifier decision. No VPN connection to the target is needed - the scanner observes the destination as a third-party network observer (ISP/DPI perspective).

## Pipeline

1. **DNS resolve**: A + AAAA, IPv4 preferred
2. **GeoIP aggregation**: HTTPS-only providers in parallel, ASN + tags
3. **TCP port scan**: Async non-blocking connect-scan 1-65535 or curated ports
4. **UDP probes**: WireGuard and AmneziaWG handshake probes only
5. **Service fingerprint + CT**: SSH, HTTP, TLS + SNI consistency, proxy exposure, proxy-header leak
6. **Active probing (J3)**: multi-probe behaviour checks per TLS-like port
7. **Verdict**: Score 0-100, stack identification, hardening advice

## Build

### Linux (CMake + Ninja)
```bash
sudo apt install build-essential cmake ninja-build libssl-dev
git clone https://github.com/Applone/ByeByeVPN.git && cd ByeByeVPN
mkdir build && cd build
cmake -G Ninja ..
ninja
```

> Requires a C++20 compiler and OpenSSL 3.x development libraries.

### Windows (CMake + MSVC)
Open Developer Command Prompt for Visual Studio:
```cmd
git clone https://github.com/Applone/ByeByeVPN.git
cd ByeByeVPN
mkdir build
cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Release
```

## CLI Usage

```bash
byebyevpn                        # interactive menu
byebyevpn <host>                 # full scan
byebyevpn scan 1.2.3.4           # same, explicit
byebyevpn ports my.server.ru     # tcp scan only
byebyevpn udp my.server.ru       # UDP WG/AWG probes only
```

## License

GPLv3. See [LICENSE](LICENSE) for the full license.
This project is a fork of ByeByeVPN and contains code originally licensed under the MIT License by `pwnnex`. See [NOTICE](NOTICE) for the original copyright and permission notices.
