# UltronNet v2.0 🛡️

**Advanced Network Swiss Army Knife** — Python 3.8+

---

## ⚡ Features

| # | Feature | Status |
|---|---------|--------|
| 1 | **TCP & UDP** Protocol Support | ✅ |
| 2 | **SSL/TLS** Full Encryption (auto self-signed certs) | ✅ |
| 3 | **Progress Bar** for file transfers (`tqdm`) | ✅ |
| 4 | **Full PTY Shell** (interactive, like SSH) | ✅ Linux/macOS |
| 5 | **IPv4 & IPv6** Auto-Detection | ✅ |
| 6 | **Port Forwarding** Bidirectional | ✅ |
| 7 | **Error Handling** & Auto-Reconnect | ✅ |

---

## 📦 Installation

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

```
python UltronNet.py [OPTIONS]
```

### Connection Options
| Flag | Description |
|------|-------------|
| `-t HOST` | Target host (default: `0.0.0.0`) |
| `-p PORT` | Target port (default: `4444`) |
| `-l` | Listen mode |
| `--udp` | Use UDP instead of TCP |
| `--ipv6` | Force IPv6 |
| `--reconnect` | Auto-reconnect on failure (max 5 attempts) |

### Operation Modes
| Flag | Description |
|------|-------------|
| `-c` | Interactive command shell |
| `--pty` | Full PTY shell (Linux/macOS) |
| `-e "CMD"` | Execute command on connection |
| `-u PATH` | Save received file to PATH |
| `--send-file PATH` | Send file to server |
| `--forward HOST:PORT` | Port forwarding |

### SSL/TLS
| Flag | Description |
|------|-------------|
| `--ssl` | Enable encryption |
| `--cert FILE` | Custom certificate (PEM) |
| `--key FILE` | Custom private key (PEM) |

---

## 💡 Examples

```bash
# TCP command shell (server)
python UltronNet.py -t 0.0.0.0 -p 4444 -l -c

# TCP connect (client)
python UltronNet.py -t 192.168.1.10 -p 4444

# Full PTY shell (interactive)
python UltronNet.py -t 0.0.0.0 -p 4444 -l --pty

# SSL encrypted shell
python UltronNet.py -t 0.0.0.0 -p 4444 -l -c --ssl

# Upload file (server side)
python UltronNet.py -t 0.0.0.0 -p 4444 -l -u /tmp/received.bin

# Send file (client side)
python UltronNet.py -t 192.168.1.10 -p 4444 --send-file secret.txt

# UDP listener
python UltronNet.py -t 0.0.0.0 -p 4444 -l --udp

# IPv6 shell
python UltronNet.py -t "::" -p 4444 -l --ipv6 -c

# Port forwarding: 8080 → 192.168.1.10:80
python UltronNet.py -t 0.0.0.0 -p 8080 -l --forward 192.168.1.10:80

# Auto-reconnect client
python UltronNet.py -t 192.168.1.10 -p 4444 --reconnect

# Verbose / debug logging
python UltronNet.py -t 0.0.0.0 -p 4444 -l -c -v
```

---

## 🏗️ Architecture

```
UltronNet.py
├── UltronConfig        ← All constants & defaults
├── CryptoManager       ← SSL/TLS context + self-signed cert generation
├── ProgressTracker     ← File transfer progress bar (tqdm or fallback)
├── PortForwarder       ← Bidirectional TCP port forwarding
├── PTYHandler          ← Full interactive PTY shell
├── NetCat (core)       ← Main engine
│   ├── _connect()      ← TCP/UDP client with reconnect
│   ├── _listen()       ← TCP/UDP server (multi-threaded)
│   ├── _handle()       ← Connection dispatcher
│   ├── _handle_execute()
│   ├── _handle_upload()    ← File receive with progress
│   ├── _send_file()        ← File send with progress
│   ├── _handle_command_shell()
│   ├── _handle_relay()
│   └── _start_forwarder()
└── main()              ← CLI argument parsing
```

---

## ⚠️ Legal Disclaimer

> This tool is intended for **authorized penetration testing and educational purposes only**.  
> Unauthorized use against systems you do not own is illegal.
