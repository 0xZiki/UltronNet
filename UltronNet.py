#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                        UltronNet v2.0                        ║
║              Advanced Network Swiss Army Knife               ║
║                                                              ║
║  Features:                                                   ║
║    ✔ TCP & UDP Protocol Support                              ║
║    ✔ Full SSL/TLS Encryption (auto self-signed certs)        ║
║    ✔ File Transfer with Live Progress Bar                    ║
║    ✔ Full Interactive PTY Shell                              ║
║    ✔ IPv4 & IPv6 Auto-Detection                              ║
║    ✔ Port Forwarding (Local & Remote)                        ║
║    ✔ Robust Error Handling & Auto-Reconnect                  ║
╚══════════════════════════════════════════════════════════════╝

Author : UltronNet Project
Version: 2.0.0
Python : 3.8+

Examples:
  # TCP command shell (listener)
  python UltronNet.py -t 0.0.0.0 -p 4444 -l -c

  # TCP command shell (client)
  python UltronNet.py -t 192.168.1.10 -p 4444

  # Upload file with progress bar
  python UltronNet.py -t 192.168.1.10 -p 4444 -l -u /tmp/received.bin

  # SSL-encrypted shell
  python UltronNet.py -t 0.0.0.0 -p 4444 -l -c --ssl

  # UDP listener
  python UltronNet.py -t 0.0.0.0 -p 4444 -l --udp

  # Port forward: local 8080 → remote 192.168.1.10:80
  python UltronNet.py --forward 192.168.1.10:80 -p 8080 -l
"""

# ─────────────────────────── Imports ────────────────────────────
import argparse
import ipaddress
import logging
import os
import platform
import select
import shlex
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

# Optional dependency: tqdm for progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Optional dependency: cryptography for self-signed SSL certs
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# PTY support (Linux/macOS only)
PTY_AVAILABLE = False
if platform.system() != "Windows":
    try:
        import pty
        import termios
        import tty
        import fcntl
        PTY_AVAILABLE = True
    except ImportError:
        pass


# ─────────────────────────── Config ─────────────────────────────
@dataclass
class UltronConfig:
    """Central configuration and constants."""

    # Network
    BUFFER_SIZE: int          = 65536          # Recv buffer (64 KB)
    CHUNK_SIZE: int           = 8192           # File transfer chunk (8 KB)
    BACKLOG: int              = 10             # TCP listen backlog
    CONNECT_TIMEOUT: float    = 10.0           # Connection timeout (s)
    RECV_TIMEOUT: float       = 30.0           # Receive timeout (s)
    RECONNECT_DELAY: float    = 3.0            # Delay before reconnect (s)
    MAX_RECONNECT: int        = 5              # Max auto-reconnect attempts

    # SSL defaults
    DEFAULT_CERT: str         = "ultron_cert.pem"
    DEFAULT_KEY: str          = "ultron_key.pem"
    SSL_MIN_VERSION: int      = ssl.TLSVersion.TLSv1_2

    # Shell prompt
    SHELL_PROMPT: bytes       = b"\r\nUltronNet #> "

    # File transfer header magic
    FILE_MAGIC: bytes         = b"\xDE\xAD\xBE\xEF"
    FILE_HEADER_FMT: str      = "!4sQ"         # magic(4) + size(8) = 12 bytes
    FILE_HEADER_SIZE: int     = 12

    # Logging
    LOG_FORMAT: str           = "%(asctime)s [%(levelname)s] %(message)s"
    LOG_DATE_FMT: str         = "%H:%M:%S"


# Singleton config instance
CFG = UltronConfig()


# ─────────────────────────── Logging ────────────────────────────
def setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=CFG.LOG_FORMAT,
        datefmt=CFG.LOG_DATE_FMT,
        handlers=[logging.StreamHandler(sys.stderr)],
    )
    return logging.getLogger("UltronNet")


log = setup_logging()


# ──────────────────────── Crypto Manager ────────────────────────
class CryptoManager:
    """
    Handles SSL/TLS context creation.
    Auto-generates self-signed certificates when none are provided.
    """

    @staticmethod
    def generate_self_signed(cert_path: str, key_path: str) -> None:
        """Generate a self-signed RSA-2048 certificate."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError(
                "Package 'cryptography' is required for SSL certificate generation.\n"
                "Install it with: pip install cryptography"
            )

        log.info("Generating self-signed certificate …")

        # RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

        # Certificate subject / issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UltronNet"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ultronnet.local"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Write key
        Path(key_path).write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

        # Write cert
        Path(cert_path).write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        log.info("Certificate saved: %s  |  Key saved: %s", cert_path, key_path)

    @staticmethod
    def server_context(cert: str, key: str) -> ssl.SSLContext:
        """Create an SSL context for the server side."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = CFG.SSL_MIN_VERSION
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    @staticmethod
    def client_context(verify: bool = False) -> ssl.SSLContext:
        """Create an SSL context for the client side."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = CFG.SSL_MIN_VERSION
        if not verify:
            # Accept self-signed certs (pentest/lab environment)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx


# ──────────────────────── Progress Tracker ──────────────────────
class ProgressTracker:
    """
    Wraps tqdm for file-transfer progress display.
    Falls back to a simple percentage printer when tqdm is unavailable.
    """

    def __init__(self, total: int, description: str = "Transfer"):
        self.total = total
        self.sent = 0
        self._start = time.time()
        self._desc = description

        if TQDM_AVAILABLE:
            self._bar = tqdm(
                total=total,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc=description,
                colour="cyan",
                file=sys.stderr,
            )
        else:
            self._bar = None
            log.info("%s  0.00%%", description)

    def update(self, n: int) -> None:
        self.sent += n
        if self._bar:
            self._bar.update(n)
        else:
            pct = (self.sent / self.total * 100) if self.total else 0
            elapsed = time.time() - self._start
            speed = self.sent / elapsed if elapsed > 0 else 0
            sys.stderr.write(
                f"\r{self._desc}: {pct:6.2f}%  "
                f"({self._fmt(self.sent)}/{self._fmt(self.total)})  "
                f"Speed: {self._fmt(speed)}/s   "
            )
            sys.stderr.flush()

    def close(self) -> None:
        if self._bar:
            self._bar.close()
        else:
            elapsed = time.time() - self._start
            sys.stderr.write(
                f"\n✔ Done: {self._fmt(self.sent)} in {elapsed:.2f}s\n"
            )

    @staticmethod
    def _fmt(size: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"


# ──────────────────────── Port Forwarder ────────────────────────
class PortForwarder:
    """
    Bidirectional TCP port forwarder.

    Accepts a connection on (listen_host, listen_port) and pipes all
    traffic to/from (remote_host, remote_port).
    """

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        remote_host: str,
        remote_port: int,
        use_ssl: bool = False,
        ssl_cert: str = "",
        ssl_key: str = "",
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.use_ssl = use_ssl
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self._stop_event = threading.Event()

    def start(self) -> None:
        family = detect_af(self.listen_host)
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(CFG.BACKLOG)
        srv.settimeout(1.0)

        log.info(
            "Port forwarder: %s:%d  →  %s:%d",
            self.listen_host, self.listen_port,
            self.remote_host, self.remote_port,
        )

        try:
            while not self._stop_event.is_set():
                try:
                    client, addr = srv.accept()
                except socket.timeout:
                    continue
                log.info("Forward connection from %s:%d", *addr[:2])
                threading.Thread(
                    target=self._handle_forward,
                    args=(client,),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            pass
        finally:
            srv.close()
            log.info("Port forwarder stopped.")

    def stop(self) -> None:
        self._stop_event.set()

    def _handle_forward(self, client: socket.socket) -> None:
        family = detect_af(self.remote_host)
        remote = socket.socket(family, socket.SOCK_STREAM)
        remote.settimeout(CFG.CONNECT_TIMEOUT)

        try:
            remote.connect((self.remote_host, self.remote_port))
        except OSError as exc:
            log.error("Forward connect failed: %s", exc)
            client.close()
            return

        if self.use_ssl:
            ctx = CryptoManager.client_context(verify=False)
            remote = ctx.wrap_socket(remote, server_hostname=self.remote_host)

        log.info(
            "Forwarding  %s  ↔  %s:%d",
            client.getpeername(), self.remote_host, self.remote_port,
        )
        stop = threading.Event()

        def pipe(src: socket.socket, dst: socket.socket) -> None:
            try:
                while not stop.is_set():
                    r, _, _ = select.select([src], [], [], 1.0)
                    if r:
                        data = src.recv(CFG.BUFFER_SIZE)
                        if not data:
                            break
                        dst.sendall(data)
            except OSError:
                pass
            finally:
                stop.set()

        t1 = threading.Thread(target=pipe, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=pipe, args=(remote, client), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        safe_close(client)
        safe_close(remote)
        log.info("Forward session closed.")


# ──────────────────────── PTY Handler ───────────────────────────
class PTYHandler:
    """
    Provides a full interactive PTY shell over a socket.

    On Linux/macOS: uses pty.openpty() for a real pseudo-terminal.
    On Windows    : falls back to a piped cmd.exe session.
    """

    @staticmethod
    def spawn_pty(client_socket: socket.socket) -> None:
        """Spawn a PTY shell and bridge it with *client_socket*."""
        if PTY_AVAILABLE:
            PTYHandler._unix_pty(client_socket)
        else:
            PTYHandler._windows_shell(client_socket)

    # ── Unix PTY ────────────────────────────────────────────────
    @staticmethod
    def _unix_pty(sock: socket.socket) -> None:
        shell = os.environ.get("SHELL", "/bin/bash")

        # Fork a child with a new PTY
        pid, fd_master = pty.fork()

        if pid == 0:
            # Child: exec shell
            os.execv(shell, [shell])
        else:
            # Parent: bridge fd_master ↔ socket
            log.info("PTY shell spawned (pid=%d, shell=%s)", pid, shell)

            def _resize_pty(_sig, _frame):
                """Forward SIGWINCH (terminal resize) to PTY."""
                try:
                    cols, rows = os.get_terminal_size()
                    fcntl.ioctl(
                        fd_master, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0),
                    )
                except Exception:
                    pass

            if hasattr(signal, "SIGWINCH"):
                signal.signal(signal.SIGWINCH, _resize_pty)

            try:
                while True:
                    r, _, _ = select.select([fd_master, sock], [], [], 0.5)
                    if fd_master in r:
                        try:
                            data = os.read(fd_master, CFG.BUFFER_SIZE)
                        except OSError:
                            break
                        if not data:
                            break
                        sock.sendall(data)
                    if sock in r:
                        try:
                            data = sock.recv(CFG.BUFFER_SIZE)
                        except OSError:
                            break
                        if not data:
                            break
                        os.write(fd_master, data)
            except (OSError, BrokenPipeError):
                pass
            finally:
                os.waitpid(pid, os.WNOHANG)
                os.close(fd_master)
                log.info("PTY shell session ended.")

    # ── Windows fallback ─────────────────────────────────────────
    @staticmethod
    def _windows_shell(sock: socket.socket) -> None:
        proc = subprocess.Popen(
            ["cmd.exe"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        log.info("Windows cmd.exe shell spawned (pid=%d)", proc.pid)
        stop = threading.Event()

        def _read_output():
            while not stop.is_set():
                data = proc.stdout.read(CFG.BUFFER_SIZE)
                if not data:
                    break
                try:
                    sock.sendall(data)
                except OSError:
                    break
            stop.set()

        def _write_input():
            while not stop.is_set():
                r, _, _ = select.select([sock], [], [], 0.5)
                if r:
                    try:
                        data = sock.recv(CFG.BUFFER_SIZE)
                    except OSError:
                        break
                    if not data:
                        break
                    proc.stdin.write(data)
                    proc.stdin.flush()
            stop.set()

        t1 = threading.Thread(target=_read_output, daemon=True)
        t2 = threading.Thread(target=_write_input, daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        proc.terminate()
        log.info("Windows shell session ended.")


# ──────────────────────── Helpers ───────────────────────────────
def detect_af(host: str) -> socket.AddressFamily:
    """Return AF_INET6 for IPv6 addresses, AF_INET otherwise."""
    try:
        ipaddress.IPv6Address(host.strip("[]"))
        return socket.AF_INET6
    except ValueError:
        return socket.AF_INET


def safe_close(sock) -> None:
    """Close a socket silently."""
    try:
        sock.close()
    except Exception:
        pass


def execute(cmd: str) -> str:
    """
    Run a shell command and return its combined stdout/stderr output.

    On Windows : uses shell=True (supports built-ins like echo, dir).
    On Unix    : uses shlex.split() for safer argument handling.
    """
    cmd = cmd.strip()
    if not cmd:
        return ""

    _is_windows = platform.system() == "Windows"

    try:
        if _is_windows:
            output = subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        else:
            output = subprocess.check_output(
                shlex.split(cmd),
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        return output.decode(errors="replace")
    except subprocess.CalledProcessError as exc:
        return exc.output.decode(errors="replace")
    except FileNotFoundError:
        return f"Command not found: {cmd.split()[0]}\n"
    except subprocess.TimeoutExpired:
        return "Command timed out.\n"


# ──────────────────────── Core NetCat ───────────────────────────
class NetCat:
    """
    Core UltronNet engine.

    Supports: TCP, UDP, SSL/TLS, IPv4/IPv6, PTY shell,
              file upload with progress, command execution,
              and port forwarding.
    """

    def __init__(self, args: argparse.Namespace, buffer: bytes = b""):
        self.args = args
        self.buffer = buffer
        self._stop = threading.Event()

        # Resolve address family (IPv4 / IPv6)
        self.af = (
            socket.AF_INET6
            if args.ipv6
            else detect_af(args.target)
        )

        # Socket type: UDP or TCP
        self.sock_type = (
            socket.SOCK_DGRAM if args.udp else socket.SOCK_STREAM
        )

    # ── Public entry point ──────────────────────────────────────
    def run(self) -> None:
        try:
            if self.args.forward:
                self._start_forwarder()
            elif self.args.listen:
                self._listen()
            else:
                self._connect()
        except KeyboardInterrupt:
            log.info("Interrupted by user.")
        except Exception as exc:
            log.exception("Fatal error: %s", exc)
        finally:
            log.info("UltronNet terminated.")

    # ── Port forwarder mode ─────────────────────────────────────
    def _start_forwarder(self) -> None:
        remote_host, remote_port_str = self.args.forward.rsplit(":", 1)
        remote_port = int(remote_port_str)
        fwd = PortForwarder(
            listen_host=self.args.target,
            listen_port=self.args.port,
            remote_host=remote_host,
            remote_port=remote_port,
            use_ssl=self.args.ssl,
            ssl_cert=self.args.cert,
            ssl_key=self.args.key,
        )
        fwd.start()

    # ── Client mode (send) ──────────────────────────────────────
    def _connect(self) -> None:
        attempt = 0
        while True:
            attempt += 1
            sock = socket.socket(self.af, self.sock_type)
            sock.settimeout(CFG.CONNECT_TIMEOUT)

            try:
                if self.args.udp:
                    self._udp_client(sock)
                else:
                    sock.connect((self.args.target, self.args.port))
                    if self.args.ssl:
                        ctx = CryptoManager.client_context(verify=False)
                        sock = ctx.wrap_socket(
                            sock, server_hostname=self.args.target
                        )
                    log.info(
                        "Connected to %s:%d (SSL=%s)",
                        self.args.target, self.args.port, self.args.ssl,
                    )
                    self._tcp_client(sock)

                # Clean exit — don't reconnect
                break

            except (ConnectionRefusedError, socket.timeout, OSError) as exc:
                log.warning("Connection failed [%d]: %s", attempt, exc)
                if self.args.reconnect and attempt < CFG.MAX_RECONNECT:
                    log.info(
                        "Reconnecting in %.1fs … (%d/%d)",
                        CFG.RECONNECT_DELAY, attempt, CFG.MAX_RECONNECT,
                    )
                    time.sleep(CFG.RECONNECT_DELAY)
                else:
                    log.error("Could not establish connection.")
                    break
            finally:
                safe_close(sock)

    def _tcp_client(self, sock: socket.socket) -> None:
        """Interactive TCP client loop."""
        sock.settimeout(CFG.RECV_TIMEOUT)
        if self.buffer:
            sock.sendall(self.buffer)

        try:
            while not self._stop.is_set():
                # Wait for data from server
                r, _, _ = select.select([sock, sys.stdin], [], [], 1.0)
                if sock in r:
                    try:
                        data = sock.recv(CFG.BUFFER_SIZE)
                    except socket.timeout:
                        continue
                    if not data:
                        log.info("Server closed connection.")
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()

                if sys.stdin in r:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    sock.sendall(line.encode())

        except (BrokenPipeError, ConnectionResetError) as exc:
            log.warning("Connection lost: %s", exc)
        except socket.timeout:
            log.warning("Receive timeout.")

    def _udp_client(self, sock: socket.socket) -> None:
        """Simple UDP client."""
        target = (self.args.target, self.args.port)
        if self.buffer:
            sock.sendto(self.buffer, target)

        sock.settimeout(CFG.RECV_TIMEOUT)
        try:
            while not self._stop.is_set():
                if sys.stdin in select.select([sys.stdin], [], [], 0.5)[0]:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    sock.sendto(line.encode(), target)
                try:
                    data, addr = sock.recvfrom(CFG.BUFFER_SIZE)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass

    # ── Server mode (listen) ────────────────────────────────────
    def _listen(self) -> None:
        if self.args.udp:
            self._udp_server()
        else:
            self._tcp_server()

    def _tcp_server(self) -> None:
        """Multi-threaded TCP listener."""
        srv = socket.socket(self.af, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.af == socket.AF_INET6:
            # Allow dual-stack on platforms that support it
            try:
                srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except AttributeError:
                pass

        srv.bind((self.args.target, self.args.port))
        srv.listen(CFG.BACKLOG)
        srv.settimeout(1.0)

        # Wrap in SSL if requested
        ssl_ctx: Optional[ssl.SSLContext] = None
        if self.args.ssl:
            cert, key = self._ensure_ssl_files()
            ssl_ctx = CryptoManager.server_context(cert, key)

        log.info(
            "Listening on %s:%d  (UDP=%s, SSL=%s, IPv6=%s)",
            self.args.target, self.args.port,
            self.args.udp, self.args.ssl, self.af == socket.AF_INET6,
        )

        try:
            while not self._stop.is_set():
                try:
                    client, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if not self._stop.is_set():
                        log.error("Accept error: %s", exc)
                    break

                log.info("Connection from %s:%d", addr[0], addr[1])

                if ssl_ctx:
                    try:
                        client = ssl_ctx.wrap_socket(
                            client, server_side=True
                        )
                    except ssl.SSLError as exc:
                        log.error("SSL handshake failed: %s", exc)
                        safe_close(client)
                        continue

                threading.Thread(
                    target=self._handle,
                    args=(client, addr),
                    daemon=True,
                ).start()

        except KeyboardInterrupt:
            pass
        finally:
            safe_close(srv)
            log.info("Listener stopped.")

    def _udp_server(self) -> None:
        """UDP server loop."""
        srv = socket.socket(self.af, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.args.target, self.args.port))
        srv.settimeout(1.0)

        log.info(
            "UDP Listening on %s:%d", self.args.target, self.args.port
        )

        try:
            while not self._stop.is_set():
                try:
                    data, addr = srv.recvfrom(CFG.BUFFER_SIZE)
                except socket.timeout:
                    continue
                log.info("UDP datagram from %s:%d (%d bytes)", addr[0], addr[1], len(data))

                if self.args.execute:
                    output = execute(data.decode(errors="replace"))
                    srv.sendto(output.encode(), addr)
                else:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()

        except KeyboardInterrupt:
            pass
        finally:
            safe_close(srv)

    # ── Connection handler ──────────────────────────────────────
    def _handle(self, client: socket.socket, addr: Tuple) -> None:
        """Dispatch incoming connection to the correct handler."""
        try:
            client.settimeout(CFG.RECV_TIMEOUT)

            if self.args.execute:
                self._handle_execute(client)
            elif self.args.upload:
                self._handle_upload(client)
            elif self.args.command:
                self._handle_command_shell(client)
            elif self.args.pty:
                PTYHandler.spawn_pty(client)
            else:
                # Transparent relay (pipe stdin→socket, socket→stdout)
                self._handle_relay(client)

        except (ConnectionResetError, BrokenPipeError) as exc:
            log.warning("Client %s:%d disconnected: %s", addr[0], addr[1], exc)
        except Exception as exc:
            log.exception("Handler error for %s:%d → %s", addr[0], addr[1], exc)
        finally:
            safe_close(client)
            log.info("Session with %s:%d closed.", addr[0], addr[1])

    # ── Execute a single command ─────────────────────────────────
    def _handle_execute(self, client: socket.socket) -> None:
        output = execute(self.args.execute)
        client.sendall(output.encode())

    # ── File upload with progress bar ───────────────────────────
    def _handle_upload(self, client: socket.socket) -> None:
        """
        Receive a file from the client using a length-prefixed protocol:
          Header: FILE_MAGIC (4 bytes) + file_size (8 bytes, big-endian)
          Body  : raw file data
        """
        # Read header
        header = self._recv_exactly(client, CFG.FILE_HEADER_SIZE)
        if header is None:
            client.sendall(b"ERROR: Header receive failed.\n")
            return

        magic, file_size = struct.unpack(CFG.FILE_HEADER_FMT, header)
        if magic != CFG.FILE_MAGIC:
            client.sendall(b"ERROR: Invalid file magic.\n")
            return

        log.info("Receiving file: %d bytes → %s", file_size, self.args.upload)

        tracker = ProgressTracker(file_size, f"Receiving {Path(self.args.upload).name}")
        received = b""

        while len(received) < file_size:
            chunk = client.recv(
                min(CFG.CHUNK_SIZE, file_size - len(received))
            )
            if not chunk:
                break
            received += chunk
            tracker.update(len(chunk))

        tracker.close()

        # Write to disk
        Path(self.args.upload).parent.mkdir(parents=True, exist_ok=True)
        Path(self.args.upload).write_bytes(received)

        msg = f"✔ Saved {len(received)} bytes to {self.args.upload}\n"
        log.info(msg.strip())
        client.sendall(msg.encode())

    def _send_file(self, sock: socket.socket, file_path: str) -> None:
        """
        Send a file using the length-prefixed protocol.
        Used when connecting to a listener with --upload.
        """
        path = Path(file_path)
        if not path.exists():
            log.error("File not found: %s", file_path)
            return

        data = path.read_bytes()
        file_size = len(data)
        header = struct.pack(CFG.FILE_HEADER_FMT, CFG.FILE_MAGIC, file_size)

        sock.sendall(header)

        tracker = ProgressTracker(file_size, f"Sending {path.name}")
        offset = 0
        while offset < file_size:
            chunk = data[offset: offset + CFG.CHUNK_SIZE]
            sock.sendall(chunk)
            tracker.update(len(chunk))
            offset += len(chunk)

        tracker.close()

        # Wait for server acknowledgement
        try:
            ack = sock.recv(CFG.BUFFER_SIZE)
            log.info("Server: %s", ack.decode(errors="replace").strip())
        except socket.timeout:
            log.warning("No ACK received from server.")

    # ── Interactive command shell ────────────────────────────────
    def _handle_command_shell(self, client: socket.socket) -> None:
        """Simple line-by-line command shell (no PTY)."""
        cmd_buf = b""
        client.sendall(CFG.SHELL_PROMPT)

        while True:
            try:
                # Accumulate until newline
                r, _, _ = select.select([client], [], [], CFG.RECV_TIMEOUT)
                if not r:
                    break
                chunk = client.recv(64)
                if not chunk:
                    break
                cmd_buf += chunk

                if b"\n" in cmd_buf:
                    cmd, cmd_buf = cmd_buf.split(b"\n", 1)
                    response = execute(cmd.decode(errors="replace"))
                    if response:
                        client.sendall(response.encode())
                    client.sendall(CFG.SHELL_PROMPT)

            except (ConnectionResetError, BrokenPipeError):
                break
            except Exception as exc:
                error_msg = f"Shell error: {exc}\n"
                try:
                    client.sendall(error_msg.encode())
                except OSError:
                    pass
                break

    # ── Transparent relay ────────────────────────────────────────
    def _handle_relay(self, client: socket.socket) -> None:
        """Pipe socket ↔ stdout/stdin (like classic netcat)."""
        stop = threading.Event()

        def _sock_to_stdout():
            while not stop.is_set():
                r, _, _ = select.select([client], [], [], 0.5)
                if r:
                    try:
                        data = client.recv(CFG.BUFFER_SIZE)
                    except OSError:
                        break
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
            stop.set()

        def _stdin_to_sock():
            while not stop.is_set():
                r, _, _ = select.select([sys.stdin], [], [], 0.5)
                if r:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    try:
                        client.sendall(line.encode())
                    except OSError:
                        break
            stop.set()

        t1 = threading.Thread(target=_sock_to_stdout, daemon=True)
        t2 = threading.Thread(target=_stdin_to_sock, daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()

    # ── Helpers ─────────────────────────────────────────────────
    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly *n* bytes from *sock*, or None on failure."""
        buf = b""
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _ensure_ssl_files(self) -> Tuple[str, str]:
        """Return (cert_path, key_path), auto-generating if needed."""
        cert = self.args.cert or CFG.DEFAULT_CERT
        key = self.args.key or CFG.DEFAULT_KEY

        if not Path(cert).exists() or not Path(key).exists():
            CryptoManager.generate_self_signed(cert, key)

        return cert, key


# ────────────────────────── CLI / Main ──────────────────────────
EXAMPLES = textwrap.dedent("""\
Examples:
  # TCP command shell (listener)
  python UltronNet.py -t 0.0.0.0 -p 4444 -l -c

  # TCP connect (interactive)
  python UltronNet.py -t 192.168.1.10 -p 4444

  # Pipe stdin to remote
  echo "hello" | python UltronNet.py -t 192.168.1.10 -p 4444

  # Upload a file (server side)
  python UltronNet.py -t 0.0.0.0 -p 4444 -l -u /tmp/received.bin

  # Upload a file (client side)
  python UltronNet.py -t 192.168.1.10 -p 4444 --send-file secret.txt

  # Execute one command on connect
  python UltronNet.py -t 0.0.0.0 -p 4444 -l -e "whoami"

  # Full PTY interactive shell
  python UltronNet.py -t 0.0.0.0 -p 4444 -l --pty

  # SSL-encrypted command shell
  python UltronNet.py -t 0.0.0.0 -p 4444 -l -c --ssl

  # SSL with custom certificate
  python UltronNet.py -t 0.0.0.0 -p 4444 -l -c --ssl --cert my.pem --key my.key

  # UDP listener
  python UltronNet.py -t 0.0.0.0 -p 4444 -l --udp

  # IPv6 listener
  python UltronNet.py -t "::" -p 4444 -l --ipv6 -c

  # Port forwarding: local 8080 → remote 192.168.1.10:80
  python UltronNet.py -t 0.0.0.0 -p 8080 -l --forward 192.168.1.10:80

  # Auto-reconnect client
  python UltronNet.py -t 192.168.1.10 -p 4444 --reconnect
""")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="UltronNet",
        description="UltronNet v2.0 — Advanced Network Swiss Army Knife",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )

    # ── Connection ──────────────────────────────────────────────
    conn = parser.add_argument_group("Connection")
    conn.add_argument("-t", "--target",   default="0.0.0.0",
                      help="Target host (default: 0.0.0.0)")
    conn.add_argument("-p", "--port",     type=int, default=4444,
                      help="Target port (default: 4444)")
    conn.add_argument("-l", "--listen",   action="store_true",
                      help="Listen for incoming connections")
    conn.add_argument("--udp",            action="store_true",
                      help="Use UDP instead of TCP")
    conn.add_argument("--ipv6",           action="store_true",
                      help="Force IPv6 (AF_INET6)")
    conn.add_argument("--reconnect",      action="store_true",
                      help="Auto-reconnect on connection failure")

    # ── Operations ──────────────────────────────────────────────
    ops = parser.add_argument_group("Operations")
    ops.add_argument("-c", "--command",   action="store_true",
                     help="Start interactive command shell")
    ops.add_argument("--pty",             action="store_true",
                     help="Start full PTY interactive shell")
    ops.add_argument("-e", "--execute",   metavar="CMD",
                     help="Execute command on connection")
    ops.add_argument("-u", "--upload",    metavar="PATH",
                     help="Save incoming data to PATH (server side)")
    ops.add_argument("--send-file",       metavar="PATH", dest="send_file",
                     help="Send a file to the server (client side)")
    ops.add_argument("--forward",         metavar="HOST:PORT",
                     help="Forward connections to HOST:PORT")

    # ── SSL/TLS ─────────────────────────────────────────────────
    tls = parser.add_argument_group("SSL/TLS")
    tls.add_argument("--ssl",             action="store_true",
                     help="Enable SSL/TLS encryption")
    tls.add_argument("--cert",            metavar="FILE",
                     help="SSL certificate file (PEM)")
    tls.add_argument("--key",             metavar="FILE",
                     help="SSL private key file (PEM)")

    # ── Misc ────────────────────────────────────────────────────
    misc = parser.add_argument_group("Misc")
    misc.add_argument("-v", "--verbose",  action="store_true",
                      help="Enable debug logging")
    misc.add_argument("--version",        action="version", version="UltronNet 2.0.0")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Update log level
    if args.verbose:
        logging.getLogger("UltronNet").setLevel(logging.DEBUG)

    # Validate mutually exclusive operations
    ops = [args.command, args.pty, bool(args.execute),
           bool(args.upload), bool(args.send_file), bool(args.forward)]
    if sum(bool(o) for o in ops) > 1:
        parser.error(
            "Only one operation may be specified at a time "
            "(-c, --pty, -e, -u, --send-file, --forward)."
        )

    # Read stdin buffer (non-interactive piped data)
    buffer = b""
    if not args.listen and not sys.stdin.isatty():
        buffer = sys.stdin.buffer.read()

    # Create and run
    nc = NetCat(args, buffer)

    # If client wants to send a file, monkey-patch the run to handle it
    if args.send_file and not args.listen:
        _original_tcp_client = nc._tcp_client

        def _send_file_client(sock):
            nc._send_file(sock, args.send_file)

        nc._tcp_client = _send_file_client

    nc.run()


if __name__ == "__main__":
    main()
