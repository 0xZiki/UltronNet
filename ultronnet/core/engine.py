"""
ultronnet.core.engine
~~~~~~~~~~~~~~~~~~~~~
Core UltronNet network engine — the ``NetCat`` class.

This module owns the top-level execution logic:
  * Mode selection (listen / connect / forward)
  * TCP/UDP listener creation and SSL wrapping
  * Client connection with optional auto-reconnect
  * Per-connection handler dispatch (execute, upload, command, PTY, relay)
  * SSL certificate auto-provisioning

It is the only module allowed to import from *all* layers:

    config  ←  core.socket_utils  ←  crypto  ←  features  ←  engine

OS / System-call notes
-----------------------
``SO_REUSEADDR``
    Allows the server to re-bind the port immediately after restart
    without waiting for the kernel's TIME_WAIT timeout.

``IPV6_V6ONLY = 0``
    On dual-stack platforms (Linux, macOS ≥ 10.5) this lets an IPv6
    wildcard socket also accept IPv4 connections via the ``::ffff:0:0/96``
    mapped address range.

``sock.settimeout(1.0)`` on listeners
    Converts ``accept()`` from blocking to non-blocking (with a 1-second
    window) so the main thread can check the stop-event between calls.

``ssl.SSLContext.wrap_socket()``
    Upgrades a plain TCP socket to TLS *after* the OS-level connection
    is established (TLS over TCP — not DTLS).

Imports
-------
  stdlib  : argparse, logging, select, socket, ssl, sys, threading, time
  intra   : config, core.socket_utils, crypto.manager, features.*
"""

import argparse
import logging
import select
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

from ultronnet.config import CFG
from ultronnet.core.socket_utils import detect_af, safe_close, recv_exactly
from ultronnet.crypto.manager import CryptoManager
from ultronnet.features.executor import execute
from ultronnet.features.file_transfer import send_file, recv_file
from ultronnet.features.port_forwarder import PortForwarder
from ultronnet.features.pty_handler import PTYHandler
from ultronnet.features.shell import handle_command_shell, handle_relay

log = logging.getLogger("UltronNet")


class NetCat:
    """Core UltronNet engine.

    Instantiated by the CLI with a parsed ``argparse.Namespace`` and an
    optional pre-read stdin buffer.  Call :meth:`run` to start.

    Parameters
    ----------
    args:
        Parsed CLI arguments (see :mod:`ultronnet.cli.parser`).
    buffer:
        Bytes read from stdin before the connection was established
        (used to pipe data into the remote on connect).
    """

    def __init__(self, args: argparse.Namespace, buffer: bytes = b"") -> None:
        self.args = args
        self.buffer = buffer
        self._stop = threading.Event()

        # Resolve address family (explicit --ipv6 flag or auto-detect)
        self.af = (
            socket.AF_INET6 if args.ipv6 else detect_af(args.target)
        )

        # Socket type: datagram for UDP, stream for TCP
        self.sock_type = (
            socket.SOCK_DGRAM if args.udp else socket.SOCK_STREAM
        )

    # ── Public entry point ─────────────────────────────────────────────
    def run(self) -> None:
        """Top-level dispatcher — select mode and run until done."""
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

    # ── Port-forwarding mode ───────────────────────────────────────────
    def _start_forwarder(self) -> None:
        """Parse the --forward HOST:PORT argument and start the forwarder."""
        remote_host, remote_port_str = self.args.forward.rsplit(":", 1)
        remote_port = int(remote_port_str)
        fwd = PortForwarder(
            listen_host=self.args.target,
            listen_port=self.args.port,
            remote_host=remote_host,
            remote_port=remote_port,
            use_ssl=self.args.ssl,
            ssl_cert=self.args.cert or "",
            ssl_key=self.args.key or "",
        )
        fwd.start()

    # ── Client (connect) mode ──────────────────────────────────────────
    def _connect(self) -> None:
        """Open a connection (with optional auto-reconnect)."""
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

                break  # clean exit — don't reconnect

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
        """Interactive TCP client loop — read from server, write from stdin."""
        sock.settimeout(CFG.RECV_TIMEOUT)

        # If --send-file was given, use the file-transfer protocol instead
        if self.args.send_file:
            send_file(sock, self.args.send_file)
            return

        # Flush any pre-read stdin buffer
        if self.buffer:
            sock.sendall(self.buffer)

        try:
            while not self._stop.is_set():
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
        """Simple UDP client: send lines from stdin, print received datagrams."""
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
                    data, _addr = sock.recvfrom(CFG.BUFFER_SIZE)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass

    # ── Server (listen) mode ───────────────────────────────────────────
    def _listen(self) -> None:
        """Branch to the appropriate listener based on --udp."""
        if self.args.udp:
            self._udp_server()
        else:
            self._tcp_server()

    def _tcp_server(self) -> None:
        """Multi-threaded TCP listener — accepts one thread per client."""
        srv = socket.socket(self.af, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.af == socket.AF_INET6:
            # Enable dual-stack (accept IPv4-mapped addresses) where supported
            try:
                srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except AttributeError:
                pass

        srv.bind((self.args.target, self.args.port))
        srv.listen(CFG.BACKLOG)
        srv.settimeout(1.0)

        # Prepare SSL context if requested
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
                        client = ssl_ctx.wrap_socket(client, server_side=True)
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
        """UDP server — receive datagrams and optionally execute commands."""
        srv = socket.socket(self.af, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.args.target, self.args.port))
        srv.settimeout(1.0)

        log.info("UDP Listening on %s:%d", self.args.target, self.args.port)

        try:
            while not self._stop.is_set():
                try:
                    data, addr = srv.recvfrom(CFG.BUFFER_SIZE)
                except socket.timeout:
                    continue
                log.info(
                    "UDP datagram from %s:%d (%d bytes)",
                    addr[0], addr[1], len(data),
                )

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

    # ── Per-connection dispatcher ──────────────────────────────────────
    def _handle(self, client: socket.socket, addr: Tuple) -> None:
        """Dispatch an accepted connection to the correct feature handler."""
        try:
            client.settimeout(CFG.RECV_TIMEOUT)

            if self.args.execute:
                output = execute(self.args.execute)
                client.sendall(output.encode())
            elif self.args.upload:
                recv_file(client, self.args.upload, recv_fn=recv_exactly)
            elif self.args.command:
                handle_command_shell(client)
            elif self.args.pty:
                PTYHandler.spawn_pty(client)
            else:
                handle_relay(client)

        except (ConnectionResetError, BrokenPipeError) as exc:
            log.warning("Client %s:%d disconnected: %s", addr[0], addr[1], exc)
        except Exception as exc:
            log.exception(
                "Handler error for %s:%d → %s", addr[0], addr[1], exc
            )
        finally:
            safe_close(client)
            log.info("Session with %s:%d closed.", addr[0], addr[1])

    # ── SSL file provisioning ──────────────────────────────────────────
    def _ensure_ssl_files(self) -> Tuple[str, str]:
        """Return (cert_path, key_path), auto-generating files if needed.

        User-supplied paths are used as-is.  Default paths resolve to
        ``~/.ultronnet/`` so generated certificates persist across
        invocations without cluttering the working directory.
        """
        cert = self.args.cert or CFG.DEFAULT_CERT
        key  = self.args.key  or CFG.DEFAULT_KEY

        user_home = Path.home() / ".ultronnet"
        user_home.mkdir(parents=True, exist_ok=True)

        if self.args.cert or self.args.key:
            cert_path = Path(cert)
            key_path  = Path(key)
        else:
            cert_path = user_home / cert
            key_path  = user_home / key

        if not cert_path.exists() or not key_path.exists():
            CryptoManager.generate_self_signed(str(cert_path), str(key_path))

        return str(cert_path), str(key_path)
