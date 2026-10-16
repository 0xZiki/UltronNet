"""
ultronnet.features.port_forwarder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Bidirectional TCP port forwarder.

Listens on a local port and, for every accepted connection, opens a
corresponding connection to the remote target and pipes data in both
directions using two daemon threads per session.

OS / System-call notes
-----------------------
``SO_REUSEADDR``
    Allows the listener to re-bind immediately after a crash without
    waiting for the TIME_WAIT state to expire (typically 2 × MSL).

``select.select([src], [], [], 1.0)``
    Non-blocking poll with a 1-second timeout so the pipe threads can
    check the ``stop`` event without busy-waiting.

``socket.settimeout(1.0)`` on the server socket
    Makes ``accept()`` return ``socket.timeout`` rather than blocking
    indefinitely, letting the main loop check ``_stop_event`` regularly.

Imports
-------
  stdlib : logging, select, socket, threading
  intra  : ultronnet.config (CFG), ultronnet.core.socket_utils,
           ultronnet.crypto.manager (CryptoManager)
"""

import logging
import select
import socket
import threading

from ultronnet.config import CFG
from ultronnet.core.socket_utils import detect_af, safe_close
from ultronnet.crypto.manager import CryptoManager

log = logging.getLogger("UltronNet")


class PortForwarder:
    """Bidirectional TCP port forwarder.

    Accepts connections on ``(listen_host, listen_port)`` and transparently
    relays all traffic to/from ``(remote_host, remote_port)``.

    Parameters
    ----------
    listen_host, listen_port:
        Local address to bind the accepting socket.
    remote_host, remote_port:
        Upstream address to connect each accepted session to.
    use_ssl:
        When *True*, the *upstream* (remote) connection is wrapped with a
        TLS client context (the accepting side is left as plain TCP).
    ssl_cert, ssl_key:
        Unused currently — reserved for future mutual-auth extension.
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
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.use_ssl = use_ssl
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self._stop_event = threading.Event()

    # ── Public control ─────────────────────────────────────────────────
    def start(self) -> None:
        """Block and accept forwarding sessions until interrupted."""
        family = detect_af(self.listen_host)
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(CFG.BACKLOG)
        srv.settimeout(1.0)   # allows periodic _stop_event checks

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
        """Signal the accept loop to terminate."""
        self._stop_event.set()

    # ── Per-session handler ────────────────────────────────────────────
    def _handle_forward(self, client: socket.socket) -> None:
        """Open upstream connection and start bidirectional pipe threads."""
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
            """Relay bytes from *src* to *dst* until one side closes."""
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
