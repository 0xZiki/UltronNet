"""
ultronnet.core.socket_utils
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Low-level socket helper functions.

These three primitives sit at the very bottom of the import DAG: they
depend only on the Python standard library and ``ultronnet.config``.
No feature module or engine code lives here so that feature modules can
import freely without creating cycles.

Functions
---------
detect_af(host)     Resolve IPv4 vs. IPv6 address family.
safe_close(sock)    Silently close any socket-like object.
recv_exactly(sock, n)  Read exactly *n* bytes or return None.

OS / System-call notes
-----------------------
``socket.AF_INET``  — traditional IPv4.
``socket.AF_INET6`` — IPv6; the engine also tries to enable dual-stack
                      via ``IPV6_V6ONLY = 0`` where the platform allows.
``sock.recv()``     — may return fewer bytes than requested; recv_exactly
                      loops until the full frame arrives.
"""

import ipaddress
import socket
from typing import Optional


def detect_af(host: str) -> socket.AddressFamily:
    """Return the address family for *host*.

    Strips surrounding brackets (``[::1]`` style) before trying to parse
    as an IPv6 address.  Falls back to ``AF_INET`` for anything that is
    not a valid IPv6 literal (hostnames, plain IPv4 strings, etc.).

    Parameters
    ----------
    host:
        Hostname or IP address string.

    Returns
    -------
    socket.AddressFamily
        ``AF_INET6`` for IPv6 literals, ``AF_INET`` for everything else.
    """
    try:
        ipaddress.IPv6Address(host.strip("[]"))
        return socket.AF_INET6
    except ValueError:
        return socket.AF_INET


def safe_close(sock) -> None:
    """Close *sock* without raising any exception.

    Accepts any object with a ``.close()`` method (plain sockets, SSL
    sockets, file-like objects).  Silently swallows all errors so callers
    in ``finally`` blocks never risk masking the original exception.
    """
    try:
        sock.close()
    except Exception:
        pass


def recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly *n* bytes from *sock*.

    TCP is a stream protocol — a single ``recv()`` call may return
    anywhere from 1 byte up to the requested amount.  This helper loops
    until the full *n*-byte payload has been assembled, or returns
    ``None`` if the connection closes early or an OS error occurs.

    Parameters
    ----------
    sock:
        Connected TCP (or SSL) socket.
    n:
        Exact number of bytes to read.

    Returns
    -------
    bytes or None
        The assembled payload, or ``None`` on connection loss / error.
    """
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
