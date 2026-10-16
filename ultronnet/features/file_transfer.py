"""
ultronnet.features.file_transfer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
File upload/download with live progress tracking.

Wire protocol (length-prefixed framing)
----------------------------------------
Every file transfer begins with a fixed 12-byte header::

    ┌─────────────┬──────────────────────────┐
    │ Magic  4 B  │  File size  8 B (uint64) │
    └─────────────┴──────────────────────────┘

Magic = ``\\xDE\\xAD\\xBE\\xEF`` — validated by the receiver to detect
framing errors or protocol mismatches before reading a potentially huge
payload.

The body immediately follows the header as raw bytes.  No chunking
delimiter or end-of-file marker is needed because the receiver knows
exactly how many bytes to expect from the header.

Classes / Functions
-------------------
ProgressTracker   Thread-safe progress display (tqdm or fallback).
send_file()       Client-side: send header + body, wait for ACK.
recv_file()       Server-side: read header + body, write to disk.

Imports
-------
  stdlib : logging, struct, sys, time, pathlib
  optional: tqdm (detected at import; graceful fallback)
  intra  : ultronnet.config (CFG only)
"""

import logging
import struct
import sys
import time
from pathlib import Path
from typing import Optional

from ultronnet.config import CFG

log = logging.getLogger("UltronNet")

# ── Optional dependency: tqdm ──────────────────────────────────────────────
try:
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# Progress Tracker
# ═══════════════════════════════════════════════════════════════════════════

class ProgressTracker:
    """Live progress display for file transfers.

    Uses ``tqdm`` when available; falls back to a simple percentage /
    speed line written to ``stderr`` otherwise.

    Parameters
    ----------
    total:
        Expected total byte count.
    description:
        Label shown in the progress bar.
    """

    def __init__(self, total: int, description: str = "Transfer") -> None:
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
        """Advance the tracker by *n* bytes."""
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
        """Finalise and clean up the progress display."""
        if self._bar:
            self._bar.close()
        else:
            elapsed = time.time() - self._start
            sys.stderr.write(
                f"\n✔ Done: {self._fmt(self.sent)} in {elapsed:.2f}s\n"
            )

    @staticmethod
    def _fmt(size: float) -> str:
        """Human-readable byte size (B → KB → MB → GB → TB)."""
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"


# ═══════════════════════════════════════════════════════════════════════════
# Transfer functions
# ═══════════════════════════════════════════════════════════════════════════

def send_file(sock, file_path: str) -> None:
    """Send a file to *sock* using the length-prefixed protocol.

    Intended for the *client* side when the server is listening with
    ``--upload``.  Sends the header, streams the body in chunks, then
    waits for the server's acknowledgement message.

    Parameters
    ----------
    sock:
        Connected socket (TCP or SSL).
    file_path:
        Filesystem path of the file to send.
    """
    path = Path(file_path)
    if not path.exists():
        log.error("File not found: %s", file_path)
        return

    data = path.read_bytes()
    file_size = len(data)

    # Build and send the 12-byte framing header
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

    # Block until the server acknowledges receipt
    try:
        ack = sock.recv(CFG.BUFFER_SIZE)
        log.info("Server: %s", ack.decode(errors="replace").strip())
    except Exception:
        log.warning("No ACK received from server.")


def recv_file(sock, dest_path: str, recv_fn=None) -> Optional[str]:
    """Receive a file from *sock* and write it to *dest_path*.

    Intended for the *server* side handler (``--upload`` mode).
    Validates the magic bytes, reads the declared payload length,
    tracks progress, writes the file, and sends an ACK back to the
    sender.

    Parameters
    ----------
    sock:
        Connected socket (TCP or SSL).
    dest_path:
        Filesystem path where the received file will be written.
    recv_fn:
        Optional callable ``(sock, n) -> Optional[bytes]`` for reading
        exactly *n* bytes.  Defaults to the standard ``recv_exactly``
        from ``socket_utils``.

    Returns
    -------
    str or None
        The resolved destination path on success, or ``None`` on error.
    """
    from ultronnet.core.socket_utils import recv_exactly  # local import avoids cycle

    if recv_fn is None:
        recv_fn = recv_exactly

    # ── Read 12-byte header ────────────────────────────────────────────
    header = recv_fn(sock, CFG.FILE_HEADER_SIZE)
    if header is None:
        sock.sendall(b"ERROR: Header receive failed.\n")
        return None

    magic, file_size = struct.unpack(CFG.FILE_HEADER_FMT, header)
    if magic != CFG.FILE_MAGIC:
        sock.sendall(b"ERROR: Invalid file magic.\n")
        return None

    log.info("Receiving file: %d bytes → %s", file_size, dest_path)

    # ── Stream body ────────────────────────────────────────────────────
    tracker = ProgressTracker(file_size, f"Receiving {Path(dest_path).name}")
    received = b""

    while len(received) < file_size:
        chunk = sock.recv(min(CFG.CHUNK_SIZE, file_size - len(received)))
        if not chunk:
            break
        received += chunk
        tracker.update(len(chunk))

    tracker.close()

    # ── Write to disk ──────────────────────────────────────────────────
    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    Path(dest_path).write_bytes(received)

    msg = f"✔ Saved {len(received)} bytes to {dest_path}\n"
    log.info(msg.strip())
    sock.sendall(msg.encode())

    return dest_path
