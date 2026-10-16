"""
ultronnet.config
~~~~~~~~~~~~~~~~
Central configuration layer for UltronNet.

This module is the ONLY module that may be imported by every other module
without restriction.  It has NO intra-package imports.

Constants defined here cover:
  - Network tunables (buffer sizes, timeouts, backlog, retry policy)
  - SSL/TLS defaults
  - File-transfer framing magic bytes and struct format
  - Shell prompt bytes
  - Logging format strings
"""

import ssl
from dataclasses import dataclass, field  # noqa: F401 (field kept for subclasses)
from pathlib import Path


@dataclass
class UltronConfig:
    """Central configuration and compile-time constants.

    Instantiate once as the module-level singleton ``CFG``.  All other
    modules import ``CFG`` directly — they never construct their own copy.
    """

    # ── Network ────────────────────────────────────────────────────────────
    BUFFER_SIZE: int        = 65536     # recv() call buffer — 64 KiB
    CHUNK_SIZE: int         = 8192      # File-transfer chunk size — 8 KiB
    BACKLOG: int            = 10        # listen() backlog queue depth
    CONNECT_TIMEOUT: float  = 10.0     # TCP connect timeout (seconds)
    RECV_TIMEOUT: float     = 30.0     # recv() idle timeout (seconds)
    RECONNECT_DELAY: float  = 3.0      # Sleep between reconnect attempts
    MAX_RECONNECT: int      = 5        # Maximum auto-reconnect iterations

    # ── SSL/TLS ────────────────────────────────────────────────────────────
    DEFAULT_CERT: str       = "ultron_cert.pem"
    DEFAULT_KEY: str        = "ultron_key.pem"
    # Minimum acceptable TLS version (TLSv1.2 bars weak legacy handshakes)
    SSL_MIN_VERSION: int    = ssl.TLSVersion.TLSv1_2

    # ── Shell ──────────────────────────────────────────────────────────────
    # Prompt bytes sent over the wire to the remote client after each command.
    SHELL_PROMPT: bytes     = b"\r\nUltronNet #> "

    # ── File transfer framing ──────────────────────────────────────────────
    # 4-byte magic sentinel that precedes every file-transfer header so the
    # receiver can detect framing errors early.
    FILE_MAGIC: bytes       = b"\xDE\xAD\xBE\xEF"
    # Struct format: network byte-order, 4s magic + Q (uint64) file size = 12 B
    FILE_HEADER_FMT: str    = "!4sQ"
    FILE_HEADER_SIZE: int   = 12       # struct.calcsize("!4sQ")

    # ── Logging ────────────────────────────────────────────────────────────
    LOG_FORMAT: str         = "%(asctime)s [%(levelname)s] %(message)s"
    LOG_DATE_FMT: str       = "%H:%M:%S"


# ── Module-level singleton ─────────────────────────────────────────────────
# Every other module does: ``from ultronnet.config import CFG``
CFG: UltronConfig = UltronConfig()

# Resolve the package root so other modules can build absolute paths.
TOOL_DIR: Path = Path(__file__).parent.resolve()
