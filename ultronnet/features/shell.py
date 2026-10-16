"""
ultronnet.features.shell
~~~~~~~~~~~~~~~~~~~~~~~~
Interactive command shell and transparent relay handlers.

Two server-side session modes live here:

handle_command_shell(client, cfg)
    A simple line-by-line command shell (no PTY).  Suitable for clients
    that can't handle terminal control sequences.  Reads one line at a
    time, executes it via :func:`~ultronnet.features.executor.execute`,
    and sends back the output followed by the shell prompt.

handle_relay(client)
    Transparent bidirectional relay — classic netcat behaviour.  Pipes
    socket → stdout and stdin → socket in two daemon threads.  No command
    parsing is done; raw bytes flow both ways.

OS / System-call notes
-----------------------
``select.select``
    Used in both handlers to avoid blocking indefinitely on a single
    I/O source.  A timeout of 0.5–1 s lets the threads respond to a
    stop event without busy-looping.

``client.recv(64)`` (command shell)
    Small receive size ensures we accumulate partial lines without
    eating into the next command when multiple keystrokes arrive in one
    TCP segment.

Imports
-------
  stdlib : logging, select, sys, threading
  intra  : ultronnet.config (CFG), ultronnet.features.executor (execute)
"""

import logging
import select
import sys
import threading

from ultronnet.config import CFG
from ultronnet.features.executor import execute

log = logging.getLogger("UltronNet")


def handle_command_shell(client) -> None:
    """Run a line-by-line interactive command shell over *client*.

    Sends the shell prompt after each command response.  Exits cleanly
    on connection loss or timeout.

    Parameters
    ----------
    client:
        Connected socket (TCP or SSL).
    """
    cmd_buf = b""
    client.sendall(CFG.SHELL_PROMPT)

    while True:
        try:
            # Wait for input with timeout (avoids blocking indefinitely)
            r, _, _ = select.select([client], [], [], CFG.RECV_TIMEOUT)
            if not r:
                break

            # Accumulate bytes; use a small read to avoid splitting commands
            chunk = client.recv(64)
            if not chunk:
                break
            cmd_buf += chunk

            # Process complete lines (may contain multiple if pasted quickly)
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


def handle_relay(client) -> None:
    """Pipe *client* ↔ stdout/stdin (classic netcat transparent relay).

    Spawns two daemon threads:
    * ``_sock_to_stdout``  —  socket → sys.stdout.buffer
    * ``_stdin_to_sock``   —  sys.stdin → socket

    Both threads share a ``stop`` event so either side closing causes
    both to exit promptly.

    Parameters
    ----------
    client:
        Connected socket (TCP or SSL).
    """
    stop = threading.Event()

    def _sock_to_stdout() -> None:
        """Forward all bytes from the socket to stdout."""
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

    def _stdin_to_sock() -> None:
        """Forward all lines from stdin to the socket."""
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
