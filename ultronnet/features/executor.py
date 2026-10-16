"""
ultronnet.features.executor
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cross-platform shell command runner.

A single public function, :func:`execute`, runs an arbitrary shell
command and returns the combined stdout/stderr output as a string.

OS / System-call notes
-----------------------
``subprocess.check_output()``
    Forks a child process, redirects stdout/stderr, waits for exit,
    and returns the output bytes.  ``CalledProcessError`` is raised on
    non-zero exit — we catch it and return the partial output anyway so
    the remote client always sees *something*.

``shlex.split()``
    Safely tokenises a POSIX shell command string without invoking a
    shell interpreter, preventing accidental glob expansion and most
    shell injection vectors.

``shell=True`` (Windows only)
    On Windows there is no ``/bin/sh``; we must pass the command string
    to cmd.exe via ``shell=True`` to support built-ins (``echo``,
    ``dir``, ``set``, etc.).  This is acceptable because the tool is
    already a remote-execution utility.

Imports
-------
  stdlib only — no intra-package imports needed.
"""

import platform
import shlex
import subprocess


def execute(cmd: str) -> str:
    """Run *cmd* in a subprocess and return its combined output.

    Parameters
    ----------
    cmd:
        Shell command string to execute.  Leading/trailing whitespace is
        stripped; an empty string returns ``""`` immediately.

    Returns
    -------
    str
        Combined stdout + stderr of the subprocess, decoded from bytes
        (invalid bytes are replaced with ``\\uFFFD``).  On error,
        a short error description is returned instead of raising.
    """
    cmd = cmd.strip()
    if not cmd:
        return ""

    is_windows = platform.system() == "Windows"

    try:
        if is_windows:
            # Windows: let cmd.exe interpret the command string.
            output = subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        else:
            # POSIX: split the command string safely, exec without shell.
            output = subprocess.check_output(
                shlex.split(cmd),
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        return output.decode(errors="replace")

    except subprocess.CalledProcessError as exc:
        # Non-zero exit — return whatever was produced before the error.
        return exc.output.decode(errors="replace")
    except FileNotFoundError:
        return f"Command not found: {cmd.split()[0]}\n"
    except subprocess.TimeoutExpired:
        return "Command timed out.\n"
