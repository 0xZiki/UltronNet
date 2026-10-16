"""
ultronnet.cli.parser
~~~~~~~~~~~~~~~~~~~~
Argument parsing and top-level ``main()`` entry point.

This is the *only* module that may directly call ``sys.exit()`` and
``parser.error()``.  It is the outermost shell of the application:

    user invokes main.py
        → main()
            → build_parser() → args
            → NetCat(args, buffer).run()

All I/O decisions about *how* to run are made inside :class:`NetCat`;
the CLI only decides *what* the user asked for.

Imports
-------
  stdlib : argparse, logging, sys, textwrap
  intra  : ultronnet.core.engine (NetCat),
           ultronnet.logging_setup (setup_logging)
"""

import argparse
import logging
import sys
import textwrap

from ultronnet.core.engine import NetCat
from ultronnet.logging_setup import setup_logging

# ── Example usage block shown at the bottom of --help ─────────────────────
EXAMPLES = textwrap.dedent("""\
Examples:
  # TCP command shell (listener)
  python main.py -t 0.0.0.0 -p 4444 -l -c

  # TCP connect (interactive)
  python main.py -t 192.168.1.10 -p 4444

  # Pipe stdin to remote
  echo "hello" | python main.py -t 192.168.1.10 -p 4444

  # Upload a file (server side — receive and save)
  python main.py -t 0.0.0.0 -p 4444 -l -u /tmp/received.bin

  # Upload a file (client side — send the file)
  python main.py -t 192.168.1.10 -p 4444 --send-file secret.txt

  # Execute one command on connect
  python main.py -t 0.0.0.0 -p 4444 -l -e "whoami"

  # Full PTY interactive shell
  python main.py -t 0.0.0.0 -p 4444 -l --pty

  # SSL-encrypted command shell
  python main.py -t 0.0.0.0 -p 4444 -l -c --ssl

  # SSL with custom certificate
  python main.py -t 0.0.0.0 -p 4444 -l -c --ssl --cert my.pem --key my.key

  # UDP listener
  python main.py -t 0.0.0.0 -p 4444 -l --udp

  # IPv6 listener
  python main.py -t "::" -p 4444 -l --ipv6 -c

  # Port forwarding: local 8080 → remote 192.168.1.10:80
  python main.py -t 0.0.0.0 -p 8080 -l --forward 192.168.1.10:80

  # Auto-reconnect client
  python main.py -t 192.168.1.10 -p 4444 --reconnect
""")


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the UltronNet argument parser.

    The parser is grouped into four sections (Connection, Operations,
    SSL/TLS, Misc) to keep the --help output readable.

    Returns
    -------
    argparse.ArgumentParser
        Fully configured parser ready for ``parse_args()``.
    """
    parser = argparse.ArgumentParser(
        prog="UltronNet",
        description="UltronNet v2.0 — Advanced Network Swiss Army Knife",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )

    # ── Connection ─────────────────────────────────────────────────────
    conn = parser.add_argument_group("Connection")
    conn.add_argument(
        "-t", "--target", default="0.0.0.0",
        help="Target host (default: 0.0.0.0)",
    )
    conn.add_argument(
        "-p", "--port", type=int, default=4444,
        help="Target port (default: 4444)",
    )
    conn.add_argument(
        "-l", "--listen", action="store_true",
        help="Listen for incoming connections",
    )
    conn.add_argument(
        "--udp", action="store_true",
        help="Use UDP instead of TCP",
    )
    conn.add_argument(
        "--ipv6", action="store_true",
        help="Force IPv6 (AF_INET6)",
    )
    conn.add_argument(
        "--reconnect", action="store_true",
        help="Auto-reconnect on connection failure",
    )

    # ── Operations ─────────────────────────────────────────────────────
    ops = parser.add_argument_group("Operations")
    ops.add_argument(
        "-c", "--command", action="store_true",
        help="Start interactive command shell",
    )
    ops.add_argument(
        "--pty", action="store_true",
        help="Start full PTY interactive shell",
    )
    ops.add_argument(
        "-e", "--execute", metavar="CMD",
        help="Execute command on connection",
    )
    ops.add_argument(
        "-u", "--upload", metavar="PATH",
        help="Save incoming data to PATH (server side)",
    )
    ops.add_argument(
        "--send-file", metavar="PATH", dest="send_file",
        help="Send a file to the server (client side)",
    )
    ops.add_argument(
        "--forward", metavar="HOST:PORT",
        help="Forward connections to HOST:PORT",
    )

    # ── SSL/TLS ────────────────────────────────────────────────────────
    tls = parser.add_argument_group("SSL/TLS")
    tls.add_argument(
        "--ssl", action="store_true",
        help="Enable SSL/TLS encryption",
    )
    tls.add_argument(
        "--cert", metavar="FILE",
        help="SSL certificate file (PEM)",
    )
    tls.add_argument(
        "--key", metavar="FILE",
        help="SSL private key file (PEM)",
    )

    # ── Misc ───────────────────────────────────────────────────────────
    misc = parser.add_argument_group("Misc")
    misc.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    misc.add_argument(
        "--version", action="version", version="UltronNet 2.0.0",
    )

    return parser


def main() -> None:
    """Parse arguments, validate, and run UltronNet."""
    # Bootstrap logging before anything else so early errors are visible
    setup_logging(verbose=False)

    parser = build_parser()
    args = parser.parse_args()

    # Adjust log level now that we know whether --verbose was passed
    if args.verbose:
        logging.getLogger("UltronNet").setLevel(logging.DEBUG)

    # ── Mutual-exclusion guard ─────────────────────────────────────────
    # Exactly one operation may be active at a time.
    active_ops = [
        args.command,
        args.pty,
        bool(args.execute),
        bool(args.upload),
        bool(args.send_file),
        bool(args.forward),
    ]
    if sum(bool(o) for o in active_ops) > 1:
        parser.error(
            "Only one operation may be specified at a time "
            "(-c, --pty, -e, -u, --send-file, --forward)."
        )

    # ── Pre-read stdin buffer (piped mode) ─────────────────────────────
    # If stdin is not a TTY we read all available bytes now so the caller
    # can pipe data:  echo "cmd" | python main.py -t host -p port
    buffer = b""
    if not args.listen and not sys.stdin.isatty():
        buffer = sys.stdin.buffer.read()

    # ── Run ────────────────────────────────────────────────────────────
    nc = NetCat(args, buffer)
    nc.run()
