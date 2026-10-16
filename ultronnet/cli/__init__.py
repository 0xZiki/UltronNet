# ultronnet/cli/__init__.py
"""
ultronnet.cli
~~~~~~~~~~~~~
Command-line interface layer.

Re-exports :func:`main` and :func:`build_parser` for convenience::

    from ultronnet.cli import main, build_parser
"""

from ultronnet.cli.parser import main, build_parser

__all__ = ["main", "build_parser"]
