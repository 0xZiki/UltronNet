"""
ultronnet — Advanced Network Swiss Army Knife (modular package).

Public surface
--------------
  __version__  : package version string
  NetCat       : core engine class
  main         : CLI entry point
"""

__version__ = "2.0.0"

# Convenience re-exports so callers can do:
#   from ultronnet import NetCat
#   from ultronnet import main
from ultronnet.core.engine import NetCat          # noqa: F401
from ultronnet.cli.parser  import main            # noqa: F401

__all__ = ["__version__", "NetCat", "main"]
