"""
ultronnet.logging_setup
~~~~~~~~~~~~~~~~~~~~~~~
Logging initialisation for UltronNet.

Provides a single helper that configures the root ``"UltronNet"`` logger
and returns it.  All other modules obtain the logger via::

    import logging
    log = logging.getLogger("UltronNet")

so they never need to import this module directly — only the CLI entry
point and the package ``__init__`` call :func:`setup_logging` once.

Imports
-------
  stdlib only + ultronnet.config (CFG)
"""

import logging
import sys

from ultronnet.config import CFG


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the ``"UltronNet"`` logger.

    Parameters
    ----------
    verbose:
        When *True*, set the level to ``DEBUG``; otherwise ``INFO``.

    Returns
    -------
    logging.Logger
        The configured logger instance.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=CFG.LOG_FORMAT,
        datefmt=CFG.LOG_DATE_FMT,
        handlers=[logging.StreamHandler(sys.stderr)],
    )
    return logging.getLogger("UltronNet")
