# ultronnet/core/__init__.py
"""
ultronnet.core
~~~~~~~~~~~~~~
Low-level network primitives used by the engine and feature modules.

Re-exports from sub-modules for convenient star-imports inside the package:

    from ultronnet.core import detect_af, safe_close, recv_exactly
"""

from ultronnet.core.socket_utils import detect_af, safe_close, recv_exactly

__all__ = ["detect_af", "safe_close", "recv_exactly"]
