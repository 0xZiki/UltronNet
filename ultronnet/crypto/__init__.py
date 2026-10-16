# ultronnet/crypto/__init__.py
"""
ultronnet.crypto
~~~~~~~~~~~~~~~~
SSL/TLS layer.

Re-exports :class:`CryptoManager` so callers can write::

    from ultronnet.crypto import CryptoManager
"""

from ultronnet.crypto.manager import CryptoManager

__all__ = ["CryptoManager"]
