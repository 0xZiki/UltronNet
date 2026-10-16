"""
ultronnet.crypto.manager
~~~~~~~~~~~~~~~~~~~~~~~~
SSL/TLS context creation and self-signed certificate generation.

This module wraps Python's ``ssl`` standard library and, optionally, the
third-party ``cryptography`` package to auto-generate RSA-2048 self-signed
certificates on first run.

OS / System-call notes
-----------------------
``ssl.SSLContext``           — Python wrapper around OpenSSL.
``ssl.PROTOCOL_TLS_SERVER`` — negotiates highest mutually-supported TLS
                               version as the *accepting* side.
``ssl.PROTOCOL_TLS_CLIENT`` — same but as the *initiating* side; by
                               default enforces hostname checking which
                               we disable for self-signed / lab usage.
``ctx.minimum_version``     — floors negotiation at TLSv1.2, rejecting
                               old SSLv3/TLS1.0/TLS1.1 handshakes.

Imports
-------
  stdlib : ssl, ipaddress, logging
  optional: cryptography (detected at import time; graceful degradation)
  intra  : ultronnet.config (CFG only)
"""

import ipaddress
import logging
import ssl
from pathlib import Path

from ultronnet.config import CFG

log = logging.getLogger("UltronNet")

# ── Optional dependency: cryptography ─────────────────────────────────────
try:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class CryptoManager:
    """Handles SSL/TLS context creation and certificate management.

    All methods are static — there is no shared mutable state.

    Certificate auto-generation requires the ``cryptography`` package.
    If it is absent, :meth:`generate_self_signed` raises a descriptive
    ``RuntimeError`` rather than crashing with an ``ImportError``.
    """

    # ── Certificate generation ─────────────────────────────────────────
    @staticmethod
    def generate_self_signed(cert_path: str, key_path: str) -> None:
        """Generate a self-signed RSA-2048 certificate and write it to disk.

        The certificate is valid for 10 years and carries a SAN for both
        ``localhost`` and ``127.0.0.1`` so local testing works without
        further CA trust configuration.

        Parameters
        ----------
        cert_path:
            Filesystem path for the PEM-encoded certificate.
        key_path:
            Filesystem path for the PEM-encoded private key.

        Raises
        ------
        RuntimeError
            If the ``cryptography`` package is not installed.
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError(
                "Package 'cryptography' is required for SSL certificate generation.\n"
                "Install it with: pip install cryptography"
            )

        log.info("Generating self-signed certificate …")

        # RSA private key — 2048-bit, public exponent F4 (65537)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

        # Identical subject / issuer makes this a self-signed (root) cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UltronNet"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ultronnet.local"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Write private key (PEM, unencrypted — suitable for server use)
        Path(key_path).write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

        # Write certificate (PEM)
        Path(cert_path).write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        log.info("Certificate saved: %s  |  Key saved: %s", cert_path, key_path)

    # ── Context factories ──────────────────────────────────────────────
    @staticmethod
    def server_context(cert: str, key: str) -> ssl.SSLContext:
        """Return an SSL context configured for the *server* (listener) side.

        Parameters
        ----------
        cert:
            Path to the PEM certificate file.
        key:
            Path to the PEM private key file.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = CFG.SSL_MIN_VERSION
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    @staticmethod
    def client_context(verify: bool = False) -> ssl.SSLContext:
        """Return an SSL context configured for the *client* side.

        Parameters
        ----------
        verify:
            When *False* (default), disable hostname checking and
            certificate verification so self-signed certs are accepted
            without error.  Suitable for pentest / lab environments.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = CFG.SSL_MIN_VERSION
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx
