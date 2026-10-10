"""Key material: WireGuard keys, at-rest encryption, and key derivation.

WireGuard itself provides the tunnel cryptography (Noise_IKpsk2 with Curve25519,
ChaCha20-Poly1305 and BLAKE2s). This module only produces keys in WireGuard's format
and protects the secrets the control plane has to persist.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
_ENC_PREFIX = "v1:"


class InvalidKeyError(ValueError):
    """Raised for malformed WireGuard keys."""


class DecryptionError(ValueError):
    """Raised when ciphertext is corrupt, tampered with, or bound to a different context."""


@dataclass(frozen=True)
class KeyPair:
    private_key: str
    public_key: str


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_key(key: str) -> bytes:
    """Decode a base64 WireGuard key, enforcing the exact 32-byte length."""
    try:
        raw = base64.b64decode(key.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidKeyError("key is not valid base64") from exc
    if len(raw) != KEY_LEN:
        raise InvalidKeyError("key must decode to exactly 32 bytes")
    return raw


def is_valid_key(key: str) -> bool:
    try:
        decode_key(key)
    except InvalidKeyError:
        return False
    return True


def _clamp(raw: bytes) -> bytes:
    # Same clamping as `wg genkey` (RFC 7748 section 5).
    key = bytearray(raw)
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64
    return bytes(key)


def public_key_from_private(private_key: str) -> str:
    raw = decode_key(private_key)
    pub = X25519PrivateKey.from_private_bytes(raw).public_key()
    return _b64(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def generate_keypair() -> KeyPair:
    """Equivalent of ``wg genkey | tee priv | wg pubkey``."""
    private_key = _b64(_clamp(os.urandom(KEY_LEN)))
    return KeyPair(private_key=private_key, public_key=public_key_from_private(private_key))


def generate_preshared_key() -> str:
    """Equivalent of ``wg genpsk``; adds a symmetric layer for post-quantum resistance."""
    return _b64(secrets.token_bytes(KEY_LEN))


def derive_key(master_secret: str, purpose: str) -> bytes:
    """Derive an independent 256-bit key per purpose from the master secret (HKDF-SHA256)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=b"nimbusvpn/hkdf-salt/v1",
        info=f"nimbusvpn/{purpose}/v1".encode(),
    ).derive(master_secret.encode("utf-8"))


class SecretBox:
    """AES-256-GCM authenticated encryption for secrets stored on disk.

    Each value is bound to a context string (e.g. ``psk:<public key>``) through the
    AEAD associated data, so a ciphertext copied onto another record fails to decrypt.
    """

    def __init__(self, master_secret: str):
        self._aead = AESGCM(derive_key(master_secret, "at-rest-encryption"))

    def encrypt(self, plaintext: str, context: str) -> str:
        nonce = os.urandom(12)
        ciphertext = self._aead.encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
        return _ENC_PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str, context: str) -> str:
        if not token.startswith(_ENC_PREFIX):
            raise DecryptionError("unknown ciphertext format")
        try:
            blob = base64.urlsafe_b64decode(token[len(_ENC_PREFIX) :])
            nonce, ciphertext = blob[:12], blob[12:]
            plaintext = self._aead.decrypt(nonce, ciphertext, context.encode("utf-8"))
        except Exception as exc:  # InvalidTag, binascii.Error, ...
            raise DecryptionError("ciphertext failed authentication") from exc
        return plaintext.decode("utf-8")
