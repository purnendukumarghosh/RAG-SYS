import base64
import shutil
import subprocess

import pytest

from nimbusvpn.crypto import (
    DecryptionError,
    InvalidKeyError,
    SecretBox,
    decode_key,
    derive_key,
    generate_keypair,
    generate_preshared_key,
    is_valid_key,
    public_key_from_private,
)


def test_x25519_rfc7748_vector():
    # RFC 7748 section 6.1: Alice's private and public key.
    private = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert (
        public_key_from_private(base64.b64encode(private).decode())
        == base64.b64encode(public).decode()
    )


def test_generated_keypair_is_clamped_and_consistent():
    keys = generate_keypair()
    raw = decode_key(keys.private_key)
    assert raw[0] & 7 == 0
    assert raw[31] & 128 == 0 and raw[31] & 64 == 64
    assert public_key_from_private(keys.private_key) == keys.public_key
    assert len(keys.public_key) == 44 and is_valid_key(keys.public_key)


def test_keys_are_unique():
    assert len({generate_keypair().private_key for _ in range(50)}) == 50
    assert len({generate_preshared_key() for _ in range(50)}) == 50


@pytest.mark.skipif(shutil.which("wg") is None, reason="wireguard-tools not installed")
def test_matches_wg_pubkey():
    keys = generate_keypair()
    out = subprocess.run(
        ["wg", "pubkey"], input=keys.private_key, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == keys.public_key


@pytest.mark.parametrize("bad", ["", "not base64!", base64.b64encode(b"short").decode(), "A" * 44])
def test_invalid_keys_rejected(bad):
    assert not is_valid_key(bad)
    with pytest.raises(InvalidKeyError):
        decode_key(bad)


def test_secret_box_roundtrip_and_context_binding():
    box = SecretBox("x" * 40)
    token = box.encrypt("top secret", "psk:abc")
    assert token.startswith("v1:") and "top secret" not in token
    assert box.decrypt(token, "psk:abc") == "top secret"
    with pytest.raises(DecryptionError):
        box.decrypt(token, "psk:other")  # copied onto another record
    with pytest.raises(DecryptionError):
        SecretBox("y" * 40).decrypt(token, "psk:abc")  # wrong master key


def test_secret_box_detects_tampering():
    box = SecretBox("x" * 40)
    token = box.encrypt("value", "ctx")
    raw = bytearray(base64.urlsafe_b64decode(token[3:]))
    raw[-1] ^= 1
    with pytest.raises(DecryptionError):
        box.decrypt("v1:" + base64.urlsafe_b64encode(bytes(raw)).decode(), "ctx")
    with pytest.raises(DecryptionError):
        box.decrypt("garbage", "ctx")


def test_derived_keys_are_independent():
    assert derive_key("m" * 40, "a") != derive_key("m" * 40, "b")
    assert derive_key("m" * 40, "a") == derive_key("m" * 40, "a")
