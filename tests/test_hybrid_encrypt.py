"""
Unit test untuk hybrid_encrypt.py (fitur pengayaan RSA-OAEP + AES-256-GCM).
Jalankan dari root folder project: pytest tests/ -v
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from hybrid_encrypt import (
    generate_keypair,
    hybrid_encrypt,
    hybrid_decrypt,
    private_key_to_pem_bytes,
    public_key_to_pem_bytes,
    private_key_from_pem_bytes,
    public_key_from_pem_bytes,
)


def test_generate_keypair_size():
    """Keypair yang dibuat harus RSA 2048-bit."""
    private_key, public_key = generate_keypair()
    assert private_key.key_size == 2048


def test_hybrid_roundtrip():
    """Enkripsi dengan public key, dekripsi dengan private key pasangannya."""
    private_key, public_key = generate_keypair()
    plaintext = b"Pesan rahasia untuk penerima yang benar"

    blob = hybrid_encrypt(plaintext, public_key)
    hasil = hybrid_decrypt(blob, private_key)

    assert hasil == plaintext


def test_hybrid_decrypt_wrong_private_key_fails():
    """Dekripsi dengan private key yang BUKAN pasangannya harus gagal."""
    _, public_key = generate_keypair()
    private_key_lain, _ = generate_keypair()  # private key tidak berpasangan

    blob = hybrid_encrypt(b"data rahasia", public_key)

    with pytest.raises(ValueError):
        hybrid_decrypt(blob, private_key_lain)


def test_hybrid_decrypt_tampered_blob_fails():
    """Dekripsi harus gagal jika blob (ciphertext) diubah."""
    private_key, public_key = generate_keypair()
    blob = hybrid_encrypt(b"data yang harus tetap utuh", public_key)

    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF

    with pytest.raises(ValueError):
        hybrid_decrypt(bytes(tampered), private_key)


def test_pem_serialization_roundtrip():
    """Kunci hasil serialisasi PEM (untuk upload/download di UI) harus
    tetap berfungsi setelah dimuat ulang."""
    private_key, public_key = generate_keypair()
    passphrase = "passphrase_test_123"

    priv_pem = private_key_to_pem_bytes(private_key, passphrase)
    pub_pem = public_key_to_pem_bytes(public_key)

    priv_loaded = private_key_from_pem_bytes(priv_pem, passphrase)
    pub_loaded = public_key_from_pem_bytes(pub_pem)

    plaintext = b"Tes roundtrip dengan kunci hasil load PEM"
    blob = hybrid_encrypt(plaintext, pub_loaded)
    hasil = hybrid_decrypt(blob, priv_loaded)

    assert hasil == plaintext


def test_private_key_wrong_passphrase_fails():
    """Memuat private key dengan passphrase salah harus melempar error."""
    private_key, _ = generate_keypair()
    priv_pem = private_key_to_pem_bytes(private_key, "passphrase_benar")

    with pytest.raises(Exception):
        private_key_from_pem_bytes(priv_pem, "passphrase_salah")


def test_hybrid_encrypt_empty_plaintext():
    """Kasus tepi: plaintext kosong tetap harus bisa roundtrip."""
    private_key, public_key = generate_keypair()
    blob = hybrid_encrypt(b"", public_key)
    hasil = hybrid_decrypt(blob, private_key)
    assert hasil == b""
