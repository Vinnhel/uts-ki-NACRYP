"""
Unit test untuk crypto_core.py.
Minimal 5 test sesuai ketentuan tugas (Bagian 4).
Jalankan dari root folder project: pytest tests/ -v

Tahap 1 (Anggota 1): test untuk derive_key() dan AES-256-GCM.
Test untuk ChaCha20 (Anggota 2) dan avalanche effect (Anggota 3)
akan ditambahkan menyusul.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from crypto_core import (
    encrypt,
    decrypt,
    derive_key,
    DecryptionError,
    ALGO_AES_GCM,
    SALT_SIZE,
    KEY_SIZE,
)


def test_encrypt_decrypt_roundtrip():
    """Plaintext hasil dekripsi harus identik dengan plaintext asli (AES-GCM)."""
    plaintext = b"Data rahasia NACRYP untuk pengujian roundtrip."
    password = "PasswordUjiKuat123!"

    blob = encrypt(plaintext, password, ALGO_AES_GCM)
    hasil = decrypt(blob, password)

    assert hasil == plaintext


def test_decrypt_wrong_password_fails():
    """Dekripsi dengan password salah harus melempar DecryptionError."""
    plaintext = b"Pesan penting"
    blob = encrypt(plaintext, "password_benar", ALGO_AES_GCM)

    with pytest.raises(DecryptionError):
        decrypt(blob, "password_salah")


def test_decrypt_tampered_ciphertext_fails():
    """Dekripsi harus gagal jika 1 byte ciphertext diubah (uji tamper)."""
    plaintext = b"Berkas yang harus tetap utuh"
    password = "sandi_aman_456"
    blob = encrypt(plaintext, password, ALGO_AES_GCM)

    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF

    with pytest.raises(DecryptionError):
        decrypt(bytes(tampered), password)


def test_nonce_unique_per_encryption():
    """Dua enkripsi dgn plaintext & password sama harus hasilkan blob berbeda."""
    plaintext = b"Plaintext yang sama persis"
    password = "sandi_sama_saja"

    blob_1 = encrypt(plaintext, password, ALGO_AES_GCM)
    blob_2 = encrypt(plaintext, password, ALGO_AES_GCM)

    assert blob_1 != blob_2


def test_derive_key_length():
    """derive_key harus mengembalikan key sepanjang 32 byte (256 bit)."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key("password_uji", salt)

    assert len(key) == KEY_SIZE
    assert isinstance(key, bytes)


def test_derive_key_deterministic_given_same_salt():
    """Salt sama + password sama harus hasilkan key yang identik."""
    salt = os.urandom(SALT_SIZE)

    key_a = derive_key("password_konsisten", salt)
    key_b = derive_key("password_konsisten", salt)

    assert key_a == key_b


def test_derive_key_different_salt_gives_different_key():
    """Salt berbeda (password sama) harus hasilkan key yang berbeda."""
    key_a = derive_key("password_sama", os.urandom(SALT_SIZE))
    key_b = derive_key("password_sama", os.urandom(SALT_SIZE))

    assert key_a != key_b
