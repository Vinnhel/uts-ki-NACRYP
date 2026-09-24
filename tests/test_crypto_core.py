"""
Unit test untuk crypto_core.py.
Minimal 5 test sesuai ketentuan tugas (Bagian 4).
Jalankan dari root folder project: pytest tests/ -v

Tahap 2 (Anggota 2): menambahkan test untuk ChaCha20-Poly1305
dan kasus tepi (edge case), melanjutkan test dari Anggota 1.
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
    ALGO_CHACHA20_POLY1305,
    SALT_SIZE,
    KEY_SIZE,
)


# ---------- Test dari Anggota 1 (AES-GCM & key derivation) ----------

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


# ---------- Ditambahkan Anggota 2 (ChaCha20-Poly1305 & edge case) ----------

def test_encrypt_decrypt_roundtrip_chacha20():
    """Roundtrip harus berhasil juga untuk mode ChaCha20-Poly1305."""
    plaintext = b"Uji ChaCha20-Poly1305 oleh Anggota 2"
    password = "sandi_chacha_789"

    blob = encrypt(plaintext, password, ALGO_CHACHA20_POLY1305)
    hasil = decrypt(blob, password)

    assert hasil == plaintext


def test_decrypt_wrong_password_fails_chacha20():
    """Dekripsi ChaCha20 dengan password salah juga harus ditolak."""
    plaintext = b"Pesan rahasia mode ChaCha20"
    blob = encrypt(plaintext, "password_benar_2", ALGO_CHACHA20_POLY1305)

    with pytest.raises(DecryptionError):
        decrypt(blob, "password_salah_2")


def test_encrypt_decrypt_empty_plaintext():
    """Kasus tepi: plaintext kosong (0 byte) tetap harus bisa roundtrip."""
    blob = encrypt(b"", "password_kosong_test", ALGO_AES_GCM)
    hasil = decrypt(blob, "password_kosong_test")

    assert hasil == b""


def test_encrypt_decrypt_binary_file_like_data():
    """Roundtrip untuk data biner acak (mensimulasikan file gambar/PDF)."""
    plaintext = os.urandom(4096)
    password = "password_biner"

    blob = encrypt(plaintext, password, ALGO_AES_GCM)
    hasil = decrypt(blob, password)

    assert hasil == plaintext
