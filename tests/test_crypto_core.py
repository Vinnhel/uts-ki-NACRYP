"""
Unit test untuk crypto_core.py.
Minimal 5 test sesuai ketentuan tugas (Bagian 4).
Jalankan: pytest tests/ -v

TODO (Hari 4): lengkapi setelah crypto_core.py selesai diimplementasikan.
"""

import pytest
# from crypto_core import encrypt, decrypt, derive_key


def test_encrypt_decrypt_roundtrip():
    """Plaintext hasil dekripsi harus identik dengan plaintext asli."""
    pytest.skip("TODO: implementasikan setelah crypto_core siap")


def test_decrypt_wrong_password_fails():
    """Dekripsi dengan password salah harus melempar exception."""
    pytest.skip("TODO")


def test_decrypt_tampered_ciphertext_fails():
    """Dekripsi harus gagal jika 1 byte ciphertext diubah."""
    pytest.skip("TODO")


def test_nonce_unique_per_encryption():
    """Dua enkripsi dengan plaintext & password sama harus hasilkan blob berbeda."""
    pytest.skip("TODO")


def test_derive_key_length():
    """derive_key harus mengembalikan key sepanjang 32 byte (256 bit)."""
    pytest.skip("TODO")


def test_derive_key_deterministic_given_same_salt():
    """Salt sama + password sama harus hasilkan key yang sama."""
    pytest.skip("TODO")
