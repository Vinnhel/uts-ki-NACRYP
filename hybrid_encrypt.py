"""
hybrid_encrypt.py
Fitur pengayaan NACRYP: Enkripsi Hibrida (RSA-OAEP + AES-256-GCM).

Konsep:
  - Setiap enkripsi membuat SESSION KEY AES-256 acak yang baru.
  - Session key ini dibungkus (di-enkripsi) memakai kunci PUBLIK RSA
    penerima (RSA-OAEP), bukan diturunkan dari password.
  - Data sesungguhnya dienkripsi dengan AES-256-GCM memakai session key.
  - Untuk dekripsi, penerima memakai kunci PRIVAT RSA miliknya untuk
    membuka session key, lalu memakai session key itu untuk dekripsi data.

Keuntungan dibanding mode password biasa:
  - Pengirim tidak perlu tahu/berbagi password rahasia dengan penerima.
  - Pengirim cukup punya kunci PUBLIK penerima (boleh disebar bebas).
  - Hanya pemilik kunci PRIVAT yang bisa membuka data.

Format blob hibrida:
  [2 byte panjang session_key terenkripsi][session_key terenkripsi RSA]
  [12 byte nonce AES][ciphertext+tag AES-GCM]
"""

import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 2048
AES_SESSION_KEY_SIZE = 32   # AES-256
NONCE_SIZE = 12


# =====================================================================
# PEMBUATAN & PENYIMPANAN PASANGAN KUNCI RSA
# =====================================================================

def generate_keypair():
    """
    Membuat pasangan kunci RSA 2048-bit baru.

    Returns:
        (private_key, public_key) — objek kunci dari library `cryptography`.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, path: str, passphrase: str):
    """
    Menyimpan kunci privat ke berkas PEM, TERENKRIPSI dengan passphrase.
    Kunci privat tidak boleh pernah disimpan dalam bentuk plain/tanpa
    proteksi (sesuai Ketentuan Teknis Umum, Bagian 4 dokumen tugas).
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key(public_key, path: str):
    """Menyimpan kunci publik ke berkas PEM (boleh disebar bebas, tidak rahasia)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str, passphrase: str):
    """Memuat kunci privat dari berkas PEM, memakai passphrase untuk membuka."""
    with open(path, "rb") as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(
        pem_data, password=passphrase.encode("utf-8")
    )


def load_public_key(path: str):
    """Memuat kunci publik dari berkas PEM."""
    with open(path, "rb") as f:
        pem_data = f.read()
    return serialization.load_pem_public_key(pem_data)


def private_key_to_pem_bytes(private_key, passphrase: str) -> bytes:
    """Serialisasi kunci privat ke bytes PEM (untuk keperluan UI/download)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    )


def public_key_to_pem_bytes(public_key) -> bytes:
    """Serialisasi kunci publik ke bytes PEM (untuk keperluan UI/download)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_from_pem_bytes(pem_bytes: bytes, passphrase: str):
    """Deserialisasi kunci privat dari bytes PEM (untuk keperluan UI/upload)."""
    return serialization.load_pem_private_key(
        pem_bytes, password=passphrase.encode("utf-8")
    )


def public_key_from_pem_bytes(pem_bytes: bytes):
    """Deserialisasi kunci publik dari bytes PEM (untuk keperluan UI/upload)."""
    return serialization.load_pem_public_key(pem_bytes)


# =====================================================================
# ENKRIPSI & DEKRIPSI HIBRIDA
# =====================================================================

_OAEP_PADDING = rsa_padding.OAEP(
    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def hybrid_encrypt(plaintext: bytes, public_key) -> bytes:
    """
    Enkripsi hibrida: session key AES-256 acak dibungkus RSA-OAEP
    memakai kunci publik penerima, lalu data dienkripsi AES-256-GCM
    memakai session key tersebut.

    Args:
        plaintext: data mentah yang akan dienkripsi.
        public_key: kunci publik RSA milik penerima.

    Returns:
        blob bytes: [2 byte panjang][session_key terenkripsi RSA]
                    [nonce][ciphertext+tag]
    """
    session_key = os.urandom(AES_SESSION_KEY_SIZE)

    encrypted_session_key = public_key.encrypt(session_key, _OAEP_PADDING)

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    panjang = struct.pack(">H", len(encrypted_session_key))  # 2 byte, big-endian
    blob = panjang + encrypted_session_key + nonce + ciphertext
    return blob


def hybrid_decrypt(blob: bytes, private_key) -> bytes:
    """
    Dekripsi hibrida: buka session key memakai kunci PRIVAT RSA
    penerima, lalu dekripsi data memakai session key tersebut.

    Args:
        blob: bytes hasil dari hybrid_encrypt().
        private_key: kunci privat RSA milik penerima.

    Returns:
        plaintext asli.

    Raises:
        ValueError: jika blob tidak valid atau dekripsi gagal (kunci
        privat salah, atau data telah diubah).
    """
    try:
        panjang = struct.unpack(">H", blob[:2])[0]
        offset = 2
        encrypted_session_key = blob[offset:offset + panjang]
        offset += panjang
        nonce = blob[offset:offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ciphertext = blob[offset:]

        session_key = private_key.decrypt(encrypted_session_key, _OAEP_PADDING)

        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise ValueError(
            "Dekripsi hibrida gagal: kunci privat salah atau data telah diubah."
        ) from e
