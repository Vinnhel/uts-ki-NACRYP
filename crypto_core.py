"""
crypto_core.py
Modul inti kriptografi untuk NACRYP — Brankas File Pribadi Terenkripsi.

Format blob terenkripsi (disimpan sebagai satu berkas .enc):

    [1 byte algo_id] [16 byte salt] [12 byte nonce] [ciphertext+tag ...]

algo_id:
    0x01 = AES-256-GCM        (Anggota 1)
    0x02 = ChaCha20-Poly1305  (Anggota 2)

Semua nilai acak (salt, nonce) WAJIB dibangkitkan dengan `secrets` /
`os.urandom`. Key tidak pernah disimpan di disk maupun di source code.
"""

import secrets

from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# --- Konstanta ---
SALT_SIZE = 16           # byte, untuk key derivation
NONCE_SIZE = 12          # byte, standar untuk GCM & ChaCha20-Poly1305
KEY_SIZE = 32            # byte, AES-256 / ChaCha20 key = 256 bit

ALGO_AES_GCM = 0x01
ALGO_CHACHA20_POLY1305 = 0x02

# Parameter Argon2id — cukup kuat untuk tugas ini, tidak terlalu lambat
# untuk didemokan (waktu derive key sekitar puluhan-ratusan ms).
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 64 * 1024   # 64 MB
_ARGON2_PARALLELISM = 2


class DecryptionError(Exception):
    """Dilempar saat dekripsi gagal: password salah atau data telah diubah.

    Pesan sengaja generik (tidak membedakan "password salah" vs
    "ciphertext diubah") untuk menghindari oracle attack.
    """
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Menurunkan kunci 256-bit dari password menggunakan Argon2id.

    Args:
        password: password/kata sandi dari pengguna (plaintext, str).
        salt: salt acak sepanjang SALT_SIZE byte (unik per enkripsi).

    Returns:
        bytes sepanjang KEY_SIZE (32 byte) sebagai kunci simetris.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt harus {SALT_SIZE} byte, diterima {len(salt)} byte")

    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,  # Argon2id — kombinasi tahan side-channel & GPU-crack
    )
    return key


def encrypt(plaintext: bytes, password: str, algo: int = ALGO_AES_GCM) -> bytes:
    """
    Mengenkripsi plaintext dengan password menggunakan algoritma pilihan.

    Args:
        plaintext: data mentah (bytes) yang akan dienkripsi.
        password: password dari pengguna.
        algo: ALGO_AES_GCM atau ALGO_CHACHA20_POLY1305.

    Returns:
        blob bytes: [1 byte algo_id][salt][nonce][ciphertext+tag]
    """
    if algo not in (ALGO_AES_GCM, ALGO_CHACHA20_POLY1305):
        raise ValueError(f"Algoritma tidak dikenal: {algo}")

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = secrets.token_bytes(NONCE_SIZE)

    if algo == ALGO_AES_GCM:
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)

    # associated_data=None -> tidak ada data tambahan yang diautentikasi.
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    blob = bytes([algo]) + salt + nonce + ciphertext
    return blob


def decrypt(blob: bytes, password: str) -> bytes:
    """
    Mendekripsi blob hasil encrypt() kembali menjadi plaintext.

    Args:
        blob: bytes hasil dari encrypt().
        password: password yang diklaim benar oleh pengguna.

    Returns:
        plaintext asli (bytes) jika password benar dan blob tidak diubah.

    Raises:
        DecryptionError: jika password salah ATAU blob/ciphertext telah
        diubah. Pesan sengaja tidak dibedakan (lihat docstring kelas).
    """
    min_len = 1 + SALT_SIZE + NONCE_SIZE
    if len(blob) < min_len:
        raise DecryptionError("Berkas tidak valid atau rusak.")

    algo = blob[0]
    salt = blob[1:1 + SALT_SIZE]
    nonce = blob[1 + SALT_SIZE:1 + SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[1 + SALT_SIZE + NONCE_SIZE:]

    if algo not in (ALGO_AES_GCM, ALGO_CHACHA20_POLY1305):
        raise DecryptionError("Berkas tidak valid atau rusak.")

    key = derive_key(password, salt)

    if algo == ALGO_AES_GCM:
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        # Password salah ATAU ciphertext diubah -> pesan generik.
        raise DecryptionError("Password salah atau berkas telah diubah.")

    return plaintext


def bit_diff_percentage(data_a: bytes, data_b: bytes) -> float:
    """
    Menghitung persentase bit yang berbeda antara dua rangkaian byte
    dengan panjang sama. Dipakai untuk mengukur avalanche effect.

    Args:
        data_a, data_b: dua bytes dengan panjang identik.

    Returns:
        float persentase (0-100) bit yang berbeda.
    """
    if len(data_a) != len(data_b):
        raise ValueError("data_a dan data_b harus memiliki panjang yang sama")

    total_bits = len(data_a) * 8
    if total_bits == 0:
        return 0.0

    diff_bits = 0
    for byte_a, byte_b in zip(data_a, data_b):
        xor_result = byte_a ^ byte_b
        diff_bits += bin(xor_result).count("1")

    return (diff_bits / total_bits) * 100
