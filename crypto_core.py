"""
crypto_core.py
Modul inti kriptografi untuk NACRYP — Brankas File Pribadi Terenkripsi.

Format blob terenkripsi (disimpan sebagai satu berkas .enc):

    [1 byte algo_id] [16 byte salt] [12 byte nonce] [ciphertext+tag ...]

algo_id:
    0x01 = AES-256-GCM
    0x02 = ChaCha20-Poly1305

Semua nilai acak (salt, nonce) WAJIB dibangkitkan dengan `secrets` /
`os.urandom`. Key tidak pernah disimpan di disk maupun di source code.

TODO (Hari 2-3): implementasikan tiap fungsi di bawah sesuai docstring.
TODO (Hari 4): tambahkan dukungan ChaCha20-Poly1305 sebagai mode kedua.
"""

import secrets

# --- Konstanta ---
SALT_SIZE = 16          # byte, untuk key derivation
NONCE_SIZE = 12          # byte, standar untuk GCM & ChaCha20-Poly1305
KEY_SIZE = 32            # byte, AES-256 / ChaCha20 key = 256 bit

ALGO_AES_GCM = 0x01
ALGO_CHACHA20_POLY1305 = 0x02


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Menurunkan kunci 256-bit dari password menggunakan Argon2id (disarankan)
    atau Scrypt sebagai alternatif.

    Args:
        password: password/kata sandi dari pengguna (plaintext, str).
        salt: salt acak sepanjang SALT_SIZE byte (unik per enkripsi).

    Returns:
        bytes sepanjang KEY_SIZE (32 byte) sebagai kunci simetris.

    Catatan implementasi:
        - Gunakan argon2.low_level.hash_secret_raw (argon2-cffi) dengan
          parameter time_cost, memory_cost, parallelism yang wajar
          (mis. time_cost=3, memory_cost=64*1024, parallelism=2), ATAU
        - Gunakan cryptography.hazmat.primitives.kdf.scrypt.Scrypt.
        - JANGAN pakai MD5/SHA-1 untuk key derivation.
    """
    raise NotImplementedError("TODO Hari 2: implementasikan derive_key")


def encrypt(plaintext: bytes, password: str, algo: int = ALGO_AES_GCM) -> bytes:
    """
    Mengenkripsi plaintext dengan password menggunakan algoritma pilihan.

    Args:
        plaintext: data mentah (bytes) yang akan dienkripsi.
        password: password dari pengguna.
        algo: ALGO_AES_GCM atau ALGO_CHACHA20_POLY1305.

    Returns:
        blob bytes dengan format:
        [1 byte algo_id][salt][nonce][ciphertext+tag]

    Langkah:
        1. Bangkitkan salt acak (SALT_SIZE byte) -> secrets.token_bytes.
        2. key = derive_key(password, salt).
        3. Bangkitkan nonce acak (NONCE_SIZE byte).
        4. Enkripsi plaintext dengan AESGCM(key) atau ChaCha20Poly1305(key),
           pakai nonce di atas -> hasil sudah termasuk auth tag di akhir.
        5. Gabungkan: bytes([algo]) + salt + nonce + ciphertext.
    """
    raise NotImplementedError("TODO Hari 2: implementasikan encrypt")


def decrypt(blob: bytes, password: str) -> bytes:
    """
    Mendekripsi blob hasil encrypt() kembali menjadi plaintext.

    Args:
        blob: bytes hasil dari encrypt().
        password: password yang diklaim benar oleh pengguna.

    Returns:
        plaintext asli (bytes) jika password benar dan blob tidak diubah.

    Raises:
        InvalidTag (dari `cryptography`) atau ValueError kustom apabila:
            - password salah, ATAU
            - blob/ciphertext telah diubah (auth tag tidak cocok).
        Fungsi pemanggil (app.py) WAJIB menangkap exception ini dan
        menampilkan pesan "Password salah atau berkas telah diubah."
        JANGAN membedakan pesan error antara "password salah" vs
        "ciphertext diubah" ke pengguna akhir (hindari oracle attack).

    Langkah:
        1. Parse blob: algo_id = blob[0], salt = blob[1:17],
           nonce = blob[17:29], ciphertext = blob[29:].
        2. key = derive_key(password, salt).
        3. Decrypt sesuai algo_id; library akan otomatis memverifikasi
           auth tag dan melempar exception jika gagal.
    """
    raise NotImplementedError("TODO Hari 2: implementasikan decrypt")


def bit_diff_percentage(data_a: bytes, data_b: bytes) -> float:
    """
    Menghitung persentase bit yang berbeda antara dua rangkaian byte
    dengan panjang sama. Dipakai untuk mengukur avalanche effect.

    Args:
        data_a, data_b: dua bytes dengan panjang identik.

    Returns:
        float persentase (0-100) bit yang berbeda.

    Dipakai di benchmark.py Hari 5 untuk membandingkan ciphertext saat
    1 bit plaintext/key diubah.
    """
    raise NotImplementedError("TODO Hari 5: implementasikan bit_diff_percentage")
