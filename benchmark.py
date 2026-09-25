"""
benchmark.py
Script pengujian wajib untuk NACRYP sesuai ketentuan tugas (Bagian 3, Topik A).

Tahap 2 (Anggota 2): menambahkan uji waktu enkripsi/dekripsi dan
perbandingan AES-256-GCM vs ChaCha20-Poly1305, melanjutkan uji
korektnes dari Anggota 1.

Jalankan: python benchmark.py
"""

import os
import time

from crypto_core import (
    encrypt,
    decrypt,
    ALGO_AES_GCM,
    ALGO_CHACHA20_POLY1305,
)

SAMPLE_DIR = "sample_files"
PASSWORD = "BenchmarkPassword123!"


# =====================================================================
# BAGIAN 1 (Anggota 1): UJI KOREKTNES
# =====================================================================

def _generate_synthetic_test_data():
    data = []
    for i in range(1, 6):
        data.append((f"teks_uji_{i}.txt", f"Ini adalah data uji ke-{i} " * (i * 20)))
    for i in range(1, 6):
        data.append((f"biner_uji_{i}.bin", os.urandom(1024 * i)))
    return data


def load_test_files():
    files = []
    if os.path.isdir(SAMPLE_DIR):
        for fname in sorted(os.listdir(SAMPLE_DIR)):
            fpath = os.path.join(SAMPLE_DIR, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as f:
                    files.append((fname, f.read()))

    if len(files) < 10:
        print(
            f"[Info] Hanya {len(files)} file ditemukan di '{SAMPLE_DIR}/'. "
            "Menambahkan data uji sintetis agar total >= 10."
        )
        for nama, konten in _generate_synthetic_test_data():
            if len(files) >= 10:
                break
            content_bytes = konten if isinstance(konten, bytes) else konten.encode()
            files.append((nama, content_bytes))

    return files


def test_korektnes(algo=ALGO_AES_GCM):
    print("\n=== 1. Uji Korektnes (minimal 10 file berbeda) ===")
    files = load_test_files()
    hasil = []

    for nama, konten in files:
        blob = encrypt(konten, PASSWORD, algo)
        hasil_dekripsi = decrypt(blob, PASSWORD)
        sukses = hasil_dekripsi == konten
        hasil.append({
            "nama_file": nama,
            "ukuran_asli_byte": len(konten),
            "ukuran_terenkripsi_byte": len(blob),
            "berhasil": sukses,
        })
        status = "OK" if sukses else "GAGAL"
        print(f"  [{status}] {nama} ({len(konten)} byte)")

    total = len(hasil)
    berhasil = sum(1 for h in hasil if h["berhasil"])
    print(f"Hasil: {berhasil}/{total} file berhasil roundtrip dengan benar.")
    return hasil


# =====================================================================
# BAGIAN 2 (Anggota 2): UJI WAKTU + PERBANDINGAN ALGORITMA
# =====================================================================

def _algo_name(algo):
    return "AES-256-GCM" if algo == ALGO_AES_GCM else "ChaCha20-Poly1305"


def test_waktu(sizes_kb=(1, 1024, 10240), algo=ALGO_AES_GCM):
    """
    Mengukur waktu enkripsi & dekripsi untuk berkas berukuran
    1 KB, 1 MB, dan 10 MB.
    """
    print(f"\n=== 2. Uji Waktu Enkripsi/Dekripsi ({_algo_name(algo)}) ===")
    hasil = []

    for size_kb in sizes_kb:
        data = os.urandom(size_kb * 1024)

        t0 = time.perf_counter()
        blob = encrypt(data, PASSWORD, algo)
        t_enc = time.perf_counter() - t0

        t0 = time.perf_counter()
        _ = decrypt(blob, PASSWORD)
        t_dec = time.perf_counter() - t0

        label = f"{size_kb} KB" if size_kb < 1024 else f"{size_kb // 1024} MB"
        hasil.append({
            "ukuran": label,
            "ukuran_byte": size_kb * 1024,
            "algoritma": _algo_name(algo),
            "waktu_enkripsi_detik": round(t_enc, 6),
            "waktu_dekripsi_detik": round(t_dec, 6),
        })
        print(f"  {label}: enkripsi {t_enc*1000:.3f} ms, dekripsi {t_dec*1000:.3f} ms")

    return hasil


def compare_algorithms(sizes_kb=(1, 1024, 10240)):
    """
    Membandingkan waktu AES-256-GCM vs ChaCha20-Poly1305 (memenuhi
    ketentuan wajib perbandingan minimal 2 algoritma/mode).
    """
    print("\n=== Perbandingan AES-256-GCM vs ChaCha20-Poly1305 ===")
    hasil_aes = test_waktu(sizes_kb, ALGO_AES_GCM)
    hasil_chacha = test_waktu(sizes_kb, ALGO_CHACHA20_POLY1305)

    print("\n  Ringkasan perbandingan (waktu enkripsi, ms):")
    for a, c in zip(hasil_aes, hasil_chacha):
        print(
            f"  {a['ukuran']:>6}: AES-GCM={a['waktu_enkripsi_detik']*1000:.3f}ms  "
            f"ChaCha20={c['waktu_enkripsi_detik']*1000:.3f}ms"
        )

    return hasil_aes + hasil_chacha


# =====================================================================
# MAIN
# =====================================================================

def main():
    print("=" * 60)
    print("NACRYP — Rangkaian Pengujian Wajib (Topik A)")
    print("=" * 60)

    hasil_korektnes = test_korektnes(ALGO_AES_GCM)
    hasil_waktu = compare_algorithms()

    print("\n[TODO Anggota 3]: avalanche, entropi/histogram, export Excel")


if __name__ == "__main__":
    main()
