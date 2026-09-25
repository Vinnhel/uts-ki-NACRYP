"""
benchmark.py
Script pengujian wajib untuk NACRYP sesuai ketentuan tugas (Bagian 3, Topik A).

Tahap 1 (Anggota 1): uji korektnes (minimal 10 file berbeda).
Uji waktu, avalanche, entropi/histogram akan ditambahkan Anggota 2 & 3.

Jalankan: python benchmark.py
"""

import os

from crypto_core import encrypt, decrypt, ALGO_AES_GCM

SAMPLE_DIR = "sample_files"   # taruh file uji nyata (gambar, PDF) di sini
PASSWORD = "BenchmarkPassword123!"


# =====================================================================
# BAGIAN 1 (Anggota 1): UJI KOREKTNES — minimal 10 masukan berbeda
# =====================================================================

def _generate_synthetic_test_data():
    """
    Menghasilkan data uji sintetis kalau folder sample_files/ kosong
    atau tidak ada, supaya benchmark tetap bisa dijalankan.
    Idealnya diganti dengan file nyata (gambar & PDF) di sample_files/.
    """
    data = []
    for i in range(1, 6):
        data.append((f"teks_uji_{i}.txt", f"Ini adalah data uji ke-{i} " * (i * 20)))
    for i in range(1, 6):
        data.append((f"biner_uji_{i}.bin", os.urandom(1024 * i)))
    return data


def load_test_files():
    """
    Memuat file uji dari SAMPLE_DIR (kalau ada), atau generate sintetis.
    Return: list of (nama_file, bytes_content)
    """
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
            "Menambahkan data uji sintetis agar total >= 10. "
            "Disarankan taruh file gambar & PDF asli di folder sample_files/."
        )
        for nama, konten in _generate_synthetic_test_data():
            if len(files) >= 10:
                break
            content_bytes = konten if isinstance(konten, bytes) else konten.encode()
            files.append((nama, content_bytes))

    return files


def test_korektnes(algo=ALGO_AES_GCM):
    """
    Uji kebenaran dekripsi: enkripsi lalu dekripsi tiap file uji,
    verifikasi hasilnya identik dengan aslinya.
    """
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
# MAIN — sementara hanya uji korektnes (TODO: tambah uji lain)
# =====================================================================

def main():
    print("=" * 60)
    print("NACRYP — Rangkaian Pengujian Wajib (Topik A)")
    print("=" * 60)

    hasil_korektnes = test_korektnes(ALGO_AES_GCM)

    print("\n[TODO Anggota 2]: uji waktu & perbandingan algoritma")
    print("[TODO Anggota 3]: avalanche, entropi/histogram, export Excel")


if __name__ == "__main__":
    main()
