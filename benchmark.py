"""
benchmark.py
Script pengujian wajib untuk NACRYP sesuai ketentuan tugas (Bagian 3, Topik A):

  1. Kebenaran dekripsi pada minimal 10 masukan berbeda (termasuk gambar & PDF)
  2. Waktu enkripsi/dekripsi untuk berkas 1 KB, 1 MB, 10 MB
  3. Avalanche effect
  4. Entropi & histogram byte ciphertext vs plaintext
  5. Perbandingan AES-256-GCM vs ChaCha20-Poly1305

Tahap 3 (Anggota 3): menambahkan uji avalanche effect, entropi,
histogram, dan ekspor ke Excel, melengkapi uji korektnes (Anggota 1)
dan uji waktu/perbandingan (Anggota 2). Versi ini SUDAH LENGKAP (final).

Jalankan: python benchmark.py
Hasil dicetak ke terminal DAN diekspor ke hasil_pengujian.xlsx
Grafik histogram disimpan sebagai histogram_perbandingan.png
"""

import math
import os
import time
from collections import Counter

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # supaya bisa jalan tanpa GUI/display
import matplotlib.pyplot as plt

from crypto_core import (
    encrypt,
    decrypt,
    bit_diff_percentage,
    ALGO_AES_GCM,
    ALGO_CHACHA20_POLY1305,
)

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
# BAGIAN 2 (Anggota 2): UJI WAKTU + PERBANDINGAN ALGORITMA
# =====================================================================

def test_waktu(sizes_kb=(1, 1024, 10240), algo=ALGO_AES_GCM):
    """
    Mengukur waktu enkripsi & dekripsi untuk berkas berukuran
    1 KB, 1 MB (1024 KB), dan 10 MB (10240 KB).
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


def _algo_name(algo):
    return "AES-256-GCM" if algo == ALGO_AES_GCM else "ChaCha20-Poly1305"


def compare_algorithms(sizes_kb=(1, 1024, 10240)):
    """
    Membandingkan waktu AES-256-GCM vs ChaCha20-Poly1305 pada
    ukuran berkas yang sama (memenuhi ketentuan wajib perbandingan
    minimal 2 algoritma/mode).
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
# BAGIAN 3 (Anggota 3): AVALANCHE, ENTROPI, HISTOGRAM, EXPORT EXCEL
# =====================================================================

def test_avalanche(n_percobaan=10, algo=ALGO_AES_GCM):
    """
    Mengukur avalanche effect: seberapa besar persentase bit ciphertext
    berubah ketika 1 bit plaintext diubah (cipher yang baik: ~50%).
    """
    print(f"\n=== 3. Uji Avalanche Effect ({_algo_name(algo)}) ===")
    hasil = []

    for i in range(n_percobaan):
        data_a = os.urandom(64)
        data_b = bytearray(data_a)
        data_b[0] ^= 0b00000001  # ubah 1 bit pertama
        data_b = bytes(data_b)

        blob_a = encrypt(data_a, PASSWORD, algo)
        blob_b = encrypt(data_b, PASSWORD, algo)

        min_len = min(len(blob_a), len(blob_b))
        persen = bit_diff_percentage(blob_a[:min_len], blob_b[:min_len])
        hasil.append(persen)

    rata_rata = sum(hasil) / len(hasil)
    print(f"  Rata-rata dari {n_percobaan} percobaan: {rata_rata:.2f}% bit berubah")
    print("  (Idealnya mendekati 50% untuk cipher yang baik)")
    return {"rata_rata_persen": rata_rata, "detail": hasil}


def hitung_entropi(data: bytes) -> float:
    """
    Menghitung entropi Shannon (bit per byte, maksimum 8.0) dari data.
    Entropi tinggi (mendekati 8) menandakan data terlihat acak.
    """
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    entropi = 0.0
    for count in freq.values():
        p = count / total
        entropi -= p * math.log2(p)
    return entropi


def test_entropi_dan_histogram(algo=ALGO_AES_GCM, simpan_grafik=True):
    """
    Membandingkan entropi plaintext vs ciphertext, dan membuat
    histogram distribusi byte untuk keduanya.
    """
    print(f"\n=== 4. Uji Entropi & Histogram ({_algo_name(algo)}) ===")

    plaintext = ("Ini adalah teks contoh yang berulang-ulang. " * 50).encode()
    blob = encrypt(plaintext, PASSWORD, algo)
    # Ambil bagian ciphertext saja (skip algo_id+salt+nonce di awal blob)
    # supaya histogram murni ciphertext, bukan tercampur salt/nonce.
    from crypto_core import SALT_SIZE, NONCE_SIZE
    ciphertext_only = blob[1 + SALT_SIZE + NONCE_SIZE:]

    entropi_plain = hitung_entropi(plaintext)
    entropi_cipher = hitung_entropi(ciphertext_only)

    print(f"  Entropi plaintext : {entropi_plain:.4f} bit/byte")
    print(f"  Entropi ciphertext: {entropi_cipher:.4f} bit/byte (maks 8.0)")

    if simpan_grafik:
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        axes[0].hist(list(plaintext), bins=256, range=(0, 255), color="steelblue")
        axes[0].set_title(f"Histogram Plaintext (entropi={entropi_plain:.2f})")
        axes[0].set_xlabel("Nilai byte")
        axes[0].set_ylabel("Frekuensi")

        axes[1].hist(list(ciphertext_only), bins=256, range=(0, 255), color="indianred")
        axes[1].set_title(f"Histogram Ciphertext (entropi={entropi_cipher:.2f})")
        axes[1].set_xlabel("Nilai byte")
        axes[1].set_ylabel("Frekuensi")

        plt.tight_layout()
        plt.savefig("histogram_perbandingan.png", dpi=120)
        plt.close()
        print("  Grafik disimpan: histogram_perbandingan.png")

    return {
        "entropi_plaintext": entropi_plain,
        "entropi_ciphertext": entropi_cipher,
    }


def export_ke_excel(
    hasil_korektnes, hasil_waktu, hasil_avalanche, hasil_entropi,
    filename="hasil_pengujian.xlsx",
):
    """
    Mengekspor seluruh hasil pengujian ke satu file Excel (multi-sheet)
    sesuai ketentuan tugas (Bagian 5: Luaran -> Data pengujian, format XLSX).
    """
    with pd.ExcelWriter(filename, engine="openpyxl") as writer:
        pd.DataFrame(hasil_korektnes).to_excel(
            writer, sheet_name="Korektnes", index=False
        )
        pd.DataFrame(hasil_waktu).to_excel(
            writer, sheet_name="Waktu & Perbandingan", index=False
        )
        pd.DataFrame(hasil_avalanche["detail"], columns=["persen_bit_berubah"]).to_excel(
            writer, sheet_name="Avalanche Effect", index=False
        )
        pd.DataFrame([hasil_entropi]).to_excel(
            writer, sheet_name="Entropi", index=False
        )

    print(f"\nSeluruh hasil pengujian diekspor ke: {filename}")


# =====================================================================
# MAIN — menjalankan seluruh rangkaian pengujian wajib
# =====================================================================

def main():
    print("=" * 60)
    print("NACRYP — Rangkaian Pengujian Wajib (Topik A)")
    print("=" * 60)

    hasil_korektnes = test_korektnes(ALGO_AES_GCM)
    hasil_waktu = compare_algorithms()
    hasil_avalanche = test_avalanche()
    hasil_entropi = test_entropi_dan_histogram()

    export_ke_excel(hasil_korektnes, hasil_waktu, hasil_avalanche, hasil_entropi)

    print("\n" + "=" * 60)
    print("SEMUA PENGUJIAN WAJIB SELESAI DIJALANKAN")
    print("=" * 60)


if __name__ == "__main__":
    main()
