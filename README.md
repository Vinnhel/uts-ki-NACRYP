# NACRYP — Brankas File Pribadi Terenkripsi

Aplikasi web sederhana untuk mengenkripsi dan mendekripsi berkas pribadi
menggunakan algoritma kriptografi modern (AES-256-GCM / ChaCha20-Poly1305).
Dibuat untuk Tugas Proyek Aplikasi Kriptografi - Mata Kuliah Keamanan
Informasi, Program Studi Informatika, Universitas Siliwangi.

## Deskripsi
Aplikasi memungkinkan pengguna mengenkripsi berkas apa pun (dokumen, gambar,
PDF, dll.) menggunakan kata sandi. Kunci enkripsi diturunkan dari kata sandi
melalui fungsi key-derivation yang aman (Scrypt/Argon2/PBKDF2) dengan salt
acak. Setiap proses enkripsi menghasilkan nonce baru sehingga ciphertext
selalu berbeda meski plaintext dan password sama. Proses dekripsi akan
ditolak apabila kata sandi salah atau berkas terenkripsi telah diubah,
karena autentikasi ditegakkan lewat authentication tag pada mode GCM/
Poly1305.

## Fitur
- Enkripsi & dekripsi teks maupun berkas (AES-256-GCM, ChaCha20-Poly1305)
- Key derivation dari password (Argon2id/Scrypt) + salt acak per berkas
- Nonce/IV acak setiap enkripsi, disimpan bersama ciphertext
- Output dapat ditampilkan dalam Base64/hex
- Penolakan dekripsi saat password salah / ciphertext diubah
- (Pengayaan — opsional) Enkripsi hibrida: session key AES dibungkus RSA-OAEP

## Instalasi
```bash
git clone <url-repo-ini>
cd uts-ki-NACRYP
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Menjalankan Aplikasi
```bash
streamlit run app.py
```
Buka browser ke `http://localhost:8501`.

## Menjalankan Unit Test
```bash
pytest tests/ -v
```

## Menjalankan Benchmark / Pengujian
```bash
python benchmark.py
```
Hasil pengujian (waktu enkripsi/dekripsi, avalanche effect, entropi,
histogram, perbandingan algoritma) akan dicetak ke terminal dan disimpan
ke `hasil_pengujian.xlsx`.

## Contoh Penggunaan
1. Buka tab **Encrypt**, unggah berkas, masukkan password, klik **Enkripsi**.
2. Unduh berkas hasil (`namafile.enc`).
3. Buka tab **Decrypt**, unggah berkas `.enc`, masukkan password yang sama,
   klik **Dekripsi** untuk mendapatkan berkas asli kembali.
4. Coba masukkan password salah atau ubah 1 byte pada berkas `.enc` —
   aplikasi akan menolak dan menampilkan pesan kegagalan verifikasi.

## Catatan Keamanan
- Password/kunci tidak pernah ditulis di source code.
- Salt dan nonce dibangkitkan dengan `secrets`/`os.urandom` (CSPRNG).
- Mode ECB dan algoritma usang (MD5, SHA-1, DES, RC4) tidak digunakan
  untuk fitur keamanan utama; hanya sebagai pembanding bila relevan.

## Penggunaan Asisten AI

