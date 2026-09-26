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
- Key derivation dari password (Argon2id) + salt acak per berkas
- Nonce/IV acak setiap enkripsi, disimpan bersama ciphertext
- Output ditampilkan dalam Base64
- Penolakan dekripsi saat password salah / ciphertext diubah
- **(Fitur Pengayaan) Enkripsi Hibrida (RSA-OAEP + AES-256-GCM)** - enkripsi
  berbasis pasangan kunci publik/privat, cocok untuk berbagi berkas dengan
  pihak lain tanpa perlu bertukar password lewat kanal rahasia

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
Total 20 test: 13 untuk `crypto_core.py` (AES-GCM, ChaCha20, key
derivation, avalanche) + 7 untuk `hybrid_encrypt.py` (RSA-OAEP).

## Menjalankan Benchmark / Pengujian
```bash
python benchmark.py
```
Hasil pengujian (waktu enkripsi/dekripsi, avalanche effect, entropi,
histogram, perbandingan algoritma) akan dicetak ke terminal dan disimpan
ke `hasil_pengujian.xlsx`.

## Contoh Penggunaan — Mode Password (Encrypt/Decrypt)
1. Buka tab **Encrypt**, unggah berkas, masukkan password, klik **Enkripsi**.
2. Unduh berkas hasil (`namafile.enc`).
3. Buka tab **Decrypt**, unggah berkas `.enc`, masukkan password yang sama,
   klik **Dekripsi** untuk mendapatkan berkas asli kembali.
4. Coba masukkan password salah atau ubah 1 byte pada berkas `.enc` —
   aplikasi akan menolak dan menampilkan pesan kegagalan verifikasi.

## Contoh Penggunaan — Mode Hybrid (RSA-OAEP, untuk berbagi berkas)
Cocok dipakai saat mengirim berkas ke orang lain di device berbeda,
tanpa perlu membagikan password lewat kanal rahasia:

1. **Penerima** membuka tab **Hybrid → Buat Kunci**, mengisi
   passphrase, klik **Buat Pasangan Kunci Baru**, lalu mengunduh
   **kedua** file (`public_key.pem` dan `private_key.pem`) dari hasil
   generate yang sama.
2. Penerima mengirim `public_key.pem` ke pengirim (boleh lewat kanal
   apa saja, tidak rahasia).
3. **Pengirim** membuka tab **Hybrid → Enkripsi**, mengunggah
   berkas yang mau dikirim + `public_key.pem` milik penerima, klik
   **Enkripsi (Hybrid)**, lalu mengirim hasil `.hyenc` ke penerima.
4. **Penerima** membuka tab **Hybrid → Dekripsi**, mengunggah
   berkas `.hyenc` + `private_key.pem` miliknya sendiri + passphrase,
   klik **Dekripsi (Hybrid)** untuk mendapatkan berkas asli.

Note: Kunci publik dan privat harus berasal dari **generate yang sama**
(satu pasang). Jangan mencampur kunci dari sesi generate berbeda.

## Catatan Keamanan
- Password/kunci tidak pernah ditulis di source code.
- Salt dan nonce dibangkitkan dengan `secrets`/`os.urandom` (CSPRNG).
- Mode ECB dan algoritma usang (MD5, SHA-1, DES, RC4) tidak digunakan
  untuk fitur keamanan utama; hanya sebagai pembanding bila relevan.
- Kunci privat RSA (mode Hybrid) disimpan terenkripsi dengan passphrase,
  tidak pernah dalam bentuk plain.

## Catatan Teknis
- Konfigurasi `.streamlit/config.toml` menaikkan batas ukuran pesan
  WebSocket (`maxMessageSize`) supaya berkas besar (mis. gambar 10-20 MB)
  tetap bisa diproses lewat antarmuka Streamlit.
- Folder `sample_files/` berisi berkas uji nyata (gambar, PDF, dll.)
  yang dipakai oleh `benchmark.py` untuk uji korektnes.
