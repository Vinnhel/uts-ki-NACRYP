# Rancangan Sistem — NACRYP (Brankas File Pribadi Terenkripsi)

## Alur Proses Enkripsi

```mermaid
flowchart LR
    A[User upload berkas + password] --> B[Bangkitkan salt acak]
    B --> C["Key Derivation (Argon2id/Scrypt)"]
    C --> D[Bangkitkan nonce acak]
    D --> E["Enkripsi AES-256-GCM / ChaCha20-Poly1305"]
    E --> F["Blob = algo_id + salt + nonce + ciphertext+tag"]
    F --> G[User unduh berkas .enc]
```

## Alur Proses Dekripsi

```mermaid
flowchart LR
    A[User upload berkas .enc + password] --> B["Parse blob (algo_id, salt, nonce, ciphertext)"]
    B --> C["Key Derivation (password + salt)"]
    C --> D["Dekripsi & verifikasi auth tag"]
    D -->|Tag valid| E[Tampilkan/unduh berkas asli]
    D -->|Tag invalid| F["Tolak: 'Password salah atau berkas telah diubah'"]
```

## Arsitektur Aplikasi

```mermaid
flowchart TB
    subgraph UI["app.py (Streamlit)"]
        U1[Tab Encrypt]
        U2[Tab Decrypt]
    end
    subgraph CORE["crypto_core.py"]
        C1[derive_key]
        C2[encrypt]
        C3[decrypt]
        C4[bit_diff_percentage]
    end
    subgraph TEST["benchmark.py"]
        T1[Uji korektnes]
        T2[Uji waktu]
        T3[Avalanche effect]
        T4[Entropi & histogram]
        T5[Perbandingan algoritma]
    end
    U1 --> C2
    U2 --> C3
    C2 --> C1
    C3 --> C1
    T1 --> C2
    T1 --> C3
    T2 --> C2
    T2 --> C3
    T3 --> C2
    T3 --> C4
    T4 --> C2
    T5 --> C2
```

## Rancangan Antarmuka (ringkas)

- **Tab Encrypt**: file uploader, input password, pilihan algoritma
  (radio button AES-256-GCM / ChaCha20-Poly1305), tombol "Enkripsi",
  tombol download hasil.
- **Tab Decrypt**: file uploader (.enc), input password, tombol
  "Dekripsi", pesan sukses/gagal yang jelas, tombol download hasil
  bila sukses.

## Format Blob Terenkripsi

| Bagian | Ukuran | Keterangan |
|---|---|---|
| algo_id | 1 byte | 0x01 = AES-256-GCM, 0x02 = ChaCha20-Poly1305 |
| salt | 16 byte | acak per enkripsi, untuk key derivation |
| nonce | 12 byte | acak per enkripsi |
| ciphertext + tag | variabel | hasil enkripsi, tag menyatu (AEAD) |
