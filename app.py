"""
app.py
Antarmuka Streamlit untuk NACRYP — Brankas File Pribadi Terenkripsi.
"""

import base64

import streamlit as st

from crypto_core import (
    encrypt,
    decrypt,
    DecryptionError,
    ALGO_AES_GCM,
    ALGO_CHACHA20_POLY1305,
)

st.set_page_config(page_title="NACRYP", page_icon="🔒")
st.title("🔒 NACRYP")
st.caption("Brankas File Pribadi Terenkripsi — AES-256-GCM / ChaCha20-Poly1305")

tab_enc, tab_dec = st.tabs(["🔐 Encrypt", "🔓 Decrypt"])

# ============================== TAB ENCRYPT ==============================
with tab_enc:
    st.subheader("Enkripsi Berkas")

    uploaded = st.file_uploader("Pilih berkas untuk dienkripsi", key="enc_file")
    password = st.text_input("Password", type="password", key="enc_pw")
    algo_choice = st.radio(
        "Algoritma", ["AES-256-GCM", "ChaCha20-Poly1305"], horizontal=True
    )

    if st.button("Enkripsi", type="primary"):
        if not uploaded or not password:
            st.error("Unggah berkas dan masukkan password terlebih dahulu.")
        else:
            try:
                plaintext = uploaded.getvalue()
                algo = (
                    ALGO_AES_GCM
                    if algo_choice == "AES-256-GCM"
                    else ALGO_CHACHA20_POLY1305
                )
                blob = encrypt(plaintext, password, algo)

                st.success(
                    f"Berhasil dienkripsi ({algo_choice}). "
                    f"Ukuran asli: {len(plaintext)} byte -> "
                    f"ukuran terenkripsi: {len(blob)} byte."
                )

                # --- Wajib: tampilkan ciphertext dalam Base64 ---
                b64 = base64.b64encode(blob).decode()
                MAX_PREVIEW_CHARS = 5000  # ~3.6 KB data asli
                if len(b64) > MAX_PREVIEW_CHARS:
                    preview = (
                        b64[:MAX_PREVIEW_CHARS]
                        + f"\n\n... (dipotong, total {len(b64):,} karakter. "
                        + "Unduh file di bawah untuk mendapatkan Base64 lengkap)"
                    )
                    st.text_area("Ciphertext (Base64) — pratinjau", preview, height=150)
                else:
                    st.text_area("Ciphertext (Base64)", b64, height=150)

                st.download_button(
                    "Unduh berkas terenkripsi (.enc)",
                    data=blob,
                    file_name=uploaded.name + ".enc",
                    mime="application/octet-stream",
                )
            except Exception as e:
                st.error(f"Enkripsi gagal: {e}")

# ============================== TAB DECRYPT ==============================
with tab_dec:
    st.subheader("Dekripsi Berkas")

    uploaded_enc = st.file_uploader("Pilih berkas .enc", key="dec_file")
    password_dec = st.text_input("Password", type="password", key="dec_pw")

    if st.button("Dekripsi", type="primary"):
        if not uploaded_enc or not password_dec:
            st.error("Unggah berkas .enc dan masukkan password terlebih dahulu.")
        else:
            try:
                blob = uploaded_enc.getvalue()
                plaintext = decrypt(blob, password_dec)

                st.success("Dekripsi berhasil! Berkas asli telah dipulihkan.")

                original_name = uploaded_enc.name
                if original_name.endswith(".enc"):
                    original_name = original_name[:-4]

                st.download_button(
                    "Unduh berkas asli",
                    data=plaintext,
                    file_name=original_name,
                )
            except DecryptionError:
                # Pesan sengaja generik: tidak membedakan "password salah"
                # vs "berkas telah diubah" (menghindari oracle attack),
                # sekaligus memenuhi ketentuan wajib fitur Topik A.
                st.error("Password salah atau berkas telah diubah.")
            except Exception as e:
                st.error(f"Terjadi kesalahan saat dekripsi: {e}")

st.divider()
st.caption(
    "NACRYP — Tugas Proyek Aplikasi Kriptografi, Keamanan Informasi, "
    "Universitas Siliwangi."
)
