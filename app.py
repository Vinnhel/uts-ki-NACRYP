"""
app.py
Antarmuka Streamlit untuk NACRYP — Brankas File Pribadi Terenkripsi.

TODO (Hari 4): hubungkan tombol ke crypto_core.encrypt / crypto_core.decrypt
setelah crypto_core.py selesai diimplementasikan.
"""

import base64
import streamlit as st
# from crypto_core import encrypt, decrypt, ALGO_AES_GCM, ALGO_CHACHA20_POLY1305

st.set_page_config(page_title="NACRYP", page_icon="🔒")
st.title("🔒 NACRYP")
st.caption("Brankas File Pribadi Terenkripsi — AES-256-GCM / ChaCha20-Poly1305")

tab_enc, tab_dec = st.tabs(["🔐 Encrypt", "🔓 Decrypt"])

with tab_enc:
    st.subheader("Enkripsi Berkas")
    uploaded = st.file_uploader("Pilih berkas untuk dienkripsi", key="enc_file")
    password = st.text_input("Password", type="password", key="enc_pw")
    algo_choice = st.radio("Algoritma", ["AES-256-GCM", "ChaCha20-Poly1305"], horizontal=True)

    if st.button("Enkripsi", type="primary"):
        if not uploaded or not password:
            st.error("Unggah berkas dan masukkan password terlebih dahulu.")
        else:
            st.info("TODO: panggil crypto_core.encrypt() di sini")
            # plaintext = uploaded.read()
            # algo = ALGO_AES_GCM if algo_choice == "AES-256-GCM" else ALGO_CHACHA20_POLY1305
            # blob = encrypt(plaintext, password, algo)
            #
            # --- Wajib: tampilkan ciphertext dalam Base64 (bukan hanya file) ---
            # b64 = base64.b64encode(blob).decode()
            # st.text_area("Ciphertext (Base64)", b64, height=150)
            # st.caption(f"Ukuran: {len(blob)} byte")
            #
            # st.download_button("Unduh berkas terenkripsi (.enc)", blob,
            #                     file_name=uploaded.name + ".enc")

with tab_dec:
    st.subheader("Dekripsi Berkas")
    uploaded_enc = st.file_uploader("Pilih berkas .enc", key="dec_file")
    password_dec = st.text_input("Password", type="password", key="dec_pw")

    if st.button("Dekripsi", type="primary"):
        if not uploaded_enc or not password_dec:
            st.error("Unggah berkas .enc dan masukkan password terlebih dahulu.")
        else:
            st.info("TODO: panggil crypto_core.decrypt() di sini, tangani "
                     "exception dan tampilkan pesan gagal bila password salah "
                     "atau berkas telah diubah.")
            # try:
            #     blob = uploaded_enc.read()
            #     plaintext = decrypt(blob, password_dec)
            #     st.success("Dekripsi berhasil.")
            #     st.download_button("Unduh berkas asli", plaintext,
            #                         file_name=uploaded_enc.name.replace(".enc", ""))
            # except Exception:
            #     st.error("Password salah atau berkas telah diubah.")
