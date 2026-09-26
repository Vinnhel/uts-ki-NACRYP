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
from hybrid_encrypt import (
    generate_keypair,
    hybrid_encrypt,
    hybrid_decrypt,
    private_key_to_pem_bytes,
    public_key_to_pem_bytes,
    private_key_from_pem_bytes,
    public_key_from_pem_bytes,
)

st.set_page_config(page_title="NACRYP", page_icon="🔒")
st.title("🔒 NACRYP")
st.caption("Brankas File Pribadi Terenkripsi — AES-256-GCM / ChaCha20-Poly1305")

tab_enc, tab_dec, tab_hybrid = st.tabs(
    ["🔐 Encrypt", "🔓 Decrypt", "🤝 Hybrid (RSA-OAEP)"]
)

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

# ============================== TAB HYBRID ================================
# Fitur pengayaan (Anggota 2: hybrid_encrypt.py, Anggota 3: UI ini)
with tab_hybrid:
    st.subheader("🤝 Enkripsi Hibrida (RSA-OAEP + AES-256-GCM)")
    st.caption(
        "Fitur pengayaan: tidak perlu berbagi password. Pengirim cukup "
        "punya kunci PUBLIK penerima; hanya kunci PRIVAT penerima yang "
        "bisa membuka data."
    )

    sub_keygen, sub_enc, sub_dec = st.tabs(
        ["1️⃣ Buat Kunci", "2️⃣ Enkripsi", "3️⃣ Dekripsi"]
    )

    # --- Sub-tab: Buat Pasangan Kunci ---
    with sub_keygen:
        st.markdown(
            "Buat pasangan kunci RSA 2048-bit. **Kunci publik** boleh "
            "dibagikan ke siapa saja (misal ke pengirim). **Kunci privat** "
            "wajib dirahasiakan dan dilindungi passphrase."
        )
        passphrase_gen = st.text_input(
            "Passphrase untuk melindungi kunci privat",
            type="password",
            key="keygen_passphrase",
        )
        if st.button("Buat Pasangan Kunci Baru"):
            if not passphrase_gen:
                st.error("Masukkan passphrase untuk melindungi kunci privat.")
            else:
                priv, pub = generate_keypair()
                # Simpan ke session_state supaya TIDAK hilang saat rerun
                # (misal saat tombol download di-klik). Tanpa ini, klik
                # download akan memicu rerun dan menghapus kunci yang
                # baru dibuat dari memori.
                st.session_state["hy_priv_pem"] = private_key_to_pem_bytes(
                    priv, passphrase_gen
                )
                st.session_state["hy_pub_pem"] = public_key_to_pem_bytes(pub)

        # Tampilkan tombol download HANYA jika kunci sudah ada di
        # session_state — ini yang membuatnya tetap muncul walau
        # sudah terjadi rerun (misal setelah salah satu file didownload).
        if "hy_priv_pem" in st.session_state and "hy_pub_pem" in st.session_state:
            st.success("Pasangan kunci berhasil dibuat.")
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    "⬇️ Unduh Kunci Publik (bagikan)",
                    data=st.session_state["hy_pub_pem"],
                    file_name="public_key.pem",
                    key="dl_pub",
                )
            with col2:
                st.download_button(
                    "⬇️ Unduh Kunci Privat (rahasiakan!)",
                    data=st.session_state["hy_priv_pem"],
                    file_name="private_key.pem",
                    key="dl_priv",
                )
            st.warning(
                "Simpan kunci privat dan passphrase-nya dengan aman. "
                "Jangan unggah kunci privat ke tempat publik (termasuk GitHub)."
            )
            st.caption(
                "Kunci di atas tetap sama sampai Anda klik 'Buat Pasangan "
                "Kunci Baru' lagi — pastikan Anda mengunduh KEDUA file "
                "(publik & privat) dari pasangan yang sama ini."
            )

    # --- Sub-tab: Enkripsi dengan Kunci Publik Penerima ---
    with sub_enc:
        st.markdown("Enkripsi berkas memakai **kunci publik** penerima.")
        uploaded_hy = st.file_uploader("Pilih berkas untuk dienkripsi", key="hy_file")
        pubkey_file = st.file_uploader(
            "Unggah kunci publik penerima (.pem)", key="hy_pubkey"
        )

        if st.button("Enkripsi (Hybrid)", type="primary"):
            if not uploaded_hy or not pubkey_file:
                st.error("Unggah berkas dan kunci publik penerima terlebih dahulu.")
            else:
                try:
                    public_key = public_key_from_pem_bytes(pubkey_file.getvalue())
                    plaintext = uploaded_hy.getvalue()
                    blob = hybrid_encrypt(plaintext, public_key)

                    st.success(
                        f"Berhasil dienkripsi. Ukuran asli: {len(plaintext)} byte -> "
                        f"terenkripsi: {len(blob)} byte."
                    )
                    st.download_button(
                        "Unduh berkas terenkripsi (.hyenc)",
                        data=blob,
                        file_name=uploaded_hy.name + ".hyenc",
                        mime="application/octet-stream",
                    )
                except Exception as e:
                    st.error(f"Enkripsi gagal: {e}")

    # --- Sub-tab: Dekripsi dengan Kunci Privat Sendiri ---
    with sub_dec:
        st.markdown("Dekripsi berkas memakai **kunci privat** milik Anda sendiri.")
        uploaded_hyenc = st.file_uploader("Pilih berkas .hyenc", key="hy_dec_file")
        privkey_file = st.file_uploader(
            "Unggah kunci privat Anda (.pem)", key="hy_privkey"
        )
        passphrase_dec = st.text_input(
            "Passphrase kunci privat", type="password", key="hy_dec_passphrase"
        )

        if st.button("Dekripsi (Hybrid)", type="primary"):
            if not uploaded_hyenc or not privkey_file or not passphrase_dec:
                st.error("Lengkapi berkas .hyenc, kunci privat, dan passphrase.")
            else:
                try:
                    private_key = private_key_from_pem_bytes(
                        privkey_file.getvalue(), passphrase_dec
                    )
                    blob = uploaded_hyenc.getvalue()
                    plaintext = hybrid_decrypt(blob, private_key)

                    st.success("Dekripsi berhasil! Berkas asli telah dipulihkan.")

                    original_name = uploaded_hyenc.name
                    if original_name.endswith(".hyenc"):
                        original_name = original_name[:-6]

                    st.download_button(
                        "Unduh berkas asli", data=plaintext, file_name=original_name
                    )
                except ValueError as e:
                    st.error(str(e))
                except Exception as e:
                    st.error(f"Terjadi kesalahan: kunci privat/passphrase salah, atau berkas rusak.")

st.divider()
st.caption(
    "NACRYP — Tugas Proyek Aplikasi Kriptografi, Keamanan Informasi, "
    "Universitas Siliwangi."
)
