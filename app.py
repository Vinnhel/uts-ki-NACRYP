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

st.set_page_config(page_title="NACRYP", page_icon="🔒", layout="centered")

# =====================================================================
# TEMA VISUAL — "Vault / Cipher Terminal"
# Dirancang dari subjek aplikasi: brankas kriptografi. Aksen kuningan
# (brass) merepresentasikan gagang/kunci brankas; monospace dipakai
# genuinely untuk data hex/base64, bukan sekadar dekorasi.
# =====================================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --nc-bg: #0F1115;
    --nc-panel: #171A21;
    --nc-panel-border: #2A2E38;
    --nc-brass: #C9A227;
    --nc-brass-dim: #8A7220;
    --nc-steel: #4C7EA8;
    --nc-text: #E7E4DD;
    --nc-text-dim: #9AA0AC;
    --nc-danger: #C1503D;
    --nc-success: #5B8C5A;
}

html, body, .stApp, .main, [data-testid="stAppViewContainer"] {
    background: var(--nc-bg) !important;
    color: var(--nc-text) !important;
}

[data-testid="stHeader"] {
    background: var(--nc-bg) !important;
}

[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li,
.stMarkdown, .stCaption, label {
    color: var(--nc-text) !important;
}

h1, h2, h3, h4 {
    font-family: 'Space Grotesk', sans-serif !important;
    color: var(--nc-text) !important;
    letter-spacing: -0.01em;
}

p, span, label, div {
    font-family: 'Inter', -apple-system, sans-serif;
}

/* --- Hero header --- */
.nc-hero {
    display: flex;
    align-items: center;
    gap: 14px;
    padding-bottom: 14px;
    margin-bottom: 18px;
    border-bottom: 1px solid var(--nc-panel-border);
}
.nc-hero-title {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 1.9rem;
    color: var(--nc-text);
    margin: 0;
    line-height: 1;
}
.nc-hero-tagline {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: var(--nc-text-dim);
    margin-top: 4px;
}

/* --- Tabs: segmented control, brass underline on active --- */
button[data-baseweb="tab"] {
    font-family: 'Space Grotesk', sans-serif !important;
    color: var(--nc-text-dim) !important;
    font-weight: 600;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: var(--nc-brass) !important;
}
div[data-baseweb="tab-highlight"] {
    background-color: var(--nc-brass) !important;
    height: 2px !important;
}
div[data-baseweb="tab-border"] {
    background-color: var(--nc-panel-border) !important;
}

/* --- Buttons --- */
.stButton > button, .stDownloadButton > button {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 600;
    border-radius: 3px;
    border: 1px solid var(--nc-brass);
}
.stButton > button[kind="primary"] {
    background: var(--nc-brass);
    color: #14161B;
}
.stButton > button[kind="primary"]:hover {
    background: var(--nc-brass-dim);
    border-color: var(--nc-brass-dim);
}
.stDownloadButton > button {
    background: transparent;
    color: var(--nc-brass);
}
.stDownloadButton > button:hover {
    background: rgba(201, 162, 39, 0.1);
}

/* --- Inputs & uploader --- */
.stTextInput input, .stTextArea textarea {
    background: var(--nc-panel) !important;
    border: 1px solid var(--nc-panel-border) !important;
    color: var(--nc-text) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
}
[data-testid="stFileUploaderDropzone"] {
    background: var(--nc-panel) !important;
    border: 1px dashed var(--nc-panel-border) !important;
}

/* --- Alerts: recolor to match palette (no default red/green) --- */
[data-testid="stAlertContentSuccess"] { color: var(--nc-success) !important; }
[data-testid="stAlertContentError"] { color: var(--nc-danger) !important; }
div[data-testid="stNotification"] {
    background: var(--nc-panel) !important;
    border: 1px solid var(--nc-panel-border) !important;
    border-left: 3px solid var(--nc-brass) !important;
}

/* --- Sidebar --- */
section[data-testid="stSidebar"] {
    background: var(--nc-panel);
    border-right: 1px solid var(--nc-panel-border);
}

hr { border-color: var(--nc-panel-border) !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="nc-hero">
    <svg width="34" height="34" viewBox="0 0 34 34" fill="none">
        <circle cx="17" cy="17" r="15" stroke="#C9A227" stroke-width="1.5"/>
        <circle cx="17" cy="17" r="4" fill="#C9A227"/>
        <line x1="17" y1="2" x2="17" y2="7" stroke="#C9A227" stroke-width="1.5"/>
        <line x1="17" y1="27" x2="17" y2="32" stroke="#C9A227" stroke-width="1.5"/>
        <line x1="2" y1="17" x2="7" y2="17" stroke="#C9A227" stroke-width="1.5"/>
        <line x1="27" y1="17" x2="32" y2="17" stroke="#C9A227" stroke-width="1.5"/>
    </svg>
    <div>
        <p class="nc-hero-title">NACRYP</p>
        <p class="nc-hero-tagline">enkripsi berkas dengan AES-256-GCM atau ChaCha20-Poly1305</p>
    </div>
</div>
""", unsafe_allow_html=True)

tab_enc, tab_dec, tab_hybrid = st.tabs(
    ["Encrypt", "Decrypt", "Hybrid (RSA-OAEP)"]
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
    st.subheader("Enkripsi Hibrida (RSA-OAEP + AES-256-GCM)")
    st.caption(
        "Tidak perlu berbagi password. Pengirim cukup "
        "punya kunci PUBLIK penerima; hanya kunci PRIVAT penerima yang "
        "bisa membuka data."
    )

    sub_keygen, sub_enc, sub_dec = st.tabs(
        ["Buat Kunci", "Enkripsi", "Dekripsi"]
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
                    "Unduh Kunci Publik (bagikan)",
                    data=st.session_state["hy_pub_pem"],
                    file_name="public_key.pem",
                    key="dl_pub",
                )
            with col2:
                st.download_button(
                    "Unduh Kunci Privat (rahasiakan)",
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

st.markdown(
    """
    <hr style="margin-top: 2rem;">
    <p style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
              color: #9AA0AC;">
        NACRYP — Tugas Proyek Aplikasi Kriptografi, Keamanan Informasi,
        Universitas Siliwangi.
    </p>
    """,
    unsafe_allow_html=True,
)
