"""
Hybrid Encryption Web App (RSA + AES) - Streamlit Frontend
"""

import sys
import os
import random

lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
if os.path.exists(lib_path):
    sys.path.insert(0, lib_path)

import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import time

# ── Page Config ──
st.set_page_config(page_title="HybridCrypt", page_icon="", layout="centered")

# ── Dark Theme CSS ──
st.markdown("""
<style>
    .stApp {
        background-color: #0a0e17;
    }
    header[data-testid="stHeader"] {
        background-color: #0a0e17;
    }
    .main-title {
        text-align: center;
        font-size: 2.4rem;
        font-weight: 700;
        color: #ffffff;
        margin-bottom: 0;
    }
    .sub-title {
        text-align: center;
        color: #7a8ba0;
        font-size: 1rem;
        margin-bottom: 30px;
    }
    .step-box {
        background-color: #080c14;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 8px 0;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.85rem;
        color: #22c55e;
    }
    .step-box.error {
        color: #ef4444;
    }
    .badge-real {
        background: #14532d;
        color: #86efac;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-decoy {
        background: #78350f;
        color: #fcd34d;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ── Session State Init ──
if "private_key" not in st.session_state:
    st.session_state.private_key = None
    st.session_state.public_key = None
    st.session_state.current_ciphertext = None


def ensure_keys():
    if st.session_state.private_key is None:
        key = RSA.generate(2048)
        st.session_state.private_key = key
        st.session_state.public_key = key.publickey()


def show_steps(steps):
    for s in steps:
        st.markdown(f'<div class="step-box">{s}</div>', unsafe_allow_html=True)


def show_error(msg):
    st.markdown(f'<div class="step-box error">{msg}</div>', unsafe_allow_html=True)


DECOY_MESSAGES = [
    "Meeting rescheduled to 3pm tomorrow. Please confirm attendance.",
    "The quarterly report is due by end of this week. Let me know if you need an extension.",
    "Reminder: Team lunch at 12:30 on Friday at the usual place.",
    "Can you send me the updated spreadsheet? I need the latest numbers.",
    "Happy birthday! Hope you have a great day ahead.",
    "The package has been shipped. Tracking number: TRK-8847291035.",
    "Please review the attached document and share your feedback by Monday.",
    "Running late today, will be in office by 10:30am.",
    "Groceries: milk, eggs, bread, butter, rice, onions, tomatoes.",
    "WiFi password for the guest network: SunFlower2024.",
    "The dentist appointment is confirmed for Thursday at 2pm.",
    "Notes from today's standup: deployed v2.1, fixed login bug, backlog groomed.",
    "Flight confirmation: DEL to BLR, 14 May, 6:45am, Seat 12A.",
    "Rent paid for April. Transaction ref: NEFT-0041928374.",
    "Pick up laundry after 5pm. They close at 8.",
    "Book recommendation: Atomic Habits by James Clear. Really good read.",
    "The new project timeline has been shared in the drive folder.",
    "Server maintenance window: Saturday 2am-5am IST. Expect brief downtime.",
    "Insurance renewal is due next month. Check the premium options.",
    "The kids' school event is on 20th April. Need to RSVP by Friday.",
]


def generate_decoy_message():
    return random.choice(DECOY_MESSAGES)


def generate_decoy_file_data(original_size):
    decoy_texts = [
        "This file contains quarterly financial projections for internal review only.",
        "Draft agenda for the upcoming board meeting. Subject to changes.",
        "Employee training schedule for Q2. All sessions are mandatory.",
        "Inventory checklist updated as of last audit cycle.",
        "Backup log entries from the staging environment.",
    ]
    base = random.choice(decoy_texts)
    repeated = (base + "\n") * max(1, original_size // len(base))
    return repeated[:original_size].encode("utf-8")


def honeypot_encrypt_data(real_data, decoy_data, real_pwd, decoy_pwd):
    """Encrypt real + decoy data with separate passwords. Returns (package_bytes, steps)."""
    steps = []
    salt = get_random_bytes(16)
    steps.append(f"Salt generated: {salt.hex()}")

    real_key = PBKDF2(real_pwd.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    steps.append("Real password key derived (PBKDF2, 100k rounds)")

    decoy_key = PBKDF2(decoy_pwd.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    steps.append("Decoy password key derived (PBKDF2, 100k rounds)")

    cipher_real = AES.new(real_key, AES.MODE_GCM)
    ct_real, tag_real = cipher_real.encrypt_and_digest(real_data)
    steps.append(f"Real data encrypted ({len(real_data)} bytes)")

    cipher_decoy = AES.new(decoy_key, AES.MODE_GCM)
    ct_decoy, tag_decoy = cipher_decoy.encrypt_and_digest(decoy_data)
    steps.append(f"Auto-generated decoy encrypted ({len(decoy_data)} bytes)")

    # Marker byte 0xHP at start to identify honeypot format
    package = (
        b"\xAA\xBB" +  # honeypot marker
        salt +
        cipher_real.nonce + tag_real + len(ct_real).to_bytes(4, "big") + ct_real +
        cipher_decoy.nonce + tag_decoy + len(ct_decoy).to_bytes(4, "big") + ct_decoy
    )
    steps.append("Both encrypted payloads packed into single blob")
    steps.append(f"Decoy auto-generated (different every time)")
    return package, steps


def honeypot_decrypt_data(package, password):
    """Try to decrypt honeypot package. Returns (data, msg_type, steps) or raises."""
    salt = package[2:18]  # skip 2-byte marker
    steps = ["Honeypot format detected", "Deriving key from password (PBKDF2, 100k rounds)..."]

    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    steps.append(f"Derived key: {key.hex()}")

    pos = 18
    messages = []
    for _ in range(2):
        nonce = package[pos:pos+16]; pos += 16
        tag = package[pos:pos+16]; pos += 16
        ct_len = int.from_bytes(package[pos:pos+4], "big"); pos += 4
        ct = package[pos:pos+ct_len]; pos += ct_len
        messages.append((nonce, tag, ct))

    labels = ["REAL", "DECOY"]
    for i, (nonce, tag, ct) in enumerate(messages):
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ct, tag)
            msg_type = labels[i]
            if msg_type == "DECOY":
                steps.append("Decryption successful!")
                steps.append("The attacker thinks they won -- but this is the DECOY!")
            else:
                steps.append("Decryption successful!")
                steps.append("This is the REAL secret data")
            return plaintext, msg_type, steps
        except (ValueError, KeyError):
            continue

    raise ValueError("Wrong password! Neither message could be decrypted.")


def is_honeypot(data):
    return len(data) >= 2 and data[:2] == b"\xAA\xBB"


# ── Header ──
st.markdown('<div class="main-title">HybridCrypt</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Hybrid Encryption System -- RSA + AES-256-GCM</div>', unsafe_allow_html=True)

# ── Tabs (no more Honeypot tab) ──
tab_encrypt, tab_decrypt, tab_files, tab_attacks, tab_keys = st.tabs(
    ["Encrypt", "Decrypt", "Files", "Attack Sim", "Keys"]
)

# ===== ENCRYPT TAB =====
with tab_encrypt:
    st.subheader("Encrypt a Message")

    # Honeypot toggle at the top
    honeypot_msg_on = st.toggle("Enable Honeypot Mode (Plausible Deniability)", key="hp_msg_toggle")

    if honeypot_msg_on:
        st.caption("Honeypot ON: A random decoy message will be auto-generated. An attacker with the decoy password sees the decoy, not your real message.")
        hp_real_pwd = st.text_input("Real Password (only you know this)", type="password", key="hp_msg_real_pwd")
        hp_decoy_pwd = st.text_input("Decoy Password (give this to attacker)", type="password", key="hp_msg_decoy_pwd")

    enc_message = st.text_area("Plaintext Message", placeholder="Enter the text you want to encrypt...", key="enc_msg")

    if st.button("Encrypt", key="btn_encrypt", type="primary"):
        if not enc_message:
            show_error("Please enter a message")
        elif honeypot_msg_on and (not hp_real_pwd or not hp_decoy_pwd):
            show_error("Both real and decoy passwords are required for Honeypot mode")
        elif honeypot_msg_on and hp_real_pwd == hp_decoy_pwd:
            show_error("Real and decoy passwords must be different")
        else:
            if honeypot_msg_on:
                # Honeypot encryption
                decoy_text = generate_decoy_message()
                real_data = enc_message.encode("utf-8")
                decoy_data = decoy_text.encode("utf-8")

                package, steps = honeypot_encrypt_data(real_data, decoy_data, hp_real_pwd, hp_decoy_pwd)
                encoded = base64.b64encode(package).decode()
                st.session_state.current_ciphertext = encoded

                st.success("Honeypot encryption complete!")
                with st.expander("Step-by-Step Process", expanded=True):
                    show_steps(steps)
                st.caption(f'Auto-generated decoy: "{decoy_text}"')
                st.markdown("**Ciphertext Output (Base64)**")
                st.code(encoded, language=None)

            else:
                # Normal hybrid encryption
                ensure_keys()
                steps = []

                aes_key = get_random_bytes(32)
                steps.append(f"AES-256 key generated: {aes_key.hex()}")

                cipher_aes = AES.new(aes_key, AES.MODE_GCM)
                ciphertext, tag = cipher_aes.encrypt_and_digest(enc_message.encode("utf-8"))
                steps.append(f"Data encrypted with AES-256-GCM")
                steps.append(f"Nonce: {cipher_aes.nonce.hex()}")
                steps.append(f"Auth Tag: {tag.hex()}")
                steps.append(f"Ciphertext size: {len(ciphertext)} bytes")

                cipher_rsa = PKCS1_OAEP.new(st.session_state.public_key)
                encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                steps.append(f"AES key encrypted with RSA public key")
                steps.append(f"Encrypted key size: {len(encrypted_aes_key)} bytes")

                package = (
                    len(encrypted_aes_key).to_bytes(2, "big") +
                    encrypted_aes_key + cipher_aes.nonce + tag + ciphertext
                )
                encoded = base64.b64encode(package).decode()
                st.session_state.current_ciphertext = encoded

                st.success("Encryption complete!")
                with st.expander("Step-by-Step Process", expanded=True):
                    show_steps(steps)

                st.markdown("**Ciphertext Output (Base64)**")
                st.code(encoded, language=None)

# ===== DECRYPT TAB =====
with tab_decrypt:
    st.subheader("Decrypt a Message")
    dec_input = st.text_area("Ciphertext (Base64)", placeholder="Paste the encrypted ciphertext here...", key="dec_msg")

    # Auto-detect honeypot and show password field
    needs_password = False
    if dec_input:
        try:
            raw = base64.b64decode(dec_input)
            if is_honeypot(raw):
                needs_password = True
                st.info("Honeypot-encrypted data detected. Enter password to decrypt.")
        except Exception:
            pass

    if needs_password:
        dec_password = st.text_input("Password", type="password", placeholder="Enter your password", key="dec_hp_pwd")
    else:
        dec_password = None

    if st.button("Decrypt", key="btn_decrypt", type="primary"):
        if not dec_input:
            show_error("Please paste ciphertext")
        else:
            try:
                raw = base64.b64decode(dec_input)

                if is_honeypot(raw):
                    if not dec_password:
                        show_error("Password is required for honeypot-encrypted data")
                    else:
                        plaintext, msg_type, steps = honeypot_decrypt_data(raw, dec_password)
                        with st.expander("Step-by-Step Process", expanded=True):
                            show_steps(steps)
                        if msg_type == "REAL":
                            st.markdown('<span class="badge-real">REAL MESSAGE</span>', unsafe_allow_html=True)
                        else:
                            st.markdown('<span class="badge-decoy">DECOY MESSAGE</span>', unsafe_allow_html=True)
                        st.text_area("Decrypted Message", value=plaintext.decode("utf-8"), height=100, key="dec_out")
                else:
                    # Normal hybrid decryption
                    ensure_keys()
                    steps = []
                    enc_key_len = int.from_bytes(raw[:2], "big")
                    encrypted_aes_key = raw[2:2 + enc_key_len]
                    nonce = raw[2 + enc_key_len:2 + enc_key_len + 16]
                    tag = raw[2 + enc_key_len + 16:2 + enc_key_len + 32]
                    ct = raw[2 + enc_key_len + 32:]

                    cipher_rsa = PKCS1_OAEP.new(st.session_state.private_key)
                    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                    steps.append(f"AES key decrypted with RSA private key")
                    steps.append(f"Recovered AES key: {aes_key.hex()}")

                    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher_aes.decrypt_and_verify(ct, tag)
                    steps.append("Authentication tag verified")
                    steps.append(f"Data decrypted successfully ({len(plaintext)} bytes)")

                    st.success("Decryption complete!")
                    with st.expander("Step-by-Step Process", expanded=True):
                        show_steps(steps)
                    st.text_area("Decrypted Message", value=plaintext.decode("utf-8"), height=100, key="dec_out_normal")

            except ValueError as e:
                show_error(str(e))
            except Exception as e:
                show_error(f"Decryption failed: {str(e)}")

# ===== FILES TAB =====
with tab_files:
    st.subheader("File Encryption / Decryption")
    file_mode = st.radio("Mode", ["Encrypt File", "Decrypt File"], horizontal=True, key="file_mode")

    if file_mode == "Encrypt File":
        # Honeypot toggle for files
        honeypot_file_on = st.toggle("Enable Honeypot Mode (Plausible Deniability)", key="hp_file_toggle")

        if honeypot_file_on:
            st.caption("Honeypot ON: Random decoy file content will be auto-generated. Attacker with decoy password gets fake data.")
            hp_file_real_pwd = st.text_input("Real Password (only you know this)", type="password", key="hp_file_real_pwd")
            hp_file_decoy_pwd = st.text_input("Decoy Password (give this to attacker)", type="password", key="hp_file_decoy_pwd")

        uploaded = st.file_uploader("Choose a file to encrypt", key="file_enc_upload")

        if uploaded and st.button("Encrypt File", key="btn_enc_file", type="primary"):
            data = uploaded.read()

            if honeypot_file_on:
                if not hp_file_real_pwd or not hp_file_decoy_pwd:
                    show_error("Both passwords are required for Honeypot mode")
                elif hp_file_real_pwd == hp_file_decoy_pwd:
                    show_error("Real and decoy passwords must be different")
                else:
                    decoy_data = generate_decoy_file_data(len(data))
                    package, steps = honeypot_encrypt_data(data, decoy_data, hp_file_real_pwd, hp_file_decoy_pwd)

                    st.success("Honeypot file encryption complete!")
                    with st.expander("Step-by-Step Process", expanded=True):
                        show_steps(steps)

                    st.download_button(
                        "Download Encrypted File",
                        data=package,
                        file_name=uploaded.name + ".enc",
                        mime="application/octet-stream"
                    )
            else:
                ensure_keys()
                steps = []

                aes_key = get_random_bytes(32)
                steps.append(f"AES-256 key generated: {aes_key.hex()}")

                cipher_aes = AES.new(aes_key, AES.MODE_GCM)
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                steps.append(f"File encrypted ({len(data)} bytes)")

                cipher_rsa = PKCS1_OAEP.new(st.session_state.public_key)
                encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                steps.append("AES key encrypted with RSA")

                package = (
                    len(encrypted_aes_key).to_bytes(2, "big") +
                    encrypted_aes_key + cipher_aes.nonce + tag + ciphertext
                )

                st.success("File encrypted!")
                with st.expander("Step-by-Step Process", expanded=True):
                    show_steps(steps)

                st.download_button(
                    "Download Encrypted File",
                    data=package,
                    file_name=uploaded.name + ".enc",
                    mime="application/octet-stream"
                )

    else:
        uploaded = st.file_uploader("Choose a .enc file to decrypt", key="file_dec_upload")

        # Check if uploaded file is honeypot
        file_needs_password = False
        if uploaded:
            file_bytes = uploaded.read()
            uploaded.seek(0)
            if is_honeypot(file_bytes):
                file_needs_password = True
                st.info("Honeypot-encrypted file detected. Enter password to decrypt.")

        if file_needs_password:
            file_dec_pwd = st.text_input("Password", type="password", placeholder="Enter your password", key="file_dec_pwd")
        else:
            file_dec_pwd = None

        if uploaded and st.button("Decrypt File", key="btn_dec_file", type="primary"):
            package = uploaded.read()

            try:
                if is_honeypot(package):
                    if not file_dec_pwd:
                        show_error("Password is required for honeypot-encrypted files")
                    else:
                        plaintext, msg_type, steps = honeypot_decrypt_data(package, file_dec_pwd)

                        with st.expander("Step-by-Step Process", expanded=True):
                            show_steps(steps)

                        if msg_type == "REAL":
                            st.markdown('<span class="badge-real">REAL FILE</span>', unsafe_allow_html=True)
                        else:
                            st.markdown('<span class="badge-decoy">DECOY FILE</span>', unsafe_allow_html=True)

                        original = uploaded.name
                        if original.endswith(".enc"):
                            original = original[:-4]

                        st.download_button(
                            "Download Decrypted File",
                            data=plaintext,
                            file_name=original,
                            mime="application/octet-stream"
                        )

                        try:
                            preview = plaintext.decode("utf-8")[:500]
                            st.text_area("Preview", value=preview, height=100, key="hp_file_preview")
                        except Exception:
                            st.info(f"Binary file - {len(plaintext)} bytes")
                else:
                    # Normal decryption
                    ensure_keys()
                    steps = []

                    enc_key_len = int.from_bytes(package[:2], "big")
                    encrypted_aes_key = package[2:2 + enc_key_len]
                    nonce = package[2 + enc_key_len:2 + enc_key_len + 16]
                    tag = package[2 + enc_key_len + 16:2 + enc_key_len + 32]
                    ct = package[2 + enc_key_len + 32:]

                    cipher_rsa = PKCS1_OAEP.new(st.session_state.private_key)
                    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                    steps.append("AES key recovered")

                    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher_aes.decrypt_and_verify(ct, tag)
                    steps.append(f"File decrypted ({len(plaintext)} bytes)")

                    original = uploaded.name
                    if original.endswith(".enc"):
                        original = original[:-4]

                    st.success("File decrypted!")
                    with st.expander("Step-by-Step Process", expanded=True):
                        show_steps(steps)

                    st.download_button(
                        "Download Decrypted File",
                        data=plaintext,
                        file_name=original,
                        mime="application/octet-stream"
                    )

                    try:
                        preview = plaintext.decode("utf-8")[:500]
                        st.text_area("Preview", value=preview, height=100, key="file_preview")
                    except Exception:
                        st.info(f"Binary file - {len(plaintext)} bytes")

            except ValueError as e:
                show_error(str(e))
            except Exception as e:
                show_error(f"Decryption failed: {str(e)}")

# ===== ATTACKS TAB =====
with tab_attacks:
    st.subheader("Attack Simulations")
    st.caption("These simulations demonstrate why hybrid encryption is secure. Provide a ciphertext target, then run an attack.")

    # ── Ciphertext Source Selection ──
    st.markdown("**Select Ciphertext Target**")
    atk_source = st.radio(
        "Source",
        ["Use last encrypted message", "Paste ciphertext (Base64)", "Upload encrypted file (.enc)"],
        horizontal=False,
        key="atk_source"
    )

    attack_ciphertext = None

    if atk_source == "Use last encrypted message":
        if st.session_state.current_ciphertext:
            attack_ciphertext = st.session_state.current_ciphertext
            st.success(f"Target loaded: {len(attack_ciphertext)} chars of Base64 ciphertext")
            with st.expander("View ciphertext being attacked"):
                st.code(attack_ciphertext, language=None)
        else:
            st.warning("No encrypted message found. Go to the Encrypt tab first.")

    elif atk_source == "Paste ciphertext (Base64)":
        pasted = st.text_area("Paste ciphertext here", placeholder="Paste Base64 ciphertext...", key="atk_paste")
        if pasted:
            attack_ciphertext = pasted.strip()
            st.success(f"Target loaded: {len(attack_ciphertext)} chars of Base64 ciphertext")

    else:
        atk_file = st.file_uploader("Upload .enc file", key="atk_file_upload")
        if atk_file:
            file_bytes = atk_file.read()
            attack_ciphertext = base64.b64encode(file_bytes).decode()
            st.success(f"Target loaded from file: {atk_file.name} ({len(file_bytes)} bytes)")

    st.divider()

    # ── Attack Buttons ──
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Brute Force AES-256**")
        st.caption("Try 1,000,000 random keys against the ciphertext")
        btn_brute = st.button("Run Brute Force", key="btn_brute")

        st.markdown("**Wrong RSA Key**")
        st.caption("Attempt decryption with attacker's key pair")
        btn_wrong = st.button("Run Wrong Key Attack", key="btn_wrong")

    with col2:
        st.markdown("**Ciphertext Tampering**")
        st.caption("Flip bits and test GCM integrity detection")
        btn_tamper = st.button("Run Tamper Attack", key="btn_tamper")

        st.markdown("**Key Size Comparison**")
        st.caption("Compare AES-128, AES-192, AES-256 strength")
        btn_keysize = st.button("Run Key Size Demo", key="btn_keysize")

    st.divider()

    # Brute Force
    if btn_brute:
        if not attack_ciphertext:
            show_error("No ciphertext target selected. Choose a source above.")
        else:
            package = base64.b64decode(attack_ciphertext)

            if is_honeypot(package):
                nonce = package[18:34]
                tag = package[34:50]
                ct_len = int.from_bytes(package[50:54], "big")
                ct = package[54:54+ct_len]
            else:
                enc_key_len = int.from_bytes(package[:2], "big")
                nonce = package[2 + enc_key_len:2 + enc_key_len + 16]
                tag = package[2 + enc_key_len + 16:2 + enc_key_len + 32]
                ct = package[2 + enc_key_len + 32:]

            attempts = 1_000_000
            st.info(f"Running brute force with {attempts:,} random keys... This will take a while.")
            progress = st.progress(0)
            status = st.empty()

            start = time.time()
            for i in range(attempts):
                fake_key = get_random_bytes(32)
                try:
                    cipher = AES.new(fake_key, AES.MODE_GCM, nonce=nonce)
                    cipher.decrypt_and_verify(ct, tag)
                except (ValueError, KeyError):
                    pass
                if (i + 1) % 50000 == 0:
                    progress.progress((i + 1) / attempts)
                    status.text(f"Tried {i+1:,} / {attempts:,} keys...")
            elapsed = time.time() - start
            progress.progress(1.0)

            keys_per_sec = attempts / elapsed
            years = (2**256) / keys_per_sec / 60 / 60 / 24 / 365

            steps = [
                f"Attacking ciphertext of {len(ct)} bytes",
                "AES-256 has 2^256 possible keys",
                f"Tried {attempts:,} random keys in {elapsed:.2f}s",
                f"Speed: {keys_per_sec:,.0f} keys/second",
                f"Time to try all keys: ~{years:.2e} years",
                "RESULT: Brute force is IMPOSSIBLE on AES-256",
            ]
            show_steps(steps)

    # Tamper
    if btn_tamper:
        if not attack_ciphertext:
            show_error("No ciphertext target selected. Choose a source above.")
        else:
            ensure_keys()
            package = base64.b64decode(attack_ciphertext)

            if is_honeypot(package):
                nonce = package[18:34]
                tag = package[34:50]
                ct_len = int.from_bytes(package[50:54], "big")
                ct = package[54:54+ct_len]
            else:
                enc_key_len = int.from_bytes(package[:2], "big")
                encrypted_aes_key = package[2:2 + enc_key_len]
                nonce = package[2 + enc_key_len:2 + enc_key_len + 16]
                tag = package[2 + enc_key_len + 16:2 + enc_key_len + 32]
                ct = package[2 + enc_key_len + 32:]

            # Tamper multiple bytes at random positions
            tampered = bytearray(ct)
            num_tamper = min(5, len(tampered))
            tamper_positions = random.sample(range(len(tampered)), num_tamper)
            tamper_positions.sort()
            for pos in tamper_positions:
                tampered[pos] ^= 0xFF
            tampered = bytes(tampered)

            # Show visual comparison
            st.markdown("**Data Tampering Visualization**")

            show_bytes = min(32, len(ct))
            orig_hex = " ".join(f"{b:02x}" for b in ct[:show_bytes])
            tamp_hex = " ".join(f"{b:02x}" for b in tampered[:show_bytes])

            # Build colored hex comparison
            orig_display = ""
            tamp_display = ""
            for i in range(show_bytes):
                if ct[i] != tampered[i]:
                    orig_display += f'<span style="color:#ef4444;font-weight:bold">{ct[i]:02x}</span> '
                    tamp_display += f'<span style="color:#22c55e;font-weight:bold">{tampered[i]:02x}</span> '
                else:
                    orig_display += f'<span style="color:#64748b">{ct[i]:02x}</span> '
                    tamp_display += f'<span style="color:#64748b">{tampered[i]:02x}</span> '

            suffix = " ..." if len(ct) > show_bytes else ""

            st.markdown(f"""
<div style="background:#080c14;border:1px solid #1e293b;border-radius:8px;padding:16px;margin:12px 0;font-family:Consolas,monospace;font-size:0.85rem;">
<div style="color:#94a3b8;margin-bottom:8px;">Original ciphertext (first {show_bytes} bytes):</div>
<div>{orig_display}{suffix}</div>
<br>
<div style="color:#94a3b8;margin-bottom:8px;">Tampered ciphertext (first {show_bytes} bytes):</div>
<div>{tamp_display}{suffix}</div>
<br>
<div style="color:#f59e0b;font-size:0.8rem;">Red = original bytes that were changed | Green = tampered bytes</div>
</div>
""", unsafe_allow_html=True)

            # Show bit-level diff for each tampered byte
            st.markdown("**Bit-Level Changes**")
            bit_rows = ""
            for pos in tamper_positions:
                if pos < len(ct):
                    orig_bits = f"{ct[pos]:08b}"
                    tamp_bits = f"{tampered[pos]:08b}"
                    diff_bits = ""
                    for ob, tb in zip(orig_bits, tamp_bits):
                        if ob != tb:
                            diff_bits += f'<span style="color:#ef4444">{tb}</span>'
                        else:
                            diff_bits += f'<span style="color:#64748b">{tb}</span>'
                    bit_rows += f"""
<tr>
<td style="padding:4px 12px;color:#94a3b8;">Byte {pos}</td>
<td style="padding:4px 12px;color:#ef4444;">{orig_bits}</td>
<td style="padding:4px 12px;">{diff_bits}</td>
<td style="padding:4px 12px;color:#94a3b8;">0x{ct[pos]:02x} -> 0x{tampered[pos]:02x}</td>
</tr>"""

            st.markdown(f"""
<div style="background:#080c14;border:1px solid #1e293b;border-radius:8px;padding:16px;margin:12px 0;overflow-x:auto;">
<table style="font-family:Consolas,monospace;font-size:0.82rem;border-collapse:collapse;">
<tr style="color:#7a8ba0;">
<th style="padding:4px 12px;text-align:left;">Position</th>
<th style="padding:4px 12px;text-align:left;">Original Bits</th>
<th style="padding:4px 12px;text-align:left;">Tampered Bits</th>
<th style="padding:4px 12px;text-align:left;">Hex Change</th>
</tr>
{bit_rows}
</table>
<div style="color:#f59e0b;font-size:0.8rem;margin-top:10px;">{num_tamper} byte(s) tampered out of {len(ct)} total bytes</div>
</div>
""", unsafe_allow_html=True)

            # Now attempt decryption
            st.markdown("**Decryption Attempt on Tampered Data**")
            steps = [f"Tampered {num_tamper} byte(s) at positions: {tamper_positions}"]

            if is_honeypot(package):
                fake_key = get_random_bytes(32)
                try:
                    cipher = AES.new(fake_key, AES.MODE_GCM, nonce=nonce)
                    cipher.decrypt_and_verify(tampered, tag)
                    steps.append("Decryption succeeded (unexpected!)")
                except (ValueError, KeyError):
                    steps.append("DECRYPTION FAILED - Authentication tag mismatch!")
                    steps.append("GCM mode detected the tampering")
                    steps.append("RESULT: Even changing 1 bit causes complete decryption failure")
            else:
                try:
                    cipher_rsa = PKCS1_OAEP.new(st.session_state.private_key)
                    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    cipher.decrypt_and_verify(tampered, tag)
                    steps.append("Decryption succeeded (unexpected!)")
                except (ValueError, KeyError):
                    steps.append("DECRYPTION FAILED - Authentication tag mismatch!")
                    steps.append("GCM mode detected the tampering")
                    steps.append("RESULT: Even changing 1 bit causes complete decryption failure")

            show_steps(steps)

    # Wrong Key
    if btn_wrong:
        if not attack_ciphertext:
            show_error("No ciphertext target selected. Choose a source above.")
        else:
            package = base64.b64decode(attack_ciphertext)

            if is_honeypot(package):
                steps = [
                    "Honeypot encryption uses password-derived keys (PBKDF2)",
                    "Generating a random password to attempt decryption...",
                ]
                fake_pwd = base64.b64encode(get_random_bytes(16)).decode()
                salt = package[2:18]
                fake_key = PBKDF2(fake_pwd.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
                steps.append(f"Attacker derived key from random password")

                nonce = package[18:34]
                tag = package[34:50]
                ct_len = int.from_bytes(package[50:54], "big")
                ct = package[54:54+ct_len]

                try:
                    cipher = AES.new(fake_key, AES.MODE_GCM, nonce=nonce)
                    cipher.decrypt_and_verify(ct, tag)
                    steps.append("Decryption succeeded (unexpected!)")
                except (ValueError, KeyError):
                    steps.append("DECRYPTION FAILED!")
                    steps.append("Without the correct password, the key derivation produces wrong keys")
                    steps.append("RESULT: Password-based encryption is secure against guessing")
            else:
                enc_key_len = int.from_bytes(package[:2], "big")
                encrypted_aes_key = package[2:2 + enc_key_len]

                steps = [
                    f"Attacking ciphertext of {len(package) - 2 - enc_key_len - 32} bytes",
                    "Generating attacker's RSA-2048 key pair...",
                ]

                with st.spinner("Generating attacker key pair..."):
                    attacker_key = RSA.generate(2048)

                steps.append("Attempting to decrypt AES key with wrong private key...")

                try:
                    cipher_rsa = PKCS1_OAEP.new(attacker_key)
                    cipher_rsa.decrypt(encrypted_aes_key)
                    steps.append("Decryption succeeded (unexpected!)")
                except (ValueError, KeyError):
                    steps.append("DECRYPTION FAILED!")
                    steps.append("RSA ensures only the correct private key works")
                    steps.append("RESULT: Without the matching private key, data is unrecoverable")

            show_steps(steps)

    # Key Size Comparison
    if btn_keysize:
        test_data = b"This is a secret message for key size comparison."
        steps = []

        for key_size in [16, 24, 32]:
            aes_key = get_random_bytes(key_size)
            start = time.time()
            for _ in range(10000):
                c = AES.new(aes_key, AES.MODE_GCM)
                c.encrypt_and_digest(test_data)
            elapsed = time.time() - start

            steps.append(f"--- AES-{key_size*8} ---")
            steps.append(f"  Key space: 2^{key_size*8} possible keys")
            steps.append(f"  10,000 encryptions in {elapsed:.3f}s")
            steps.append(f"  Brute force: ~{2**(key_size*8):.1e} attempts needed")

        show_steps(steps)

# ===== KEYS TAB =====
with tab_keys:
    st.subheader("RSA Key Management")
    st.caption("Generate a new 2048-bit RSA key pair. Keys are used for all encryption/decryption operations.")

    if st.button("Generate New Key Pair", key="btn_gen_keys", type="primary"):
        with st.spinner("Generating 2048-bit RSA key pair..."):
            start = time.time()
            key = RSA.generate(2048)
            st.session_state.private_key = key
            st.session_state.public_key = key.publickey()
            elapsed = time.time() - start

        keys_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
        os.makedirs(keys_folder, exist_ok=True)
        with open(os.path.join(keys_folder, "private_key.pem"), "wb") as f:
            f.write(key.export_key())
        with open(os.path.join(keys_folder, "public_key.pem"), "wb") as f:
            f.write(key.publickey().export_key())

        st.success(f"Key pair generated in {elapsed:.2f}s")
        steps = [
            "Generating 2048-bit RSA key pair...",
            f"RSA key pair generated in {elapsed:.2f}s",
            "Public key saved to keys/public_key.pem",
            "Private key saved to keys/private_key.pem",
        ]
        with st.expander("Step-by-Step Process", expanded=True):
            show_steps(steps)

    if st.session_state.public_key:
        st.text_area("Public Key Preview", value=st.session_state.public_key.export_key().decode(), height=200, key="key_prev")
    else:
        st.info("No keys generated yet. Click the button above.")
