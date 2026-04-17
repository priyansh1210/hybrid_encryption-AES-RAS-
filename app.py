"""
Hybrid Encryption Web App (RSA + AES) - Flask Frontend
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from flask import Flask, render_template, request, jsonify, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import time
import tempfile

app = Flask(__name__)

# Store keys in memory for the session
keys = {"private": None, "public": None}
honeypot_store = {}


def ensure_keys():
    if keys["private"] is None:
        key = RSA.generate(2048)
        keys["private"] = key
        keys["public"] = key.publickey()


# ── ROUTES ──

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate-keys", methods=["POST"])
def api_generate_keys():
    start = time.time()
    key = RSA.generate(2048)
    keys["private"] = key
    keys["public"] = key.publickey()
    elapsed = time.time() - start

    keys_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
    os.makedirs(keys_folder, exist_ok=True)
    with open(os.path.join(keys_folder, "private_key.pem"), "wb") as f:
        f.write(key.export_key())
    with open(os.path.join(keys_folder, "public_key.pem"), "wb") as f:
        f.write(key.publickey().export_key())

    return jsonify({
        "success": True,
        "time": f"{elapsed:.2f}s",
        "public_key_preview": key.publickey().export_key().decode()[:200] + "...",
        "steps": [
            "Generating 2048-bit RSA key pair...",
            f"RSA key pair generated in {elapsed:.2f}s",
            "Public key saved to keys/public_key.pem",
            "Private key saved to keys/private_key.pem",
        ]
    })


@app.route("/api/encrypt-message", methods=["POST"])
def api_encrypt_message():
    ensure_keys()
    data = request.json
    message = data.get("message", "")
    if not message:
        return jsonify({"success": False, "error": "Message is empty"})

    plaintext = message.encode("utf-8")
    steps = []

    # Step 1: Generate AES key
    aes_key = get_random_bytes(32)
    steps.append(f"AES-256 key generated: {aes_key.hex()}")

    # Step 2: Encrypt with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
    steps.append(f"Data encrypted with AES-256-GCM")
    steps.append(f"Nonce: {cipher_aes.nonce.hex()}")
    steps.append(f"Auth Tag: {tag.hex()}")
    steps.append(f"Ciphertext size: {len(ciphertext)} bytes")

    # Step 3: Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(keys["public"])
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    steps.append(f"AES key encrypted with RSA public key")
    steps.append(f"Encrypted key size: {len(encrypted_aes_key)} bytes")

    # Pack into base64 for display
    package = (
        len(encrypted_aes_key).to_bytes(2, "big") +
        encrypted_aes_key +
        cipher_aes.nonce +
        tag +
        ciphertext
    )
    encoded = base64.b64encode(package).decode()

    return jsonify({
        "success": True,
        "ciphertext": encoded,
        "steps": steps,
    })


@app.route("/api/decrypt-message", methods=["POST"])
def api_decrypt_message():
    ensure_keys()
    data = request.json
    encoded = data.get("ciphertext", "")
    if not encoded:
        return jsonify({"success": False, "error": "Ciphertext is empty"})

    try:
        package = base64.b64decode(encoded)
    except Exception:
        return jsonify({"success": False, "error": "Invalid base64 ciphertext"})

    steps = []

    try:
        enc_key_len = int.from_bytes(package[:2], "big")
        encrypted_aes_key = package[2:2 + enc_key_len]
        nonce = package[2 + enc_key_len:2 + enc_key_len + 16]
        tag = package[2 + enc_key_len + 16:2 + enc_key_len + 32]
        ciphertext = package[2 + enc_key_len + 32:]

        # Step 1: Decrypt AES key
        cipher_rsa = PKCS1_OAEP.new(keys["private"])
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        steps.append(f"AES key decrypted with RSA private key")
        steps.append(f"Recovered AES key: {aes_key.hex()}")

        # Step 2: Decrypt data
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        steps.append("Authentication tag verified")
        steps.append(f"Data decrypted successfully ({len(plaintext)} bytes)")

        return jsonify({
            "success": True,
            "plaintext": plaintext.decode("utf-8"),
            "steps": steps,
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Decryption failed: {str(e)}"})


@app.route("/api/encrypt-file", methods=["POST"])
def api_encrypt_file():
    ensure_keys()
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"})

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"})

    plaintext = file.read()
    steps = []

    aes_key = get_random_bytes(32)
    steps.append(f"AES-256 key generated: {aes_key.hex()}")

    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
    steps.append(f"File encrypted with AES-256-GCM ({len(plaintext)} bytes)")

    cipher_rsa = PKCS1_OAEP.new(keys["public"])
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    steps.append("AES key encrypted with RSA public key")

    package = (
        len(encrypted_aes_key).to_bytes(2, "big") +
        encrypted_aes_key +
        cipher_aes.nonce +
        tag +
        ciphertext
    )

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file.filename + ".enc")
    with open(out_path, "wb") as f:
        f.write(package)

    encoded = base64.b64encode(package).decode()
    steps.append(f"Encrypted file saved: {file.filename}.enc")

    return jsonify({
        "success": True,
        "ciphertext": encoded,
        "filename": file.filename + ".enc",
        "steps": steps,
    })


@app.route("/api/decrypt-file", methods=["POST"])
def api_decrypt_file():
    ensure_keys()
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"})

    file = request.files["file"]
    package = file.read()
    steps = []

    try:
        enc_key_len = int.from_bytes(package[:2], "big")
        encrypted_aes_key = package[2:2 + enc_key_len]
        nonce = package[2 + enc_key_len:2 + enc_key_len + 16]
        tag = package[2 + enc_key_len + 16:2 + enc_key_len + 32]
        ciphertext = package[2 + enc_key_len + 32:]

        cipher_rsa = PKCS1_OAEP.new(keys["private"])
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        steps.append("AES key recovered with RSA private key")

        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        steps.append(f"File decrypted successfully ({len(plaintext)} bytes)")

        original_name = file.filename
        if original_name.endswith(".enc"):
            original_name = original_name[:-4]
        name, ext = os.path.splitext(original_name)
        out_name = name + "_decrypted" + ext

        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), out_name)
        with open(out_path, "wb") as f:
            f.write(plaintext)
        steps.append(f"Decrypted file saved: {out_name}")

        try:
            text_preview = plaintext.decode("utf-8")[:500]
        except Exception:
            text_preview = f"[Binary file - {len(plaintext)} bytes]"

        return jsonify({
            "success": True,
            "filename": out_name,
            "preview": text_preview,
            "steps": steps,
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Decryption failed: {str(e)}"})


@app.route("/api/attack/brute-force", methods=["POST"])
def api_attack_brute_force():
    ensure_keys()
    data = request.json
    encoded = data.get("ciphertext", "")
    if not encoded:
        return jsonify({"success": False, "error": "No ciphertext to attack. Encrypt a message first."})

    try:
        package = base64.b64decode(encoded)
    except Exception:
        return jsonify({"success": False, "error": "Invalid ciphertext"})

    enc_key_len = int.from_bytes(package[:2], "big")
    nonce = package[2 + enc_key_len:2 + enc_key_len + 16]
    tag = package[2 + enc_key_len + 16:2 + enc_key_len + 32]
    ciphertext = package[2 + enc_key_len + 32:]

    attempts = 10000
    start = time.time()
    for _ in range(attempts):
        fake_key = get_random_bytes(32)
        try:
            cipher = AES.new(fake_key, AES.MODE_GCM, nonce=nonce)
            cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            pass
    elapsed = time.time() - start
    keys_per_sec = attempts / elapsed
    years = (2**256) / keys_per_sec / 60 / 60 / 24 / 365

    return jsonify({
        "success": True,
        "steps": [
            "AES-256 has 2^256 possible keys",
            f"Tried {attempts:,} random keys in {elapsed:.2f}s",
            f"Speed: {keys_per_sec:,.0f} keys/second",
            f"Time to try all keys: ~{years:.2e} years",
            "RESULT: Brute force is IMPOSSIBLE on AES-256",
        ]
    })


@app.route("/api/attack/tamper", methods=["POST"])
def api_attack_tamper():
    ensure_keys()
    data = request.json
    encoded = data.get("ciphertext", "")
    if not encoded:
        return jsonify({"success": False, "error": "No ciphertext to attack. Encrypt a message first."})

    try:
        package = base64.b64decode(encoded)
    except Exception:
        return jsonify({"success": False, "error": "Invalid ciphertext"})

    enc_key_len = int.from_bytes(package[:2], "big")
    encrypted_aes_key = package[2:2 + enc_key_len]
    nonce = package[2 + enc_key_len:2 + enc_key_len + 16]
    tag = package[2 + enc_key_len + 16:2 + enc_key_len + 32]
    ciphertext = package[2 + enc_key_len + 32:]

    tampered_ct = bytearray(ciphertext)
    if len(tampered_ct) > 0:
        tampered_ct[0] ^= 0xFF
    tampered_ct = bytes(tampered_ct)

    steps = ["Flipped bits in first byte of ciphertext", "Attempting decryption of tampered data..."]

    try:
        cipher_rsa = PKCS1_OAEP.new(keys["private"])
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        cipher.decrypt_and_verify(tampered_ct, tag)
        steps.append("Decryption succeeded (unexpected!)")
    except (ValueError, KeyError):
        steps.append("DECRYPTION FAILED - Authentication tag mismatch!")
        steps.append("GCM mode detected the tampering")
        steps.append("RESULT: AES-GCM provides integrity protection")

    return jsonify({"success": True, "steps": steps})


@app.route("/api/attack/wrong-key", methods=["POST"])
def api_attack_wrong_key():
    data = request.json
    encoded = data.get("ciphertext", "")
    if not encoded:
        return jsonify({"success": False, "error": "No ciphertext to attack. Encrypt a message first."})

    try:
        package = base64.b64decode(encoded)
    except Exception:
        return jsonify({"success": False, "error": "Invalid ciphertext"})

    enc_key_len = int.from_bytes(package[:2], "big")
    encrypted_aes_key = package[2:2 + enc_key_len]

    steps = ["Generating attacker's RSA-2048 key pair..."]
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

    return jsonify({"success": True, "steps": steps})


@app.route("/api/honeypot/encrypt", methods=["POST"])
def api_honeypot_encrypt():
    data = request.json
    real_msg = data.get("real_message", "")
    decoy_msg = data.get("decoy_message", "")
    real_pwd = data.get("real_password", "")
    decoy_pwd = data.get("decoy_password", "")

    if not all([real_msg, decoy_msg, real_pwd, decoy_pwd]):
        return jsonify({"success": False, "error": "All fields are required"})
    if real_pwd == decoy_pwd:
        return jsonify({"success": False, "error": "Passwords must be different"})

    steps = []
    salt = get_random_bytes(16)
    steps.append(f"Salt generated: {salt.hex()}")

    real_key = PBKDF2(real_pwd.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    steps.append(f"Real password key derived (PBKDF2, 100k rounds)")

    decoy_key = PBKDF2(decoy_pwd.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    steps.append(f"Decoy password key derived (PBKDF2, 100k rounds)")

    cipher_real = AES.new(real_key, AES.MODE_GCM)
    ct_real, tag_real = cipher_real.encrypt_and_digest(real_msg.encode())
    steps.append("Real message encrypted")

    cipher_decoy = AES.new(decoy_key, AES.MODE_GCM)
    ct_decoy, tag_decoy = cipher_decoy.encrypt_and_digest(decoy_msg.encode())
    steps.append("Decoy message encrypted")

    # Pack: salt(16) + [nonce(16)+tag(16)+ct_len(4)+ct] x2
    package = (
        salt +
        cipher_real.nonce + tag_real + len(ct_real).to_bytes(4, "big") + ct_real +
        cipher_decoy.nonce + tag_decoy + len(ct_decoy).to_bytes(4, "big") + ct_decoy
    )
    encoded = base64.b64encode(package).decode()
    steps.append("Both messages packed into single encrypted blob")

    hp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.enc")
    with open(hp_path, "wb") as f:
        f.write(package)
    steps.append("Saved to honeypot.enc")

    return jsonify({"success": True, "ciphertext": encoded, "steps": steps})


@app.route("/api/honeypot/decrypt", methods=["POST"])
def api_honeypot_decrypt():
    data = request.json
    encoded = data.get("ciphertext", "")
    password = data.get("password", "")

    if not encoded or not password:
        return jsonify({"success": False, "error": "Ciphertext and password are required"})

    try:
        package = base64.b64decode(encoded)
    except Exception:
        return jsonify({"success": False, "error": "Invalid ciphertext"})

    salt = package[:16]
    steps = [f"Deriving key from password (PBKDF2, 100k rounds)..."]

    key = PBKDF2(password.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    steps.append(f"Derived key: {key.hex()}")

    # Parse both encrypted messages
    pos = 16
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
            steps.append(f"Decryption successful!")
            msg_type = labels[i]
            if msg_type == "DECOY":
                steps.append("The attacker thinks they won -- but this is the DECOY!")
            else:
                steps.append("This is the REAL secret message")
            return jsonify({
                "success": True,
                "plaintext": plaintext.decode("utf-8"),
                "message_type": msg_type,
                "steps": steps,
            })
        except (ValueError, KeyError):
            continue

    return jsonify({"success": False, "error": "Wrong password! Neither message could be decrypted."})


if __name__ == "__main__":
    print("\n  Starting Hybrid Encryption Web App...")
    print("  Open http://127.0.0.1:5000 in your browser\n")
    app.run(debug=True, port=5000)
