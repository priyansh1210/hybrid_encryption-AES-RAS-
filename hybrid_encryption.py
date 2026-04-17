"""
Hybrid Encryption Project (RSA + AES)
Simple implementation demonstrating how hybrid encryption works.
"""

import sys
import os

# Add local lib folder for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import time
import hashlib


# ─────────────────────────────────────────────
# KEY GENERATION
# ─────────────────────────────────────────────

def generate_rsa_keys():
    """Generate a 2048-bit RSA key pair."""
    print("\n[Step 1] Generating 2048-bit RSA key pair...")
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    print("  ✔ RSA Public Key  generated (2048 bits)")
    print("  ✔ RSA Private Key generated (2048 bits)")
    return private_key, public_key


def generate_aes_key():
    """Generate a random 256-bit AES key."""
    aes_key = get_random_bytes(32)  # 256 bits
    print("\n[Step 2] Generating random AES-256 key...")
    print(f"  ✔ AES Key (hex): {aes_key.hex()}")
    print(f"  ✔ AES Key size : 256 bits")
    return aes_key


# ─────────────────────────────────────────────
# ENCRYPTION
# ─────────────────────────────────────────────

def encrypt_aes(data, aes_key):
    """Encrypt data using AES-256 in GCM mode."""
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("\n[Step 3] Encrypting data with AES-256-GCM...")
    print(f"  ✔ Nonce (hex)     : {cipher.nonce.hex()}")
    print(f"  ✔ Auth Tag (hex)  : {tag.hex()}")
    print(f"  ✔ Ciphertext size : {len(ciphertext)} bytes")
    return cipher.nonce, tag, ciphertext


def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    """Encrypt the AES key using RSA public key."""
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    print("\n[Step 4] Encrypting AES key with RSA public key...")
    print(f"  ✔ Encrypted AES key (base64): {base64.b64encode(encrypted_aes_key).decode()[:60]}...")
    print(f"  ✔ Encrypted key size: {len(encrypted_aes_key)} bytes")
    return encrypted_aes_key


def hybrid_encrypt(data, rsa_public_key):
    """Full hybrid encryption: AES encrypts data, RSA encrypts AES key."""
    aes_key = generate_aes_key()
    nonce, tag, ciphertext = encrypt_aes(data, aes_key)
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, rsa_public_key)

    print("\n" + "=" * 50)
    print("  ENCRYPTION COMPLETE")
    print("=" * 50)

    # Pack everything together
    package = {
        "encrypted_aes_key": encrypted_aes_key,
        "nonce": nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }
    return package


# ─────────────────────────────────────────────
# DECRYPTION
# ─────────────────────────────────────────────

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    """Decrypt the AES key using RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print("\n[Step 1] Decrypting AES key with RSA private key...")
    print(f"  ✔ Recovered AES Key (hex): {aes_key.hex()}")
    return aes_key


def decrypt_aes(nonce, tag, ciphertext, aes_key):
    """Decrypt data using AES-256 GCM."""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print("\n[Step 2] Decrypting data with AES-256-GCM...")
    print(f"  ✔ Authentication tag verified")
    print(f"  ✔ Decrypted data size: {len(data)} bytes")
    return data


def hybrid_decrypt(package, rsa_private_key):
    """Full hybrid decryption."""
    aes_key = decrypt_aes_key_with_rsa(package["encrypted_aes_key"], rsa_private_key)
    data = decrypt_aes(package["nonce"], package["tag"], package["ciphertext"], aes_key)

    print("\n" + "=" * 50)
    print("  DECRYPTION COMPLETE")
    print("=" * 50)
    return data


# ─────────────────────────────────────────────
# FILE HANDLING
# ─────────────────────────────────────────────

def save_encrypted(package, output_path):
    """Save encrypted package to a .enc file."""
    with open(output_path, "wb") as f:
        # Format: [enc_key_len(2 bytes)][encrypted_aes_key][nonce(16)][tag(16)][ciphertext]
        enc_key = package["encrypted_aes_key"]
        f.write(len(enc_key).to_bytes(2, "big"))
        f.write(enc_key)
        f.write(package["nonce"])
        f.write(package["tag"])
        f.write(package["ciphertext"])
    print(f"  ✔ Saved encrypted file: {output_path}")


def load_encrypted(input_path):
    """Load encrypted package from a .enc file."""
    with open(input_path, "rb") as f:
        enc_key_len = int.from_bytes(f.read(2), "big")
        encrypted_aes_key = f.read(enc_key_len)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    return {
        "encrypted_aes_key": encrypted_aes_key,
        "nonce": nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }


def save_keys(private_key, public_key, folder):
    """Save RSA keys to PEM files."""
    priv_path = os.path.join(folder, "private_key.pem")
    pub_path = os.path.join(folder, "public_key.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.export_key())
    with open(pub_path, "wb") as f:
        f.write(public_key.export_key())
    print(f"  ✔ Private key saved: {priv_path}")
    print(f"  ✔ Public key saved : {pub_path}")


def load_keys(folder):
    """Load RSA keys from PEM files."""
    priv_path = os.path.join(folder, "private_key.pem")
    pub_path = os.path.join(folder, "public_key.pem")
    with open(priv_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(pub_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key


# ─────────────────────────────────────────────
# ATTACK SIMULATIONS
# ─────────────────────────────────────────────

def attack_brute_force_aes(package):
    """Simulate brute-force attack on AES-256 key."""
    print("\n" + "=" * 50)
    print("  ATTACK: Brute Force on AES-256 Key")
    print("=" * 50)
    print("\n  AES-256 has 2^256 possible keys.")
    print("  That's 115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,936 keys!")

    print("\n  Simulating 1 million random key guesses...")
    attempts = 1_000_000
    start = time.time()
    for i in range(attempts):
        fake_key = get_random_bytes(32)
        try:
            cipher = AES.new(fake_key, AES.MODE_GCM, nonce=package["nonce"])
            cipher.decrypt_and_verify(package["ciphertext"], package["tag"])
            print(f"  ✗ Key found! (this should never happen)")
            return
        except (ValueError, KeyError):
            pass
    elapsed = time.time() - start

    print(f"  ✔ Tried {attempts:,} keys in {elapsed:.2f} seconds")
    keys_per_sec = attempts / elapsed
    print(f"  ✔ Speed: {keys_per_sec:,.0f} keys/second")
    years = (2**256) / keys_per_sec / 60 / 60 / 24 / 365
    print(f"  ✔ Time to try all keys: ~{years:.2e} years")
    print(f"\n  RESULT: Brute force is IMPOSSIBLE on AES-256.")


def attack_tamper_ciphertext(package, rsa_private_key):
    """Simulate tampering with ciphertext (integrity attack)."""
    print("\n" + "=" * 50)
    print("  ATTACK: Ciphertext Tampering (Integrity Attack)")
    print("=" * 50)

    tampered = dict(package)
    ct = bytearray(package["ciphertext"])
    if len(ct) > 0:
        ct[0] ^= 0xFF  # Flip bits in first byte
    tampered["ciphertext"] = bytes(ct)

    print("\n  Flipped bits in the first byte of ciphertext.")
    print("  Trying to decrypt tampered data...")

    try:
        aes_key = decrypt_aes_key_with_rsa(tampered["encrypted_aes_key"], rsa_private_key)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=tampered["nonce"])
        cipher.decrypt_and_verify(tampered["ciphertext"], tampered["tag"])
        print("  ✗ Decryption succeeded (should not happen!)")
    except (ValueError, KeyError):
        print("\n  ✔ DECRYPTION FAILED — Authentication tag mismatch!")
        print("  ✔ GCM mode detected the tampering.")
        print("\n  RESULT: AES-GCM provides integrity protection.")


def attack_wrong_rsa_key(package):
    """Simulate decryption with the wrong RSA private key."""
    print("\n" + "=" * 50)
    print("  ATTACK: Wrong RSA Private Key")
    print("=" * 50)

    print("\n  Generating a different RSA key pair (attacker's key)...")
    attacker_key = RSA.generate(2048)

    print("  Trying to decrypt AES key with attacker's private key...")
    try:
        cipher_rsa = PKCS1_OAEP.new(attacker_key)
        cipher_rsa.decrypt(package["encrypted_aes_key"])
        print("  ✗ Decryption succeeded (should not happen!)")
    except (ValueError, KeyError):
        print("\n  ✔ DECRYPTION FAILED!")
        print("  ✔ RSA ensures only the correct private key can recover the AES key.")
        print("\n  RESULT: Without the matching private key, data is unrecoverable.")


def attack_key_size_comparison():
    """Compare encryption strength with different key sizes."""
    print("\n" + "=" * 50)
    print("  DEMO: Key Size Strength Comparison")
    print("=" * 50)

    test_data = b"This is a secret message for key size comparison."

    for key_size in [16, 24, 32]:  # AES-128, AES-192, AES-256
        aes_key = get_random_bytes(key_size)
        cipher = AES.new(aes_key, AES.MODE_GCM)
        start = time.time()
        for _ in range(10000):
            c = AES.new(aes_key, AES.MODE_GCM)
            c.encrypt_and_digest(test_data)
        elapsed = time.time() - start
        print(f"\n  AES-{key_size*8}:")
        print(f"    Key space   : 2^{key_size*8} possible keys")
        print(f"    10,000 encryptions in {elapsed:.3f}s")
        print(f"    Brute force : ~{2**(key_size*8):.1e} attempts needed")


# ─────────────────────────────────────────────
# HONEYPOT DECRYPTION
# ─────────────────────────────────────────────

def derive_key_from_password(password, salt):
    """Derive a 256-bit AES key from a password using PBKDF2."""
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    return key


def honeypot_encrypt(real_message, decoy_message, real_password, decoy_password):
    """Encrypt two messages: real and decoy, each unlocked by a different password."""
    print("\n" + "=" * 50)
    print("  HONEYPOT ENCRYPTION")
    print("=" * 50)

    salt = get_random_bytes(16)
    print(f"\n[Step 1] Generating salt...")
    print(f"  ✔ Salt (hex): {salt.hex()}")

    # Derive keys from passwords
    print(f"\n[Step 2] Deriving AES keys from passwords (PBKDF2, 100k rounds)...")
    real_key = derive_key_from_password(real_password, salt)
    print(f"  ✔ Real password key (hex)  : {real_key.hex()}")
    decoy_key = derive_key_from_password(decoy_password, salt)
    print(f"  ✔ Decoy password key (hex) : {decoy_key.hex()}")

    # Encrypt real message
    print(f"\n[Step 3] Encrypting REAL message with real password key...")
    cipher_real = AES.new(real_key, AES.MODE_GCM)
    ct_real, tag_real = cipher_real.encrypt_and_digest(real_message.encode("utf-8"))
    print(f"  ✔ Ciphertext size: {len(ct_real)} bytes")

    # Encrypt decoy message
    print(f"\n[Step 4] Encrypting DECOY message with decoy password key...")
    cipher_decoy = AES.new(decoy_key, AES.MODE_GCM)
    ct_decoy, tag_decoy = cipher_decoy.encrypt_and_digest(decoy_message.encode("utf-8"))
    print(f"  ✔ Ciphertext size: {len(ct_decoy)} bytes")

    package = {
        "salt": salt,
        "real": {"nonce": cipher_real.nonce, "tag": tag_real, "ciphertext": ct_real},
        "decoy": {"nonce": cipher_decoy.nonce, "tag": tag_decoy, "ciphertext": ct_decoy},
    }

    print("\n" + "=" * 50)
    print("  HONEYPOT ENCRYPTION COMPLETE")
    print("=" * 50)
    print("  Both messages are now encrypted.")
    print("  An attacker who forces you to reveal a password")
    print("  gets the DECOY. Only you know the REAL password.")

    return package


def honeypot_decrypt(package, password):
    """Try to decrypt with the given password. Returns whichever message matches."""
    print("\n" + "=" * 50)
    print("  HONEYPOT DECRYPTION")
    print("=" * 50)

    key = derive_key_from_password(password, package["salt"])
    print(f"\n[Step 1] Deriving key from password...")
    print(f"  ✔ Derived key (hex): {key.hex()}")

    # Try real message
    print(f"\n[Step 2] Attempting decryption...")
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=package["real"]["nonce"])
        data = cipher.decrypt_and_verify(package["real"]["ciphertext"], package["real"]["tag"])
        print(f"  ✔ Decryption successful!")
        print(f"\n  Decrypted Message: {data.decode('utf-8')}")
        print(f"\n  (This was the REAL message)")
        return
    except (ValueError, KeyError):
        pass

    # Try decoy message
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=package["decoy"]["nonce"])
        data = cipher.decrypt_and_verify(package["decoy"]["ciphertext"], package["decoy"]["tag"])
        print(f"  ✔ Decryption successful!")
        print(f"\n  Decrypted Message: {data.decode('utf-8')}")
        print(f"\n  (This was the DECOY message — attacker thinks they won!)")
        return
    except (ValueError, KeyError):
        pass

    print(f"  ✗ Wrong password! Neither message could be decrypted.")


def save_honeypot(package, output_path):
    """Save honeypot package to file."""
    with open(output_path, "wb") as f:
        # Format: salt(16) + [nonce(16)+tag(16)+ct_len(4)+ct] x2
        f.write(package["salt"])
        for key in ["real", "decoy"]:
            p = package[key]
            f.write(p["nonce"])
            f.write(p["tag"])
            f.write(len(p["ciphertext"]).to_bytes(4, "big"))
            f.write(p["ciphertext"])
    print(f"  ✔ Saved honeypot file: {output_path}")


def load_honeypot(input_path):
    """Load honeypot package from file."""
    with open(input_path, "rb") as f:
        salt = f.read(16)
        package = {"salt": salt}
        for key in ["real", "decoy"]:
            nonce = f.read(16)
            tag = f.read(16)
            ct_len = int.from_bytes(f.read(4), "big")
            ciphertext = f.read(ct_len)
            package[key] = {"nonce": nonce, "tag": tag, "ciphertext": ciphertext}
    return package


# ─────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────

def print_menu():
    print("\n" + "=" * 50)
    print("   HYBRID ENCRYPTION SYSTEM (RSA + AES)")
    print("=" * 50)
    print("  1. Generate RSA Key Pair")
    print("  2. Encrypt a Message")
    print("  3. Decrypt a Message")
    print("  4. Encrypt a File")
    print("  5. Decrypt a File")
    print("  6. Attack Simulations")
    print("  7. Honeypot Encryption (Plausible Deniability)")
    print("  8. Exit")
    print("=" * 50)


def attack_menu():
    print("\n" + "=" * 50)
    print("   ATTACK SIMULATIONS")
    print("=" * 50)
    print("  1. Brute Force AES-256 Key")
    print("  2. Ciphertext Tampering")
    print("  3. Wrong RSA Private Key")
    print("  4. Key Size Comparison")
    print("  5. Back to Main Menu")
    print("=" * 50)


def main():
    private_key = None
    public_key = None
    last_encrypted_package = None
    keys_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

    # Try loading existing keys
    if os.path.exists(os.path.join(keys_folder, "private_key.pem")):
        try:
            private_key, public_key = load_keys(keys_folder)
            print("\n  ✔ Loaded existing RSA keys from /keys folder.")
        except Exception:
            pass

    while True:
        print_menu()
        choice = input("  Enter choice (1-8): ").strip()

        # ── 1. Generate Keys ──
        if choice == "1":
            private_key, public_key = generate_rsa_keys()
            os.makedirs(keys_folder, exist_ok=True)
            save_keys(private_key, public_key, keys_folder)

        # ── 2. Encrypt Message ──
        elif choice == "2":
            if not public_key:
                print("\n  ✗ No RSA keys found. Generate keys first (option 1).")
                continue
            message = input("\n  Enter message to encrypt: ")
            if not message:
                print("  ✗ Empty message.")
                continue

            print("\n" + "=" * 50)
            print("  ENCRYPTING MESSAGE")
            print("=" * 50)
            data = message.encode("utf-8")
            last_encrypted_package = hybrid_encrypt(data, public_key)

            # Save to file too
            enc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "message.enc")
            save_encrypted(last_encrypted_package, enc_path)

        # ── 3. Decrypt Message ──
        elif choice == "3":
            if not private_key:
                print("\n  ✗ No RSA keys found. Generate keys first (option 1).")
                continue

            enc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "message.enc")
            if last_encrypted_package:
                pkg = last_encrypted_package
            elif os.path.exists(enc_path):
                pkg = load_encrypted(enc_path)
            else:
                print("\n  ✗ No encrypted message found. Encrypt a message first (option 2).")
                continue

            print("\n" + "=" * 50)
            print("  DECRYPTING MESSAGE")
            print("=" * 50)
            try:
                decrypted_data = hybrid_decrypt(pkg, private_key)
                print(f"\n  Decrypted Message: {decrypted_data.decode('utf-8')}")
            except Exception as e:
                print(f"\n  ✗ Decryption failed: {e}")

        # ── 4. Encrypt File ──
        elif choice == "4":
            if not public_key:
                print("\n  ✗ No RSA keys found. Generate keys first (option 1).")
                continue
            filepath = input("\n  Enter file path to encrypt: ").strip().strip('"')
            if not os.path.exists(filepath):
                print(f"  ✗ File not found: {filepath}")
                continue

            print(f"\n" + "=" * 50)
            print(f"  ENCRYPTING FILE: {os.path.basename(filepath)}")
            print("=" * 50)

            with open(filepath, "rb") as f:
                data = f.read()
            print(f"  ✔ Read {len(data)} bytes from file")

            package = hybrid_encrypt(data, public_key)
            out_path = filepath + ".enc"
            save_encrypted(package, out_path)
            print(f"\n  Encrypted file saved: {out_path}")

        # ── 5. Decrypt File ──
        elif choice == "5":
            if not private_key:
                print("\n  ✗ No RSA keys found. Generate keys first (option 1).")
                continue
            filepath = input("\n  Enter .enc file path to decrypt: ").strip().strip('"')
            if not os.path.exists(filepath):
                print(f"  ✗ File not found: {filepath}")
                continue

            print(f"\n" + "=" * 50)
            print(f"  DECRYPTING FILE: {os.path.basename(filepath)}")
            print("=" * 50)

            try:
                package = load_encrypted(filepath)
                decrypted_data = hybrid_decrypt(package, private_key)

                # Remove .enc extension for output
                if filepath.endswith(".enc"):
                    out_path = filepath[:-4]
                    # Add _decrypted to avoid overwriting original
                    name, ext = os.path.splitext(out_path)
                    out_path = name + "_decrypted" + ext
                else:
                    out_path = filepath + ".dec"

                with open(out_path, "wb") as f:
                    f.write(decrypted_data)
                print(f"\n  Decrypted file saved: {out_path}")
            except Exception as e:
                print(f"\n  ✗ Decryption failed: {e}")

        # ── 6. Attack Simulations ──
        elif choice == "6":
            if not private_key or not last_encrypted_package:
                print("\n  ✗ Please generate keys (option 1) and encrypt a message (option 2) first.")
                continue

            while True:
                attack_menu()
                atk = input("  Enter choice (1-5): ").strip()
                if atk == "1":
                    attack_brute_force_aes(last_encrypted_package)
                elif atk == "2":
                    attack_tamper_ciphertext(last_encrypted_package, private_key)
                elif atk == "3":
                    attack_wrong_rsa_key(last_encrypted_package)
                elif atk == "4":
                    attack_key_size_comparison()
                elif atk == "5":
                    break
                else:
                    print("  ✗ Invalid choice.")

        # ── 7. Honeypot Encryption ──
        elif choice == "7":
            honeypot_pkg = None
            hp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.enc")

            print("\n" + "=" * 50)
            print("   HONEYPOT ENCRYPTION (Plausible Deniability)")
            print("=" * 50)
            print("  1. Create Honeypot Message")
            print("  2. Decrypt Honeypot Message")
            print("  3. Back to Main Menu")
            print("=" * 50)
            hp_choice = input("  Enter choice (1-3): ").strip()

            if hp_choice == "1":
                real_msg = input("\n  Enter your REAL secret message: ")
                decoy_msg = input("  Enter the DECOY message (what attacker sees): ")
                real_pwd = input("  Enter your REAL password: ")
                decoy_pwd = input("  Enter the DECOY password (give this to attacker): ")

                if not all([real_msg, decoy_msg, real_pwd, decoy_pwd]):
                    print("  ✗ All fields are required.")
                elif real_pwd == decoy_pwd:
                    print("  ✗ Real and decoy passwords must be different!")
                else:
                    honeypot_pkg = honeypot_encrypt(real_msg, decoy_msg, real_pwd, decoy_pwd)
                    save_honeypot(honeypot_pkg, hp_path)

            elif hp_choice == "2":
                if os.path.exists(hp_path):
                    honeypot_pkg = load_honeypot(hp_path)
                    print(f"\n  ✔ Loaded honeypot file: {hp_path}")
                else:
                    print("\n  ✗ No honeypot file found. Create one first.")
                    continue

                pwd = input("\n  Enter password to decrypt: ")
                honeypot_decrypt(honeypot_pkg, pwd)

        # ── 8. Exit ──
        elif choice == "8":
            print("\n  Goodbye!\n")
            break
        else:
            print("  ✗ Invalid choice. Try again.")


if __name__ == "__main__":
    main()
