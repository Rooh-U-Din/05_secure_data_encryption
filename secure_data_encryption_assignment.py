import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
import base64
from datetime import datetime, timedelta

# JSON file for storing encrypted data
DATA_FILE = "data_store.json"

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 3

if "lockout_until" not in st.session_state:
    st.session_state.lockout_until = None

# Generate or load encryption key
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    KEY = f.read()

cipher = Fernet(KEY)

# Load existing data from JSON
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

stored_data = load_data()
failed_attempts = 0

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)  # 16 bytes = 128-bit salt
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

def verify_passkey(passkey, stored_hash):
    decoded = base64.b64decode(stored_hash.encode())
    salt = decoded[:16]
    stored_key = decoded[16:]
    new_key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return new_key == stored_key


st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data(stored_data)
            st.success("✅ Data stored securely in JSON file!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Stored Encrypted Data")

    # Lockout check
    if st.session_state.lockout_until and datetime.now() < st.session_state.lockout_until:
        remaining = (st.session_state.lockout_until - datetime.now()).seconds
        st.warning(f"🔒 Locked out! Try again in {remaining} seconds.")
        st.stop()

    if not stored_data:
        st.info("ℹ️ No encrypted data found.")
    else:
        encrypted_options = list(stored_data.keys())
        selected_encrypted = st.selectbox("📄 Select Encrypted Data to Decrypt:", encrypted_options)

        st.code(selected_encrypted, language="text")
        passkey = st.text_input("🔑 Enter Your Passkey:", type="password")

        if st.button("🔓 Decrypt Selected Data"):
            stored_hash = stored_data[selected_encrypted]["passkey"]

            if verify_passkey(passkey, stored_hash):
                try:
                    decrypted = decrypt_data(selected_encrypted)
                    st.session_state.failed_attempts = 0  # ✅ Reset on success
                    st.session_state.lockout_until = None
                    st.success("✅ Successfully Decrypted!")
                    st.text_area("📖 Your Decrypted Data:", decrypted, height=150)
                except:
                    st.error("⚠️ Decryption failed.")
            else:
                # ❌ Wrong passkey
                st.session_state.failed_attempts += 1
                remaining_attempts = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining_attempts}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_until = datetime.now() + timedelta(seconds=300)
                    st.warning("🚫 Too many failed attempts. Locked out for 5mints.")
                    st.rerun()

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
