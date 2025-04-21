import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
import base64
from datetime import datetime, timedelta

# File paths
DATA_FILE = "data_store.json"
USER_FILE = "users.json"
KEY_FILE = "secret.key"

# Session initialization
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_until" not in st.session_state:
    st.session_state.lockout_until = None

if "failed_retrieve_attempts" not in st.session_state:
    st.session_state.failed_retrieve_attempts = 0
if "lockout_retrieve_until" not in st.session_state:
    st.session_state.lockout_retrieve_until = None
if "post_lock_single_chance_used" not in st.session_state:
    st.session_state.post_lock_single_chance_used = False


# Encryption Key
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    KEY = f.read()
cipher = Fernet(KEY)

# Load data
def load_json(file):
    if os.path.exists(file):
        with open(file, "r") as f:
            try:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)
            except json.JSONDecodeError:
                return {}
    return {}

# Save data
def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# Password hashing
def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

# Verify passkey
def verify_passkey(passkey, stored_hash):
    decoded = base64.b64decode(stored_hash.encode())
    salt = decoded[:16]
    stored_key = decoded[16:]
    new_key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return new_key == stored_key

# Encrypt/decrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Load files
users = load_json(USER_FILE)
stored_data = load_json(DATA_FILE)

# UI
st.title("🔐 Secure Multi-User Data Vault")

menu = ["Home", "Signup", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Sign Up
if choice == "Signup":
    st.subheader("👤 Create Account")

    name = str(st.text_input("Enter your name: "))
    if len(name) >= 4:
            st.success("Name confirmed")
    else:
            st.warning("Please enter name atleast 4 letter")

    password = st.text_input("Enter password", type="password")
    if len(password) >= 8:
        st.success("Password confirmed")
    else:
        st.warning("Please enter password atleast 8 letter")

    if st.button("Sign Up"):
        if name in users:
            st.error("⚠️ User already exists.")
        if len(name) >= 4  and len(password) >= 8:
            hashed = hash_passkey(password)
            users[name] = {"password": hashed}
            save_json(USER_FILE, users)
            st.success("✅ Account created successfully!")
        else:
            st.error("Please enter vailed password or name")
        
            
# Login
elif choice == "Login":
    st.subheader("🔑 Login to your account")
    name = st.text_input("Please enter your name: ")
    password = st.text_input("Password", type="password")

    # Lockout mechanism
    if st.session_state.lockout_until and datetime.now() < st.session_state.lockout_until:
        remaining = (st.session_state.lockout_until - datetime.now()).seconds
        st.warning(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    if st.button("Login"):
        if name in users and verify_passkey(password, users[name]["password"]):
            st.session_state.user = name
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful!")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {attempts_left}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_until = datetime.now() + timedelta(seconds=10)
                st.warning("🚫 Too many failed attempts. Locked for 10 seconds.")
                st.stop()

# Store Data
elif choice == "Store Data":
    if not st.session_state.user:
        st.warning("⚠️ Please login first.")
        st.stop()

    st.subheader("💾 Store Your Encrypted Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)

            user = st.session_state.user
            if user not in stored_data:
                stored_data[user] = {}

            stored_data[user][encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            }
            save_json(DATA_FILE, stored_data)
            st.success("✅ Data encrypted and saved.")
        else:
            st.error("⚠️ Please enter both data and passkey.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.user:
        st.warning("⚠️ Please login first.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    user = st.session_state.user
    user_entries = stored_data.get(user, {})

    if not user_entries:
        st.info("ℹ️ No data found for your account.")
    else:
        selected_encrypted = st.selectbox("📄 Choose encrypted entry", list(user_entries.keys()))
        st.code(selected_encrypted)

        # Check for lockout
        if st.session_state.lockout_retrieve_until and datetime.now() < st.session_state.lockout_retrieve_until:
            remaining = (st.session_state.lockout_retrieve_until - datetime.now()).seconds
            st.warning(f"🔒 You are locked out. Try again in {remaining} seconds.")
            st.stop()

        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt"):
            stored_hash = user_entries[selected_encrypted]["passkey"]
            if verify_passkey(passkey, stored_hash):
                try:
                    decrypted = decrypt_data(selected_encrypted)
                    st.success("✅ Decrypted Successfully")
                    st.text_area("Decrypted Data", decrypted, height=150)
                    
                    st.session_state.failed_retrieve_attempts = 0
                    st.session_state.lockout_retrieve_until = None
                    st.session_state.post_lock_single_chance_used = False
                except:
                    st.error("⚠️ Decryption failed. Data may be corrupted.")
            else:
                st.session_state.failed_retrieve_attempts += 1

                # After lockout, allow only one chance
                if st.session_state.lockout_retrieve_until and not st.session_state.post_lock_single_chance_used:
                    st.session_state.post_lock_single_chance_used = True
                    st.error("❌ Incorrect passkey. Last chance used.")
                elif st.session_state.lockout_retrieve_until and st.session_state.post_lock_single_chance_used:
                    st.session_state.lockout_retrieve_until = datetime.now() + timedelta(minutes=2)
                    st.session_state.failed_retrieve_attempts = 0
                    st.session_state.post_lock_single_chance_used = False
                    st.warning("🔒 Locked again for 2 minutes due to failed retry.")
                    st.stop()
                elif st.session_state.failed_retrieve_attempts >= 3:
                    st.session_state.lockout_retrieve_until = datetime.now() + timedelta(minutes=2)
                    st.session_state.failed_retrieve_attempts = 0
                    st.session_state.post_lock_single_chance_used = False
                    st.warning("🔒 Too many failed attempts. Locked for 2 minutes.")
                    st.stop()
                else:
                    attempts_left = 3 - st.session_state.failed_retrieve_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")

# Logout
elif choice == "Logout":
    if not st.session_state.user:
        st.warning("⚠️ Please login first.")
    elif st.button("Logout"):
        st.session_state.user = None
        st.success("✅ Logged out successfully!")
        st.session_state.lockout_until = None




# Home
elif choice == "Home":
    st.subheader("🏠 Welcome to Secure Multi-User Vault")
    st.markdown("""
    - Sign up to create your secure vault 🔐  
    - Log in to store/retrieve encrypted data  
    - Each user can only access their own stored items  
    - Decryption is done using a passkey
    """)
