import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Session state initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Utility functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_data(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# Sidebar Navigation
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("Welcome to the 🔐 Secure Data Encryption System")
    st.markdown("This application allows you to securely store and retrieve sensitive data using encryption.")

# Register
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠ Username already exists. Please choose a different one.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Please enter both username and password.")

# Login
elif choice == "Login":
    st.subheader("🔑 Login")

    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f"⏱ Too many failed attempts. Please wait {remaining_time} seconds before trying again.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. You have {remaining} attempts left.")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error(f"🛑 Too many failed attempts. Please wait {LOCKOUT_DURATION} seconds before trying again.")
                st.stop()

# Store Data
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("💾 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt and store")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.error("Please enter both data and passkey.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("🔑 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.warning("⚠ No data found for the user.")
        else:
            st.write("🔐 Encrypted Data:")
            for item in user_data:
                st.code(item, language="text")

            encrypt_input = st.text_area("Enter encrypted data to decrypt")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypt_input, passkey)
                if result:
                    st.success(f"✅ Decrypted Data: {result}")
                else:
                    st.error("❌ Decryption failed. Please check the encrypted data and passkey.")

# Logout
elif choice == "Logout":
    if st.session_state.authenticated_user:
        st.session_state.authenticated_user = None
        st.success("✅ You have been logged out.")
    else:
        st.info("ℹ️ You are not logged in.")
   
     
