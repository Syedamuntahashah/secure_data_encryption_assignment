import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ----------------------------
# 🌟 Secure Data Encryption System
# ----------------------------

# Generate or retrieve encryption key (session-safe)
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

# Persistent data & attempts via session_state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ----------------------------
# 🔑 Utility Functions
# ----------------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    for data in st.session_state.stored_data.values():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# ----------------------------
# 🎨 Streamlit UI
# ----------------------------

st.set_page_config(page_title="Secure Data Encryption", page_icon="🛡️")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigate", menu)

# ----------------------------
# 🏠 Home Page
# ----------------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.info("Use this app to **store & retrieve data securely** using encrypted keys. All data is kept in memory (no files or databases).")

# ----------------------------
# 📂 Store Data Page
# ----------------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    user_data = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Create a Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed_pass = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.warning("⚠️ Please enter both data and a passkey.")

# ----------------------------
# 🔍 Retrieve Data Page
# ----------------------------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    encrypted_input = st.text_area("Enter Encrypted Data:")
    passkey_input = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Decryption Successful!")
                st.write("**Decrypted Data:**")
                st.code(result, language="text")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Please reauthorize.")
                    st.session_state.redirect = "Login"
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Please provide both the encrypted text and passkey.")

# ----------------------------
# 🔐 Login Page
# ----------------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")

    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in successfully. You may now try again.")
            if st.session_state.get("redirect") == "Login":
                st.session_state.redirect = None
                st.experimental_rerun()
        else:
            st.error("❌ Wrong password! Access denied.")

