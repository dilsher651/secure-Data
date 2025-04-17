
import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os
import json
from pathlib import Path
import time
from datetime import datetime
import base64

# ===========================================
# IMPORTANT: Make sure cryptography is installed
# Run: pip install cryptography
# And include in requirements.txt for Streamlit Cloud:
# cryptography>=3.0
# ===========================================

# Custom CSS for modern styling
st.markdown("""
<style>
    .main {
        background-color: #f8f9fa;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        background-color: #ffffff;
        border: 1px solid #ced4da;
        border-radius: 8px;
    }
    .stButton>button {
        background-color: #4e73df;
        color: white;
        border-radius: 8px;
        border: none;
        padding: 10px 24px;
        font-weight: 500;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        background-color: #2e59d9;
        transform: translateY(-2px);
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    .error-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    .card {
        background-color: white;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        padding: 20px;
        margin-bottom: 20px;
    }
    .sidebar .sidebar-content {
        background-color: #4e73df;
        color: white;
    }
    h1, h2, h3 {
        color: #2e59d9;
    }
</style>
""", unsafe_allow_html=True)

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
DATA_FILE = "secure_data.json"
KEY_FILE = "encryption.key"
USERS_FILE = "users.json"

# Initialize required files
for f in [DATA_FILE, KEY_FILE, USERS_FILE]:
    Path(f).touch(exist_ok=True)

# Initialize or load encryption key
def get_encryption_key():
    try:
        if Path(KEY_FILE).exists():
            with open(KEY_FILE, "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(key)
            return key
    except Exception as e:
        st.error(f"Key initialization failed: {str(e)}")
        raise

# Initialize or load data
def load_json_file(filename, default={}):
    try:
        if Path(filename).exists():
            with open(filename, "r") as f:
                return json.load(f)
    except Exception as e:
        st.markdown(f'<div class="error-box">Error loading data: {str(e)}</div>', unsafe_allow_html=True)
    return default

def save_json_file(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        st.markdown(f'<div class="error-box">Error saving data: {str(e)}</div>', unsafe_allow_html=True)

# Security functions
def hash_password(password, salt=None):
    salt = salt or os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        100000
    )
    return f"{salt}${hashed.hex()}"

def verify_password(password, stored_hash):
    if not stored_hash or '$' not in stored_hash:
        return False
    salt, _ = stored_hash.split('$')
    new_hash = hash_password(password, salt)
    return new_hash == stored_hash

# User management
def authenticate(username, password):
    users = load_json_file(USERS_FILE)
    if username in users and verify_password(password, users[username]['password']):
        return True
    return False

def create_user(username, password):
    users = load_json_file(USERS_FILE)
    if username in users:
        return False
    users[username] = {
        'password': hash_password(password),
        'created_at': datetime.now().isoformat()
    }
    save_json_file(USERS_FILE, users)
    return True

# Initialize
try:
    KEY = get_encryption_key()
    cipher = Fernet(KEY)
except Exception as e:
    st.error(f"CRITICAL: Encryption setup failed - {str(e)}")
    st.stop()

stored_data = load_json_file(DATA_FILE)
failed_attempts = load_json_file("attempts.json", default={})
users = load_json_file(USERS_FILE)

# Session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'lockout' not in st.session_state:
    st.session_state.lockout = {}

# Modern UI with colorful elements
st.title("🔐 SecureVault Pro")
st.markdown("---")

# Authentication check
if not st.session_state.authenticated:
    with st.sidebar:
        st.title("🔑 Authentication")
        menu = st.radio("Navigation", ["Login", "Register"], label_visibility="collapsed")
    
    if menu == "Login":
        with st.container():
            st.header("Welcome Back!")
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                
                if st.form_submit_button("Login", use_container_width=True):
                    if username in st.session_state.lockout:
                        if time.time() < st.session_state.lockout[username]:
                            remaining = int(st.session_state.lockout[username] - time.time())
                            st.error(f"🔒 Account locked. Try again in {remaining} seconds.")
                        else:
                            del st.session_state.lockout[username]
                    
                    if authenticate(username, password):
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.rerun()
                    else:
                        if username in failed_attempts:
                            failed_attempts[username] += 1
                        else:
                            failed_attempts[username] = 1
                        
                        save_json_file("attempts.json", failed_attempts)
                        
                        if failed_attempts[username] >= MAX_ATTEMPTS:
                            st.session_state.lockout[username] = time.time() + LOCKOUT_TIME
                            st.error("⚠️ Too many failed attempts. Account locked for 5 minutes.")
                        else:
                            st.error(f"❌ Invalid credentials. Attempts remaining: {MAX_ATTEMPTS - failed_attempts[username]}")
    
    else:
        with st.container():
            st.header("Create New Account")
            with st.form("register_form"):
                new_username = st.text_input("Choose Username", placeholder="Enter a unique username")
                new_password = st.text_input("Choose Password", type="password", placeholder="Create a strong password")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter your password")
                
                if st.form_submit_button("Register", use_container_width=True):
                    if new_password == confirm_password:
                        if create_user(new_username, new_password):
                            st.success("🎉 Account created successfully! Please login.")
                        else:
                            st.error("Username already exists.")
                    else:
                        st.error("Passwords don't match.")
    
    st.stop()

# Main app (authenticated)
with st.sidebar:
    st.title(f"👋 {st.session_state.username}")
    menu = st.radio("Menu", ["Dashboard", "Store Data", "Retrieve Data", "My Vault", "Logout"])

if menu == "Dashboard":
    st.header("📊 Your Secure Dashboard")
    with st.container():
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Stored Items", len(stored_data.get(st.session_state.username, [])))
        with col2:
            st.metric("Security Level", "Military Grade")
        
        st.markdown("---")
        st.subheader("Quick Actions")
        st.button("➕ Store New Data", key="quick_store")
        st.button("🔍 Retrieve Data", key="quick_retrieve")
        
        st.markdown("---")
        st.subheader("Security Tips")
        st.info("💡 Always use strong, unique passkeys for each stored item")
        st.info("💡 Never share your encrypted data and passkey together")

elif menu == "Store Data":
    st.header("📥 Store Data Securely")
    with st.container():
        with st.form("store_form"):
            user_data = st.text_area("Your Data", placeholder="Enter the sensitive data you want to secure", height=150)
            passkey = st.text_input("Encryption Passkey", type="password", placeholder="Create a strong passkey for this data")
            identifier = st.text_input("Friendly Name (Optional)", placeholder="e.g. 'Bank Credentials'")
            
            if st.form_submit_button("🔒 Encrypt & Save", use_container_width=True):
                if user_data and passkey:
                    if identifier:
                        existing_ids = [d.get('identifier') for d in stored_data.get(st.session_state.username, [])]
                        if identifier in existing_ids:
                            st.error("This friendly name already exists. Please choose a different one.")
                        else:
                            data_cipher = Fernet(Fernet.generate_key())
                            encrypted_text = data_cipher.encrypt(user_data.encode()).decode()
                            
                            entry = {
                                "username": st.session_state.username,
                                "encrypted_text": encrypted_text,
                                "passkey_hash": hash_password(passkey),
                                "identifier": identifier,
                                "created_at": datetime.now().isoformat(),
                                "cipher_key": base64.urlsafe_b64encode(data_cipher._signing_key).decode('utf-8')
                            }
                            
                            if st.session_state.username not in stored_data:
                                stored_data[st.session_state.username] = []
                            
                            stored_data[st.session_state.username].append(entry)
                            save_json_file(DATA_FILE, stored_data)
                            
                            st.success("✅ Data encrypted and stored securely!")
                            st.code(f"Encrypted Reference:\n{encrypted_text[:50]}...")
                            st.warning("⚠️ Save this reference and your passkey - both are needed for retrieval")
                else:
                    st.error("Please provide both data and passkey")

elif menu == "Retrieve Data":
    st.header("📤 Retrieve Your Data")
    with st.container():
        user_data = stored_data.get(st.session_state.username, [])
        encrypted_to_data = {d['encrypted_text']: d for d in user_data}
        id_to_data = {d['identifier']: d for d in user_data if d.get('identifier')}
        
        with st.form("retrieve_form"):
            if id_to_data:
                selected_id = st.selectbox("Select by Friendly Name", [""] + list(id_to_data.keys()))
            else:
                selected_id = None
            
            encrypted_text = st.text_area(
                "Encrypted Data Reference",
                value=id_to_data[selected_id]['encrypted_text'] if selected_id and selected_id in id_to_data else "",
                placeholder="Paste your encrypted data reference here"
            )
            
            passkey = st.text_input("Decryption Passkey", type="password", placeholder="Enter the passkey for this data")
            
            if st.form_submit_button("🔓 Decrypt Data", use_container_width=True):
                if not encrypted_text or not passkey:
                    st.error("Please provide both encrypted data and passkey")
                else:
                    entry = None
                    if encrypted_text in encrypted_to_data:
                        entry = encrypted_to_data[encrypted_text]
                    elif selected_id and selected_id in id_to_data:
                        entry = id_to_data[selected_id]
                    
                    if not entry:
                        st.error("No matching data found. Please check your reference or friendly name.")
                    else:
                        attempt_key = f"{st.session_state.username}_{entry['encrypted_text']}"
                        if attempt_key in st.session_state.lockout:
                            if time.time() < st.session_state.lockout[attempt_key]:
                                remaining = int(st.session_state.lockout[attempt_key] - time.time())
                                st.error(f"🔒 Too many failed attempts! Try again in {remaining} seconds.")
                            else:
                                del st.session_state.lockout[attempt_key]
                        
                        if verify_password(passkey, entry['passkey_hash']):
                            try:
                                cipher_key = base64.urlsafe_b64decode(entry['cipher_key'])
                                data_cipher = Fernet(cipher_key)
                                decrypted_text = data_cipher.decrypt(entry['encrypted_text'].encode()).decode()
                                st.success("✅ Decryption successful!")
                                st.text_area("Your Decrypted Data", value=decrypted_text, height=200)
                            except Exception as e:
                                st.error(f"Decryption failed: {str(e)}")
                        else:
                            if attempt_key in failed_attempts:
                                failed_attempts[attempt_key] += 1
                            else:
                                failed_attempts[attempt_key] = 1
                            
                            save_json_file("attempts.json", failed_attempts)
                            
                            if failed_attempts[attempt_key] >= MAX_ATTEMPTS:
                                st.session_state.lockout[attempt_key] = time.time() + LOCKOUT_TIME
                                st.error("🔒 Too many failed attempts! This data is locked for 5 minutes.")
                            else:
                                st.error(f"❌ Incorrect passkey! Attempts remaining: {MAX_ATTEMPTS - failed_attempts[attempt_key]}")

elif menu == "My Vault":
    st.header("🗄️ Your Secure Vault")
    with st.container():
        user_data = stored_data.get(st.session_state.username, [])
        
        if not user_data:
            st.info("Your vault is empty. Store some data to get started!")
        else:
            st.subheader(f"Your Stored Items ({len(user_data)})")
            for i, item in enumerate(user_data, 1):
                with st.expander(f"🔐 {item.get('identifier', 'Unnamed Item')}"):
                    col1, col2 = st.columns([3,1])
                    with col1:
                        st.write(f"📅 Created: {item['created_at']}")
                        st.code(f"Reference: {item['encrypted_text'][:50]}...")
                    with col2:
                        if st.button("📋 Copy", key=f"copy_{i}"):
                            st.session_state.clipboard = item['encrypted_text']
                            st.success("Copied to clipboard!")

elif menu == "Logout":
    st.session_state.authenticated = False
    st.session_state.username = None
    st.success("You have been logged out successfully.")
    time.sleep(1)
    st.rerun()