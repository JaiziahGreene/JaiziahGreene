#!/usr/bin/env python3
import os
import sqlite3
import json
import re
import sys
import shutil
from pathlib import Path
from datetime import datetime, timedelta

# Paths to Chrome data files
CHROME_PATH = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
DEFAULT_PROFILE = os.path.join(CHROME_PATH, "Default")
COOKIES_DB = os.path.join(DEFAULT_PROFILE, "Network", "Cookies")
LOCAL_STORAGE = os.path.join(DEFAULT_PROFILE, "Local Storage", "leveldb")
SESSION_STORAGE = os.path.join(DEFAULT_PROFILE, "Session Storage")

# Target domains we're interested in
TARGET_DOMAINS = [
    "sishrsb.ednet.ns.ca",
    "gnspes.ca",
    "everyone.ednet.ns.ca", 
    "saml.nspes.ca",
    "ednet.ns.ca",
    "nspes"
]

def copy_db_for_access(db_path, copy_path):
    """Create a copy of an SQLite database file to avoid locks"""
    try:
        shutil.copy2(db_path, copy_path)
        return True
    except Exception as e:
        print(f"Error copying database {db_path}: {e}")
        return False

def extract_cookies():
    """Extract auth-related cookies from Chrome"""
    temp_cookies_db = "/tmp/temp_cookies.db"
    
    if not os.path.exists(COOKIES_DB):
        print(f"Cookies database not found: {COOKIES_DB}")
        return []
    
    if not copy_db_for_access(COOKIES_DB, temp_cookies_db):
        return []
    
    cookies = []
    try:
        conn = sqlite3.connect(temp_cookies_db)
        cursor = conn.cursor()
        
        # SQLite query to extract cookies for our target domains
        for domain in TARGET_DOMAINS:
            cursor.execute(
                "SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc "
                "FROM cookies WHERE host_key LIKE ? OR host_key LIKE ?",
                (f"%{domain}%", f"%.{domain}%")
            )
            
            for row in cursor.fetchall():
                host_key, name, value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc = row
                
                # Focus on auth-related cookies
                auth_related_names = [
                    'auth', 'token', 'sess', 'sid', 'user', 'login', 'pass', 'jwt', 
                    'access', 'id', 'key', 'saml', 'sso', 'credential'
                ]
                
                # Check if the cookie name contains any auth-related keywords
                if any(keyword.lower() in name.lower() for keyword in auth_related_names) or len(value) > 30:
                    # Convert Chrome timestamp to readable date (microseconds since Jan 1, 1601)
                    chrome_epoch = datetime(1601, 1, 1)
                    if expires_utc:
                        expires_date = chrome_epoch + timedelta(microseconds=expires_utc)
                    else:
                        expires_date = None
                    
                    # Convert creation timestamp
                    creation_date = chrome_epoch + timedelta(microseconds=creation_utc)
                    
                    # Convert last access timestamp
                    last_access_date = chrome_epoch + timedelta(microseconds=last_access_utc)
                    
                    cookies.append({
                        'host': host_key,
                        'name': name,
                        'value': value,
                        'path': path,
                        'expires': str(expires_date) if expires_date else 'Session',
                        'secure': bool(is_secure),
                        'httponly': bool(is_httponly),
                        'created': str(creation_date),
                        'last_accessed': str(last_access_date)
                    })
        
        conn.close()
        os.remove(temp_cookies_db)
    except Exception as e:
        print(f"Error extracting cookies: {e}")
        try:
            conn.close()
        except:
            pass
        try:
            os.remove(temp_cookies_db)
        except:
            pass
    
    return cookies

def extract_local_storage():
    """Extract data from Local Storage"""
    if not os.path.exists(LOCAL_STORAGE):
        print(f"Local Storage directory not found: {LOCAL_STORAGE}")
        return []
    
    storage_data = []
    try:
        # Local Storage is stored in LevelDB format, which is more complex to parse directly
        # We'll look for text files that might contain authentication data
        for root, dirs, files in os.walk(LOCAL_STORAGE):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip log files and large files
                if file.endswith('.log') or os.path.getsize(file_path) > 1024*1024:
                    continue
                
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        
                        # Try to decode as text
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            
                            # Check if related to our target domains
                            if any(domain in text_content for domain in TARGET_DOMAINS):
                                # Look for authentication related data
                                auth_keywords = [
                                    'token', 'auth', 'login', 'user', 'password', 'session', 
                                    'credential', 'jwt', 'saml', 'sso'
                                ]
                                
                                if any(keyword in text_content.lower() for keyword in auth_keywords):
                                    storage_data.append({
                                        'file': file_path,
                                        'size': os.path.getsize(file_path),
                                        'preview': text_content[:500] + ('...' if len(text_content) > 500 else '')
                                    })
                        except:
                            # Binary file couldn't be decoded as text
                            pass
                            
                except Exception as e:
                    print(f"Error reading local storage file {file_path}: {e}")
    
    except Exception as e:
        print(f"Error extracting Local Storage data: {e}")
    
    return storage_data

def extract_session_storage():
    """Extract data from Session Storage"""
    if not os.path.exists(SESSION_STORAGE):
        print(f"Session Storage directory not found: {SESSION_STORAGE}")
        return []
    
    storage_data = []
    try:
        # Session Storage is also in LevelDB format
        for root, dirs, files in os.walk(SESSION_STORAGE):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip log files and large files
                if file.endswith('.log') or os.path.getsize(file_path) > 1024*1024:
                    continue
                
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        
                        # Try to decode as text
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            
                            # Check if related to our target domains
                            if any(domain in text_content for domain in TARGET_DOMAINS):
                                # Look for authentication related data
                                auth_keywords = [
                                    'token', 'auth', 'login', 'user', 'password', 'session', 
                                    'credential', 'jwt', 'saml', 'sso'
                                ]
                                
                                if any(keyword in text_content.lower() for keyword in auth_keywords):
                                    storage_data.append({
                                        'file': file_path,
                                        'size': os.path.getsize(file_path),
                                        'preview': text_content[:500] + ('...' if len(text_content) > 500 else '')
                                    })
                        except:
                            # Binary file couldn't be decoded as text
                            pass
                            
                except Exception as e:
                    print(f"Error reading session storage file {file_path}: {e}")
    
    except Exception as e:
        print(f"Error extracting Session Storage data: {e}")
    
    return storage_data

def extract_web_data():
    """Check the Web Data database for autofill information"""
    temp_web_data_db = "/tmp/temp_web_data.db"
    web_data_db = os.path.join(DEFAULT_PROFILE, "Web Data")
    
    if not os.path.exists(web_data_db):
        print(f"Web Data database not found: {web_data_db}")
        return {}
    
    if not copy_db_for_access(web_data_db, temp_web_data_db):
        return {}
    
    web_data = {
        'autofill': [],
        'keygen': []
    }
    
    try:
        conn = sqlite3.connect(temp_web_data_db)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        # Extract autofill data
        try:
            cursor.execute("SELECT name, value, date_created FROM autofill")
            for row in cursor.fetchall():
                web_data['autofill'].append({
                    'name': row['name'],
                    'value': row['value'],
                    'date_created': row['date_created']
                })
        except sqlite3.OperationalError:
            print("No autofill table found in Web Data")
        
        # Extract keygen data (might contain saved passwords hints)
        try:
            cursor.execute("SELECT url_hash, url, alternate_url, "
                           "username_element, username_value, "
                           "creation_time, date_synced, date_last_used "
                           "FROM keystore_data_for_keygen")
            for row in cursor.fetchall():
                web_data['keygen'].append({
                    'url': row['url'],
                    'alternate_url': row['alternate_url'],
                    'username_element': row['username_element'],
                    'username_value': row['username_value'],
                    'creation_time': row['creation_time']
                })
        except sqlite3.OperationalError:
            print("No keystore_data_for_keygen table found in Web Data")
        
        conn.close()
        os.remove(temp_web_data_db)
    except Exception as e:
        print(f"Error extracting Web Data: {e}")
        try:
            conn.close()
        except:
            pass
        try:
            os.remove(temp_web_data_db)
        except:
            pass
    
    return web_data

def main():
    print("===== Education Portal Authentication Data Extractor =====")
    
    # 1. Extract auth-related cookies
    print("\n[1] Extracting authentication cookies...")
    cookies = extract_cookies()
    
    if cookies:
        print(f"Found {len(cookies)} authentication-related cookies")
        print("\n----- Authentication Cookies -----")
        for i, cookie in enumerate(cookies):
            print(f"{i+1}. Domain: {cookie['host']}")
            print(f"   Name: {cookie['name']}")
            print(f"   Value: {cookie['value']}")
            print(f"   Path: {cookie['path']}")
            print(f"   Expires: {cookie['expires']}")
            print(f"   Secure: {cookie['secure']}")
            print(f"   HttpOnly: {cookie['httponly']}")
            print(f"   Created: {cookie['created']}")
            print(f"   Last Accessed: {cookie['last_accessed']}")
            print()
    else:
        print("No authentication-related cookies found.")
    
    # 2. Extract Local Storage data
    print("\n[2] Extracting Local Storage data...")
    local_storage_data = extract_local_storage()
    
    if local_storage_data:
        print(f"Found {len(local_storage_data)} Local Storage entries potentially containing auth data")
        print("\n----- Local Storage Authentication Data -----")
        for i, data in enumerate(local_storage_data):
            print(f"{i+1}. File: {data['file']}")
            print(f"   Size: {data['size']} bytes")
            print(f"   Preview: {data['preview'][:200]}...")
            print()
    else:
        print("No authentication-related Local Storage data found.")
    
    # 3. Extract Session Storage data
    print("\n[3] Extracting Session Storage data...")
    session_storage_data = extract_session_storage()
    
    if session_storage_data:
        print(f"Found {len(session_storage_data)} Session Storage entries potentially containing auth data")
        print("\n----- Session Storage Authentication Data -----")
        for i, data in enumerate(session_storage_data):
            print(f"{i+1}. File: {data['file']}")
            print(f"   Size: {data['size']} bytes")
            print(f"   Preview: {data['preview'][:200]}...")
            print()
    else:
        print("No authentication-related Session Storage data found.")
    
    # 4. Extract Web Data
    print("\n[4] Extracting Web Data autofill information...")
    web_data = extract_web_data()
    
    if web_data['autofill']:
        print(f"Found {len(web_data['autofill'])} autofill entries")
        print("\n----- Autofill Data -----")
        for i, data in enumerate(web_data['autofill']):
            print(f"{i+1}. Name: {data['name']}")
            print(f"   Value: {data['value']}")
            print(f"   Date Created: {data['date_created']}")
            print()
    else:
        print("No autofill data found.")
    
    if web_data['keygen']:
        print(f"Found {len(web_data['keygen'])} keygen entries (potential saved login hints)")
        print("\n----- Keygen Data -----")
        for i, data in enumerate(web_data['keygen']):
            print(f"{i+1}. URL: {data['url']}")
            print(f"   Alternate URL: {data['alternate_url']}")
            print(f"   Username Element: {data['username_element']}")
            print(f"   Username Value: {data['username_value']}")
            print(f"   Creation Time: {data['creation_time']}")
            print()
    else:
        print("No keygen data found.")
    
    # 5. Summarize findings
    print("\n===== Authentication Data Summary =====")
    auth_data_found = cookies or local_storage_data or session_storage_data or web_data['autofill'] or web_data['keygen']
    
    if auth_data_found:
        print("Potential authentication data found:")
        if cookies:
            print(f"- {len(cookies)} authentication-related cookies")
        if local_storage_data:
            print(f"- {len(local_storage_data)} Local Storage entries containing auth keywords")
        if session_storage_data:
            print(f"- {len(session_storage_data)} Session Storage entries containing auth keywords")
        if web_data['autofill']:
            print(f"- {len(web_data['autofill'])} autofill entries")
        if web_data['keygen']:
            print(f"- {len(web_data['keygen'])} keygen entries (potential saved login hints)")
    else:
        print("No authentication data found in Chrome profile.")

if __name__ == "__main__":
    main()
