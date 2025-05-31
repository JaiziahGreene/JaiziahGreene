#!/usr/bin/env python3
"""
Chrome Data Extraction and Analysis Tool

This script combines multiple approaches to extract and analyze Chrome browser data
from the "Lil samson bro" user profile, with a focus on educational domains.

Features:
1. Extracts and analyzes both encrypted and plaintext cookie data
2. Identifies authentication-related cookies and their properties
3. Provides details about Chrome's encryption format
4. Outputs data in various formats for further analysis
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import binascii
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

# Configuration
CHROME_PATH = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
DEFAULT_PROFILE = os.path.join(CHROME_PATH, "Default")
LOCAL_STATE = os.path.join(CHROME_PATH, "Local State")
LOGIN_DATA = os.path.join(DEFAULT_PROFILE, "Login Data")
COOKIES_DB = os.path.join(DEFAULT_PROFILE, "Network", "Cookies")

# Target domains
TARGET_DOMAINS = [
    "sishrsb.ednet.ns.ca",
    "gnspes.ca",
    "everyone.ednet.ns.ca", 
    "saml.nspes.ca",
    "ednet.ns.ca",
    "nspes.ca"
]

# Output files
OUTPUT_DIR = "/workspaces/JaiziahGreene/chrome_extraction_results"
COOKIES_JSON = os.path.join(OUTPUT_DIR, "extracted_cookies.json")
COOKIES_RAW = os.path.join(OUTPUT_DIR, "raw_cookies.txt")
SUMMARY_REPORT = os.path.join(OUTPUT_DIR, "extraction_summary.md")

def setup_output_directory():
    """Create output directory if it doesn't exist"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

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
        
        # Decode but don't attempt to decrypt (requires DPAPI)
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        
        # Check for 'DPAPI' prefix (5 bytes)
        if encrypted_key_bytes[:5] == b'DPAPI':
            print("Encryption key uses Windows DPAPI (cannot be decrypted in this environment)")
            
        return {
            "base64": encrypted_key,
            "raw_bytes": encrypted_key_bytes,
            "has_dpapi_prefix": encrypted_key_bytes[:5] == b'DPAPI'
        }
    except Exception as e:
        print(f"Error getting encryption key: {e}")
        return None

def extract_cookies():
    """Extract cookies from Chrome's Cookies database"""
    if not os.path.exists(COOKIES_DB):
        print(f"Cookie database not found: {COOKIES_DB}")
        return []
    
    temp_db, temp_dir = copy_db_for_access(COOKIES_DB)
    if not temp_db:
        return []
    
    cookies = []
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # For each target domain, extract all cookies
        for domain in TARGET_DOMAINS:
            cursor.execute(
                "SELECT host_key, name, value, encrypted_value, path, expires_utc, "
                "is_secure, is_httponly, creation_utc, last_access_utc, has_expires "
                "FROM cookies WHERE host_key LIKE ? OR host_key LIKE ?",
                (f"%{domain}%", f"%.{domain}%")
            )
            
            for row in cursor.fetchall():
                host_key, name, value, encrypted_value, path, expires_utc, is_secure, \
                is_httponly, creation_utc, last_access_utc, has_expires = row
                
                # Convert Chrome timestamps
                chrome_epoch = datetime(1601, 1, 1)
                
                if expires_utc and has_expires:
                    expires_date = chrome_epoch + timedelta(microseconds=expires_utc)
                else:
                    expires_date = None
                
                creation_date = chrome_epoch + timedelta(microseconds=creation_utc)
                last_access_date = chrome_epoch + timedelta(microseconds=last_access_utc)
                
                # Store both the value and encrypted_value
                cookie = {
                    'domain': host_key,
                    'name': name,
                    'value': value if value else "",
                    'encrypted_value': binascii.hexlify(encrypted_value).decode('utf-8') if encrypted_value else "",
                    'path': path,
                    'expires': str(expires_date) if expires_date else 'Session',
                    'secure': bool(is_secure),
                    'httponly': bool(is_httponly),
                    'created': str(creation_date),
                    'last_accessed': str(last_access_date)
                }
                
                cookies.append(cookie)
        
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

def analyze_chrome_encryption_format(cookies):
    """Analyze the encryption format used by Chrome"""
    prefixes = {}
    first_bytes = {}
    
    for cookie in cookies:
        encrypted_value = cookie.get('encrypted_value', '')
        if not encrypted_value:
            continue
        
        # Analyze the first few bytes for patterns
        if len(encrypted_value) >= 6:
            prefix = encrypted_value[:6].lower()
            if prefix in prefixes:
                prefixes[prefix] += 1
            else:
                prefixes[prefix] = 1
    
    results = {
        'total_cookies': len(cookies),
        'encrypted_cookies': sum(1 for c in cookies if c.get('encrypted_value')),
        'common_prefixes': prefixes
    }
    
    # Try to determine the encryption version
    if '763230' in prefixes:
        results['encryption_version'] = 'v10 (Chrome 80+)'
        results['encryption_algorithm'] = 'AES-256-GCM'
        results['notes'] = '763230 is hex for v20 - indicates v10 encryption scheme'
    
    return results

def write_cookies_to_json(cookies, output_file):
    """Write cookies to a JSON file"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(cookies, f, indent=2)
    print(f"Exported cookies to JSON: {output_file}")

def write_raw_cookies(cookies, output_file):
    """Write cookies in a raw text format with domain|name|encrypted_value"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("// domain|name|encrypted_value_hex\n")
        for cookie in cookies:
            if cookie.get('encrypted_value'):
                f.write(f"{cookie['domain']}|{cookie['name']}|{cookie['encrypted_value']}\n")
    print(f"Exported raw cookies: {output_file}")

def write_summary_report(cookies, encryption_analysis, key_info, output_file):
    """Generate a summary report of the extraction"""
    lines = []
    
    # Header
    lines.append("# Chrome Data Extraction Summary")
    lines.append(f"\nExtraction date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Stats
    lines.append("\n## Extraction Statistics")
    lines.append(f"- Total cookies found: {len(cookies)}")
    lines.append(f"- Encrypted cookies: {encryption_analysis['encrypted_cookies']}")
    
    # Encryption details
    lines.append("\n## Chrome Encryption Details")
    if key_info:
        lines.append("- ✅ Encryption key found in Local State file")
        lines.append(f"- Encrypted with: Windows DPAPI (Data Protection API)")
        if 'encryption_version' in encryption_analysis:
            lines.append(f"- Chrome encryption version: {encryption_analysis['encryption_version']}")
            lines.append(f"- Encryption algorithm: {encryption_analysis['encryption_algorithm']}")
    else:
        lines.append("- ❌ Could not retrieve encryption key")
    
    # Domain breakdown
    lines.append("\n## Educational Domains")
    domain_counts = {}
    for cookie in cookies:
        domain = cookie['domain']
        if domain in domain_counts:
            domain_counts[domain] += 1
        else:
            domain_counts[domain] = 1
    
    for domain, count in domain_counts.items():
        lines.append(f"- {domain}: {count} cookies")
    
    # Authentication cookies
    lines.append("\n## Key Authentication Cookies")
    auth_cookies = ["JSESSIONID", "psaid", "SimpleSAMLSessionID", "ESimpleSAMLSessionID"]
    
    for cookie in cookies:
        if cookie['name'] in auth_cookies:
            lines.append(f"- **{cookie['name']}** on *{cookie['domain']}*")
            lines.append(f"  - Path: {cookie['path']}")
            lines.append(f"  - Secure: {cookie['secure']}")
            lines.append(f"  - HttpOnly: {cookie['httponly']}")
            lines.append(f"  - Created: {cookie['created']}")
            lines.append(f"  - Expires: {cookie['expires']}")
    
    # Next steps
    lines.append("\n## Limitations and Next Steps")
    lines.append("1. The cookies are encrypted using Chrome's encryption scheme")
    lines.append("2. Full decryption requires the Windows user account that created them")
    lines.append("3. The encrypted cookies may still be useful for analysis or authentication pattern study")
    lines.append("4. To use these cookies for authentication, they would need to be decrypted")
    lines.append("   or the original Windows environment would need to be accessed")
    
    # Write the report
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    
    print(f"Generated summary report: {output_file}")

def main():
    print("===== Chrome Data Extraction and Analysis Tool =====")
    
    # Create output directory
    setup_output_directory()
    
    # Step 1: Get Chrome encryption key
    print("\n[1] Retrieving Chrome encryption key...")
    key_info = get_chrome_key()
    
    # Step 2: Extract cookies
    print("\n[2] Extracting cookies from Chrome profile...")
    cookies = extract_cookies()
    
    if cookies:
        print(f"Found {len(cookies)} cookies for educational domains")
        
        # Step 3: Analyze encryption format
        print("\n[3] Analyzing Chrome encryption format...")
        encryption_analysis = analyze_chrome_encryption_format(cookies)
        
        # Step 4: Export cookies and generate report
        print("\n[4] Exporting data and generating report...")
        write_cookies_to_json(cookies, COOKIES_JSON)
        write_raw_cookies(cookies, COOKIES_RAW)
        write_summary_report(cookies, encryption_analysis, key_info, SUMMARY_REPORT)
        
        print("\nExtraction complete. Results saved to:")
        print(f"- JSON cookies: {COOKIES_JSON}")
        print(f"- Raw cookies: {COOKIES_RAW}")
        print(f"- Summary report: {SUMMARY_REPORT}")
    else:
        print("No cookies found for the target educational domains")

if __name__ == "__main__":
    main()
