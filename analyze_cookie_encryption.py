#!/usr/bin/env python3
import json
import binascii
import os
import re
from datetime import datetime

# Path to our exported cookies JSON file
COOKIES_JSON_PATH = "/workspaces/JaiziahGreene/impacket/examples/exported_cookies.json"

def analyze_cookie_encryption_format():
    """Analyze the format of encrypted cookies to understand their structure"""
    if not os.path.exists(COOKIES_JSON_PATH):
        print(f"Error: Cookies JSON file not found at {COOKIES_JSON_PATH}")
        return
    
    try:
        with open(COOKIES_JSON_PATH, 'r') as f:
            cookies = json.load(f)
        
        print(f"Analyzing {len(cookies)} encrypted cookies...\n")
        
        # Pattern analysis
        prefixes = {}
        for cookie in cookies:
            if not cookie.get('encrypted_value_hex'):
                continue
                
            hex_value = cookie['encrypted_value_hex']
            
            # Extract prefix (first 6 bytes)
            if len(hex_value) >= 12:  # At least 6 bytes (12 hex chars)
                prefix = hex_value[:12]
                if prefix in prefixes:
                    prefixes[prefix].append(cookie['name'])
                else:
                    prefixes[prefix] = [cookie['name']]
            
            # Print detailed analysis of a few cookies
            if cookie['name'] in ['psaid', 'JSESSIONID', 'SimpleSAMLSessionID']:
                print(f"=== Analysis of {cookie['name']} on {cookie['host']} ===")
                print(f"Value (hex): {hex_value}")
                
                # Try to decode parts of the hex value
                try:
                    # Skip the first 3 bytes (prefix) and try to decode as UTF-8
                    byte_value = binascii.unhexlify(hex_value[6:])
                    print(f"Byte length: {len(byte_value)}")
                    
                    # Try to find ASCII strings in the data
                    ascii_pattern = re.compile(b'[ -~]{4,}')  # Find 4+ printable ASCII chars
                    ascii_matches = ascii_pattern.findall(byte_value)
                    if ascii_matches:
                        print("Possible ASCII strings found:")
                        for match in ascii_matches:
                            print(f"  - {match.decode('utf-8', errors='replace')}")
                    
                    # Extract other metadata
                    print(f"Created: {cookie['created']}")
                    print(f"Expires: {cookie['expires']}")
                    print(f"Path: {cookie['path']}")
                    print(f"Secure: {cookie['secure']}")
                    print(f"HttpOnly: {cookie['httponly']}")
                except Exception as e:
                    print(f"Error decoding: {e}")
                
                print()
        
        # Analyze common prefixes
        print("=== Common Prefixes Analysis ===")
        for prefix, names in prefixes.items():
            if len(names) > 1:
                print(f"Prefix: {prefix} used in {len(names)} cookies: {', '.join(names[:5])}{' and more...' if len(names) > 5 else ''}")
        
        # Check for patterns in first bytes
        print("\n=== First Bytes Analysis ===")
        first_bytes = {}
        for cookie in cookies:
            if not cookie.get('encrypted_value_hex'):
                continue
                
            hex_value = cookie['encrypted_value_hex']
            if len(hex_value) >= 6:
                first_3_bytes = hex_value[:6]
                if first_3_bytes in first_bytes:
                    first_bytes[first_3_bytes] += 1
                else:
                    first_bytes[first_3_bytes] = 1
        
        for first_3_bytes, count in first_bytes.items():
            print(f"First 3 bytes: {first_3_bytes} occurs in {count} cookies")
        
    except Exception as e:
        print(f"Error analyzing cookies: {e}")

def main():
    print("===== Chrome Cookie Encryption Format Analyzer =====")
    analyze_cookie_encryption_format()

if __name__ == "__main__":
    main()
