#!/usr/bin/env python3
import json
import os
import sys
import binascii
from datetime import datetime, timedelta

# Output file path
OUTPUT_FILE = "chrome_data_analysis_report.md"

# Key files and data sources
COOKIES_JSON_PATH = "/workspaces/JaiziahGreene/impacket/examples/exported_cookies.json"
RAW_COOKIES_PATH = "/workspaces/JaiziahGreene/raw_cookies.txt"
LOCAL_STATE_PATH = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data/Local State"

def format_timestamp(microseconds_since_1601):
    """Convert Chrome's timestamp format to a readable date"""
    if not microseconds_since_1601:
        return "N/A"
    
    chrome_epoch = datetime(1601, 1, 1)
    date = chrome_epoch + timedelta(microseconds=microseconds_since_1601)
    return date.strftime("%Y-%m-%d %H:%M:%S")

def analyze_chrome_encryption():
    """Analyze Chrome's encryption format based on our data"""
    results = {
        "key_found": False,
        "key_b64": "",
        "cookies_count": 0,
        "encrypted_cookies": {},
        "encryption_prefix": "",
        "cookie_prefixes": set()
    }
    
    # Check if we have the Local State file (contains the encrypted key)
    if os.path.exists(LOCAL_STATE_PATH):
        results["key_found"] = True
        try:
            with open(LOCAL_STATE_PATH, 'r') as f:
                local_state = json.load(f)
                if 'os_crypt' in local_state and 'encrypted_key' in local_state['os_crypt']:
                    results["key_b64"] = local_state['os_crypt']['encrypted_key']
        except Exception as e:
            print(f"Error reading Local State file: {e}")
    
    # Parse the raw cookies file to examine encryption patterns
    if os.path.exists(RAW_COOKIES_PATH):
        try:
            with open(RAW_COOKIES_PATH, 'r') as f:
                raw_cookies = f.readlines()
                
            results["cookies_count"] = len(raw_cookies)
            
            for line in raw_cookies:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                
                parts = line.split('|')
                if len(parts) >= 3:
                    domain = parts[0]
                    name = parts[1]
                    encrypted_hex = parts[2]
                    
                    if encrypted_hex and len(encrypted_hex) >= 6:
                        # Store the first 3 bytes (6 chars) as a prefix pattern
                        prefix = encrypted_hex[:6].lower()
                        results["cookie_prefixes"].add(prefix)
                        
                        # Keep track of all cookie values
                        if domain not in results["encrypted_cookies"]:
                            results["encrypted_cookies"][domain] = {}
                        
                        results["encrypted_cookies"][domain][name] = encrypted_hex
            
            # If all cookies have the same prefix (likely a version identifier)
            if len(results["cookie_prefixes"]) == 1:
                results["encryption_prefix"] = next(iter(results["cookie_prefixes"]))
        except Exception as e:
            print(f"Error analyzing raw cookies: {e}")
    
    # Check exported cookies JSON for more details
    if os.path.exists(COOKIES_JSON_PATH):
        try:
            with open(COOKIES_JSON_PATH, 'r') as f:
                cookies_json = json.load(f)
                
            results["cookies_count"] = len(cookies_json)
        except Exception as e:
            print(f"Error analyzing cookies JSON: {e}")
    
    return results

def generate_report(analysis):
    """Generate a comprehensive report of our findings"""
    report = []
    
    # Title and introduction
    report.append("# Chrome Browser Data Analysis Report")
    report.append("\n## Overview")
    report.append("This report presents findings from the analysis of Chrome browser data extracted from the \"Lil samson bro\" user profile.")
    report.append("The focus was on extracting encrypted credentials, cookies, and authentication data from educational websites.")
    
    # Encryption key analysis
    report.append("\n## Chrome Encryption Key Analysis")
    if analysis["key_found"]:
        report.append("- ✅ Successfully extracted the encrypted key from Chrome's Local State file")
        report.append("- The key is encrypted using Windows DPAPI (Data Protection API)")
        
        # Include the base64 encoded key
        if analysis["key_b64"]:
            report.append(f"- Encrypted key (base64): `{analysis['key_b64']}`")
        
        report.append("- **Limitation**: This key can only be decrypted on the original Windows system")
        report.append("  with access to the user's account that created the key")
    else:
        report.append("- ❌ Could not find or access Chrome's Local State file")
    
    # Cookie analysis
    report.append("\n## Cookie Analysis")
    if analysis["cookies_count"] > 0:
        report.append(f"- Found {analysis['cookies_count']} encrypted cookies")
        
        # Pattern analysis
        if analysis["encryption_prefix"]:
            report.append(f"- All cookies share the same encryption prefix: `{analysis['encryption_prefix']}`")
            report.append("  This suggests Chrome is using consistent encryption across all cookies")
        
        # Domains
        if analysis["encrypted_cookies"]:
            report.append("\n### Educational Domains Found")
            for domain in analysis["encrypted_cookies"].keys():
                report.append(f"- {domain}")
            
            # Highlight key authentication cookies
            report.append("\n### Key Authentication Cookies")
            auth_cookies = ["JSESSIONID", "psaid", "SimpleSAMLSessionID", "ESimpleSAMLSessionID"]
            
            for domain in analysis["encrypted_cookies"]:
                for cookie_name in analysis["encrypted_cookies"][domain]:
                    if cookie_name in auth_cookies:
                        hex_value = analysis["encrypted_cookies"][domain][cookie_name]
                        report.append(f"- **{cookie_name}** on *{domain}*")
                        report.append(f"  - Encrypted value (hex): `{hex_value}`")
                        report.append(f"  - Length: {len(hex_value)//2} bytes")
    else:
        report.append("- ❌ No cookies found or could not access cookie data")
    
    # Chrome version details
    report.append("\n## Chrome Encryption Format")
    report.append("Chrome uses AES-256-GCM for cookie and password encryption in recent versions:")
    report.append("1. The master key is stored in the Local State file (encrypted with DPAPI)")
    report.append("2. This master key is used to decrypt the individual cookies and passwords")
    report.append("3. The encryption format is: `v10` + encrypted_data + nonce + tag")
    
    if analysis["encryption_prefix"] == "763230":
        report.append("\nThe encryption prefix `763230` is hexadecimal for the ASCII characters `v20`,")
        report.append("indicating Chrome is using version 10 (v10) of its encryption scheme.")
    
    # Authentication system analysis
    report.append("\n## Educational Authentication System Analysis")
    report.append("Based on the cookie names and domains, we can identify the authentication systems in use:")
    report.append("1. **SimpleSAMLphp** - An open-source SAML 2.0 authentication system")
    report.append("   - Used by `saml.nspes.ca` and `everyone.ednet.ns.ca`")
    report.append("   - Cookie: `SimpleSAMLSessionID` and `ESimpleSAMLSessionID`")
    report.append("\n2. **Java-based Portal** - Likely PowerSchool or similar education management system")
    report.append("   - Used by `sishrsb.ednet.ns.ca`")
    report.append("   - Cookies: `JSESSIONID` and `psaid` (PowerSchool ID)")
    
    # Decryption challenges
    report.append("\n## Decryption Challenges")
    report.append("The Chrome data is encrypted using a system that requires:")
    report.append("1. The encrypted key from the Local State file (which we have)")
    report.append("2. Decryption of that key using Windows DPAPI (which requires the original Windows user account)")
    report.append("3. Using the decrypted key to decrypt the cookies/passwords")
    report.append("\nWithout access to the Windows user account, direct decryption in this environment is not possible.")
    
    # Authentication flow
    report.append("\n## Authentication Flow")
    report.append("The authentication flow for these educational systems appears to be:")
    report.append("1. User visits a service (e.g., `gnspes.ca` or `sishrsb.ednet.ns.ca`)")
    report.append("2. Redirect to the SAML authentication service at `saml.nspes.ca`")
    report.append("3. After authentication, the user receives cookies for all related domains")
    report.append("4. The session is maintained across educational services using these cookies")
    
    # Conclusions
    report.append("\n## Conclusions")
    report.append("1. We have successfully extracted encrypted cookies from the Chrome profile")
    report.append("2. The cookies represent active sessions on Nova Scotia educational systems")
    report.append("3. Complete decryption would require access to the original Windows system")
    report.append("4. The authentication flow and cookie patterns provide insight into how the")
    report.append("   educational systems manage authentication and sessions")
    
    # Write the report
    with open(OUTPUT_FILE, 'w') as f:
        f.write("\n".join(report))
    
    print(f"Report generated: {OUTPUT_FILE}")

def main():
    print("===== Chrome Data Comprehensive Analysis =====")
    print("Analyzing Chrome encryption and cookie patterns...")
    
    analysis = analyze_chrome_encryption()
    
    print(f"Found {analysis['cookies_count']} cookies")
    print(f"Encryption prefix identified: {analysis['encryption_prefix']}")
    
    print("\nGenerating comprehensive report...")
    generate_report(analysis)

if __name__ == "__main__":
    main()
