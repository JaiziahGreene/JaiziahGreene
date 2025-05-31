#!/usr/bin/env python3
"""
This script compares the hash values from the mimikatz dump files with those in the output files
to identify data integrity issues.
"""

import re
import os
from collections import defaultdict

def extract_hash_from_mimikatz(filename):
    """Extract NTLM and LM hashes from mimikatz dump files."""
    users_data = defaultdict(dict)
    
    try:
        # Try different encodings
        for encoding in ['utf-8', 'utf-16-le', 'latin-1']:
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        # Split by RID sections
        sections = re.split(r'RID\s+:\s+[0-9a-fA-F]+\s+\(\d+\)', content)
        
        # Process each section
        for section in sections[1:]:
            user_match = re.search(r'User\s+:\s+([^\r\n]+)', section)
            if not user_match:
                continue
            
            username = user_match.group(1).strip()
            
            # Extract NTLM hash
            ntlm_match = re.search(r'Hash\s+NTLM(?:\s+)?:\s+([0-9a-fA-F]{32})', section)
            ntlm_hash = ntlm_match.group(1).lower() if ntlm_match else ""
            
            # Extract LM hash
            lm_match = re.search(r'Hash\s+LM\s+:\s+([0-9a-fA-F]{32})', section)
            lm_hash = lm_match.group(1).lower() if lm_match else ""
            
            if ntlm_hash or lm_hash:
                users_data[username]['ntlm'] = ntlm_hash
                users_data[username]['lm'] = lm_hash
                users_data[username]['source'] = filename
    
    except Exception as e:
        print(f"Error processing {filename}: {e}")
    
    return users_data

def read_fixed_data(filename):
    """Read hash data from the fixed file."""
    users_data = defaultdict(dict)
    
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            parts = line.split(':')
            if len(parts) >= 3:
                username = parts[0]
                password = parts[1]
                ntlm = parts[2].lower() if parts[2] else ""
                lm = parts[3].lower() if len(parts) >= 4 and parts[3] else ""
                
                users_data[username]['ntlm'] = ntlm
                users_data[username]['lm'] = lm
                if password:
                    users_data[username]['password'] = password
    
    return users_data

# Main processing
mimikatz_files = [
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/mimikatz PC 2.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 3 Dump.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 4 Dump.txt"
]

# Extract from mimikatz dumps
all_mimikatz_data = defaultdict(dict)
for file in mimikatz_files:
    file_data = extract_hash_from_mimikatz(file)
    for username, data in file_data.items():
        if username in all_mimikatz_data and 'ntlm' in all_mimikatz_data[username]:
            if all_mimikatz_data[username]['ntlm'] != data['ntlm']:
                print(f"WARNING: {username} has different NTLM hashes in different dumps!")
                print(f"  {all_mimikatz_data[username]['source']}: {all_mimikatz_data[username]['ntlm']}")
                print(f"  {data['source']}: {data['ntlm']}")
        else:
            all_mimikatz_data[username] = data

# Read from fixed data
fixed_data = read_fixed_data("/workspaces/JaiziahGreene/complete_user_hash_data_fixed.txt")
original_data = read_fixed_data("/workspaces/JaiziahGreene/complete_user_hash_data.txt")

# Compare and identify issues
print("\n=== Hash Integrity Issues ===\n")
issues_found = 0

# Check users in fixed_data against mimikatz
for username, data in fixed_data.items():
    if username in all_mimikatz_data:
        mdata = all_mimikatz_data[username]
        
        # Compare NTLM
        if 'ntlm' in data and 'ntlm' in mdata and data['ntlm'] and mdata['ntlm'] and data['ntlm'] != mdata['ntlm']:
            issues_found += 1
            print(f"{issues_found}. {username} has wrong NTLM hash:")
            print(f"   Fixed data: {data['ntlm']}")
            print(f"   Mimikatz:   {mdata['ntlm']}")
            print(f"   Source: {mdata['source']}")
        
        # LM hash issues - extra LMs not in dumps or wrong values
        if 'lm' in data and data['lm']:
            if 'lm' not in mdata or not mdata['lm']:
                issues_found += 1
                print(f"{issues_found}. {username} has LM hash in fixed data but not in mimikatz:")
                print(f"   Fixed data: {data['lm']}")
                print(f"   Source: {mdata['source']}")
            elif data['lm'] != mdata['lm']:
                issues_found += 1
                print(f"{issues_found}. {username} has wrong LM hash:")
                print(f"   Fixed data: {data['lm']}")
                print(f"   Mimikatz:   {mdata['lm']}")
                print(f"   Source: {mdata['source']}")

# Check for missing strong password users (NTLM only)
strong_passwords = []
for username, data in all_mimikatz_data.items():
    if ('ntlm' in data and data['ntlm']) and ('lm' not in data or not data['lm']):
        if username in fixed_data:
            if 'lm' in fixed_data[username] and fixed_data[username]['lm']:
                issues_found += 1
                print(f"{issues_found}. {username} should be NTLM-only (strong password) but has LM hash in fixed data:")
                print(f"   Mimikatz NTLM: {data['ntlm']}")
                print(f"   Fixed LM: {fixed_data[username]['lm']}")
                print(f"   Source: {data['source']}")
        strong_passwords.append(username)

print(f"\nTotal hash integrity issues found: {issues_found}")
print(f"Total strong password users (NTLM only): {len(strong_passwords)}")
print("Strong password users (first 10 shown):")
for i, username in enumerate(sorted(strong_passwords)[:10]):
    print(f"  {i+1}. {username}")

