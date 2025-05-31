#!/usr/bin/env python3
# filepath: /workspaces/JaiziahGreene/match_user_hashes.py
# Script to match usernames with their NTLM hashes and create a neatly formatted output

import re
from collections import defaultdict

# Input files
mimikatz_file = 'mimikatz_output.txt'
found_passwords_file = 'found_ntlm.txt'
output_file = 'user_ntlm_passwords.txt'

# Dictionary to store hash-to-password mappings
hash_to_password = {}

# Read found passwords
with open(found_passwords_file, 'r') as f:
    for line in f:
        line = line.strip()
        if ':' in line:
            ntlm_hash, password = line.split(':', 1)
            hash_to_password[ntlm_hash.lower()] = password

# Dictionary to store username to hash mappings
user_hash_mappings = {}

# Pattern to match user and hash
user_pattern = re.compile(r'User\s*:\s*(.+?)$')
hash_pattern = re.compile(r'Hash\s+NTLM\s*:\s*([a-fA-F0-9]{32})', re.IGNORECASE)

# Read mimikatz output
with open(mimikatz_file, 'r', encoding='utf-16-le', errors='ignore') as f:
    current_user = None
    
    for line in f:
        line = line.strip()
        
        # Check for user
        user_match = user_pattern.search(line)
        if user_match:
            current_user = user_match.group(1).strip()
            continue
        
        # Check for NTLM hash if we have a current user
        if current_user:
            hash_match = hash_pattern.search(line)
            if hash_match:
                ntlm_hash = hash_match.group(1).lower()
                user_hash_mappings[current_user] = ntlm_hash
                current_user = None  # Reset current user after finding hash

# Now create the output with username, hash, and password (if found)
with open(output_file, 'w') as f:
    f.write("Username\tNTLM Hash\tPassword (if known)\n")
    f.write("-" * 80 + "\n")
    
    for username, ntlm_hash in sorted(user_hash_mappings.items()):
        password = hash_to_password.get(ntlm_hash, "")
        f.write(f"{username}\t{ntlm_hash}\t{password}\n")

print(f"Matched usernames with NTLM hashes and saved to {output_file}")
