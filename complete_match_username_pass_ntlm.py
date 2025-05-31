#!/usr/bin/env python3
# Script to match all NTLM hashes with usernames and passwords

import re

# Files to use
ntlm_passwords_file = '/workspaces/JaiziahGreene/all the found ntlms pc 1.txt'
user_ntlm_file = '/workspaces/JaiziahGreene/user_ntlm_passwords.txt'
mimikatz_file = '/workspaces/JaiziahGreene/mimikatz_output.txt'
output_file = '/workspaces/JaiziahGreene/complete_username_pass_ntlm.txt'

# Dictionary to store hash -> password mappings
hash_to_password = {}

# Dictionary to store hash -> username mappings
hash_to_username = {}

# Load hash:password pairs from the ntlm_passwords_file
print(f"Loading hash:password pairs from {ntlm_passwords_file}...")
with open(ntlm_passwords_file, 'r') as f:
    # Skip the first line if it's a comment/header
    first_line = f.readline().strip()
    if first_line.startswith('//'):
        lines = f.readlines()
    else:
        lines = [first_line] + f.readlines()
        
    for line in lines:
        line = line.strip()
        if line and ':' in line:
            parts = line.split(':')
            if len(parts) == 2:
                ntlm_hash = parts[0].lower()
                password = parts[1]
                hash_to_password[ntlm_hash] = password
            
print(f"Loaded {len(hash_to_password)} hash:password pairs")

# Load username:hash pairs from user_ntlm_file
print(f"Loading username:hash pairs from {user_ntlm_file}...")
with open(user_ntlm_file, 'r') as f:
    # Skip the first two lines (header and separator)
    lines = f.readlines()[2:]
    for line in lines:
        parts = line.strip().split('\t')
        if len(parts) >= 2:
            username = parts[0]
            ntlm_hash = parts[1].lower()
            hash_to_username[ntlm_hash] = username
            
print(f"Loaded {len(hash_to_username)} username:hash pairs")

# Try to extract more username:hash pairs from mimikatz output
print(f"Extracting username:hash pairs from {mimikatz_file}...")

with open(mimikatz_file, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()
    
# Parse mimikatz output for user information
user_sections = re.split(r'\nRID\s+:', content)[1:]  # Split by RID sections
current_user = None

for section in user_sections:
    # Extract username
    user_match = re.search(r'User\s+:\s+(\S+)', section)
    if user_match:
        current_user = user_match.group(1)
        
        # Look for any 32-character hex string that might be a hash
        hex_matches = re.findall(r'(?<![a-fA-F0-9])([a-fA-F0-9]{32})(?![a-fA-F0-9])', section)
        if hex_matches:
            for hash_value in hex_matches:
                hash_value = hash_value.lower()
                hash_to_username[hash_value] = current_user

print(f"After mimikatz extraction, we have {len(hash_to_username)} username:hash pairs")

# Now create the final output with username:pass:ntlm format
print(f"Creating output file {output_file}...")
with open(output_file, 'w') as out_f:
    for ntlm_hash, password in hash_to_password.items():
        username = hash_to_username.get(ntlm_hash, "unknown")
        out_f.write(f"{username}:{password}:{ntlm_hash}\n")
        
print(f"Output saved to {output_file}")

# Additionally, let's create a summary file with counts
with open(f"{output_file}.summary.txt", 'w') as summary_f:
    summary_f.write(f"Total NTLM hashes with passwords: {len(hash_to_password)}\n")
    summary_f.write(f"Total usernames matched: {sum(1 for h in hash_to_password if hash_to_username.get(h) != 'unknown')}\n")
    summary_f.write(f"Total unmatched hashes (username=unknown): {sum(1 for h in hash_to_password if hash_to_username.get(h) == 'unknown')}\n")
    
    if sum(1 for h in hash_to_password if hash_to_username.get(h) == 'unknown') > 0:
        summary_f.write("\nUnmatched hashes:\n")
        for ntlm_hash, password in hash_to_password.items():
            if hash_to_username.get(ntlm_hash) == "unknown":
                summary_f.write(f"unknown:{password}:{ntlm_hash}\n")
                
print(f"Summary saved to {output_file}.summary.txt")
