#!/usr/bin/env python3
import os
import re
import sys

dumps = [
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/mimikatz PC 2.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 3 Dump.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 4 Dump.txt"
]

def clean_text(text):
    """Handle encoding issues in the file"""
    return ''.join(c if c.isprintable() or c in ['\n', '\t'] else ' ' for c in text)

ntlm_only_users = []

for dump_path in dumps:
    print(f"Processing {dump_path}...")
    try:
        with open(dump_path, 'r', errors='ignore') as f:
            dump_content = f.read()
            
        # Clean up the content
        dump_content = clean_text(dump_content)
        
        # Extract user blocks
        user_blocks = re.findall(r'User : ([^\n]+)(?:\s+[^\n]+\n)+?(?=User |$)', dump_content, re.MULTILINE)
        
        # Find users with only NTLM hashes
        for block in user_blocks:
            username = block.strip()
            has_lm = "Hash LM" in block
            has_ntlm = "Hash NTLM" in block
            
            if has_ntlm and not has_lm:
                # Extract the NTLM hash
                ntlm_match = re.search(r'Hash NTLM:\s*([0-9a-fA-F]{32})', block)
                ntlm_hash = ntlm_match.group(1) if ntlm_match else "Unknown"
                
                ntlm_only_users.append((username, ntlm_hash))
                print(f"Found NTLM-only user: {username} with hash: {ntlm_hash}")
            
    except Exception as e:
        print(f"Error processing {dump_path}: {e}")

print("\n===== Users with only NTLM hashes (no LM hash) =====")
for username, ntlm_hash in ntlm_only_users:
    print(f"{username}: {ntlm_hash}")
