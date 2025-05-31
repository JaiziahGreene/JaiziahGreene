#!/usr/bin/env python3
"""Find all users in our hash files that have only NTLM hashes (no LM hash)"""

import os

# Define file paths
accurate_file = "/workspaces/JaiziahGreene/complete_user_hash_data_accurate.txt"
strong_passwords_file = "/workspaces/JaiziahGreene/strong_passwords_accurate.txt"

def find_ntlm_only_users():
    """Identify users with only NTLM hashes from the complete hash data file"""
    ntlm_only_users = []
    
    # Read the main hash file
    try:
        with open(accurate_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('//')]
            
            for line in lines:
                parts = line.split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    ntlm = parts[2] if len(parts) >= 3 else None
                    lm = parts[3] if len(parts) >= 4 else None
                    
                    # Check for users with NTLM but no LM
                    if ntlm and not lm:
                        ntlm_only_users.append((username, ntlm))
            
        print(f"Found {len(ntlm_only_users)} users with only NTLM hashes (no LM hash):")
        for username, ntlm in ntlm_only_users:
            print(f"{username}: {ntlm}")
            
    except Exception as e:
        print(f"Error processing {accurate_file}: {str(e)}")
    
    # Check if these users are in the strong passwords file
    try:
        with open(strong_passwords_file, 'r', encoding='utf-8') as f:
            strong_lines = [line.strip() for line in f if line.strip() and not line.startswith('//')]
            
        # Get just the NTLM hashes
        strong_hashes = set()
        for line in strong_lines:
            if line and len(line) == 32 and all(c in '0123456789abcdef' for c in line.lower()):
                strong_hashes.add(line.lower())
        
        # Check if all NTLM-only users are in the strong passwords file
        for username, ntlm in ntlm_only_users:
            if ntlm.lower() in strong_hashes:
                print(f"✓ {username}'s NTLM hash is correctly in the strong passwords file")
            else:
                print(f"❌ {username}'s NTLM hash is missing from the strong passwords file!")
    
    except Exception as e:
        print(f"Error processing {strong_passwords_file}: {str(e)}")
        
    return ntlm_only_users

if __name__ == "__main__":
    find_ntlm_only_users()
