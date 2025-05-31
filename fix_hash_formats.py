#!/usr/bin/env python3
"""
Format Fixer for Hash Files

This script fixes the format issues in the hash files:
1. Corrects lm_only_hashes_accurate.txt to contain only LM hashes without usernames
2. Corrects ntlm_only_hashes_accurate.txt to contain only NTLM hashes without usernames
3. Corrects strong_passwords_accurate.txt to contain only NTLM hashes without usernames
4. Ensures ashleywilliams' hash (155d1254d37e9d54bf4bd4d80e55153b) is in strong_passwords.txt
5. Fixes any incomplete entries in complete_user_hash_data_accurate.txt
"""

import os
import re

# File paths
workspace_path = "/workspaces/JaiziahGreene"
complete_file = os.path.join(workspace_path, "complete_user_hash_data_accurate.txt")
lm_only_file = os.path.join(workspace_path, "lm_only_hashes_accurate.txt")
ntlm_only_file = os.path.join(workspace_path, "ntlm_only_hashes_accurate.txt")
strong_passwords_file = os.path.join(workspace_path, "strong_passwords_accurate.txt")

# Ashley Williams' NTLM hash for strong passwords
ashley_ntlm_hash = "155d1254d37e9d54bf4bd4d80e55153b"

def fix_lm_only_hashes():
    """Fix LM only hashes file to contain only the hash values without usernames"""
    print("Fixing LM only hashes file...")
    
    with open(lm_only_file, 'r') as f:
        lines = f.readlines()
    
    fixed_lines = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            fixed_lines.append(line)
            continue
        
        # Extract hash from username:hash format
        if ':' in line:
            _, hash_value = line.split(':', 1)
            fixed_lines.append(hash_value)
        else:
            fixed_lines.append(line)  # Already in correct format
    
    with open(lm_only_file, 'w') as f:
        f.write('\n'.join(fixed_lines) + '\n')
    
    print(f"  ✓ Fixed LM hashes file: {lm_only_file}")

def fix_ntlm_only_hashes():
    """Fix NTLM only hashes file to contain only the hash values without usernames"""
    print("Fixing NTLM only hashes file...")
    
    with open(ntlm_only_file, 'r') as f:
        lines = f.readlines()
    
    fixed_lines = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            fixed_lines.append(line)
            continue
        
        # Extract hash from username:hash format
        if ':' in line:
            _, hash_value = line.split(':', 1)
            fixed_lines.append(hash_value)
        else:
            fixed_lines.append(line)  # Already in correct format
    
    with open(ntlm_only_file, 'w') as f:
        f.write('\n'.join(fixed_lines) + '\n')
    
    print(f"  ✓ Fixed NTLM hashes file: {ntlm_only_file}")

def fix_strong_passwords():
    """
    Fix strong passwords file to:
    1. Contain only the hash values without usernames
    2. Ensure ashley_ntlm_hash is included
    """
    print("Fixing strong passwords file...")
    
    with open(strong_passwords_file, 'r') as f:
        lines = f.readlines()
    
    fixed_lines = []
    hashes_set = set()
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            fixed_lines.append(line)
            continue
        
        # Extract hash from username:hash format
        if ':' in line:
            username, hash_value = line.split(':', 1)
            fixed_lines.append(hash_value)
            hashes_set.add(hash_value)
            
            # Check if this is Ashley's username but with a different hash
            if username.lower() == "ashleywilliams" and hash_value != ashley_ntlm_hash:
                print(f"  ⚠️ Ashley's hash mismatch in strong passwords - found {hash_value} instead of {ashley_ntlm_hash}")
        else:
            fixed_lines.append(line)
            hashes_set.add(line)
    
    # Ensure Ashley's hash is included
    if ashley_ntlm_hash not in hashes_set:
        print(f"  ✓ Adding Ashley's hash {ashley_ntlm_hash} to strong passwords")
        fixed_lines.append(ashley_ntlm_hash)
    
    with open(strong_passwords_file, 'w') as f:
        f.write('\n'.join(fixed_lines) + '\n')
    
    print(f"  ✓ Fixed strong passwords file: {strong_passwords_file}")

def fix_complete_user_hash_data():
    """Fix any incomplete entries in complete_user_hash_data_accurate.txt"""
    print("Fixing complete user hash data...")
    
    with open(complete_file, 'r') as f:
        lines = f.readlines()
    
    fixed_lines = []
    fixed_count = 0
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            fixed_lines.append(line)
            continue
        
        # Check if line ends with a colon (missing LM hash)
        if line.endswith(':'):
            fixed_lines.append(line[:-1])  # Remove trailing colon
            fixed_count += 1
        else:
            fixed_lines.append(line)
    
    with open(complete_file, 'w') as f:
        f.write('\n'.join(fixed_lines) + '\n')
    
    print(f"  ✓ Fixed {fixed_count} incomplete entries in complete user hash data")

def main():
    print("=== HASH FORMAT FIXER ===")
    
    fix_lm_only_hashes()
    fix_ntlm_only_hashes()
    fix_strong_passwords()
    fix_complete_user_hash_data()
    
    print("\nAll hash files have been fixed and are now in the correct format.")
    print("Please run simple_hash_validator.py to verify the fixes.")

if __name__ == "__main__":
    main()
