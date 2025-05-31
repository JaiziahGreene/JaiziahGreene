#!/usr/bin/env python3
"""
This script combines data from mimikatz output and existing username:password:ntlm file
to create a comprehensive, de-duplicated output with the format:
username:password:ntlm:lm (with password and lm being optional)
"""

import re
import os
import sys
from collections import defaultdict

# Regular expressions to extract data from mimikatz output
USER_PATTERN = re.compile(r'User\s+:\s+(.+)')
RID_PATTERN = re.compile(r'RID\s+:\s+([0-9a-f]+)\s+\((\d+)\)')
LM_HASH_PATTERN = re.compile(r'Hash\s+LM\s+:\s+([0-9a-f]{32})')
NTLM_HASH_PATTERN = re.compile(r'Hash\s+NTLM:\s+([0-9a-f]{32})')

def parse_mimikatz_output(filename):
    """Parse the mimikatz output file and extract user data."""
    users_data = defaultdict(dict)
    
    try:
        # Read the file as binary and try different encodings
        with open(filename, 'rb') as f:
            binary_content = f.read()
            
        # Try different encodings
        for encoding in ['utf-16', 'utf-8', 'latin-1', 'windows-1252']:
            try:
                content = binary_content.decode(encoding, errors='replace')
                break
            except UnicodeDecodeError:
                continue
        else:
            # If all encodings fail, use latin-1 as a fallback
            content = binary_content.decode('latin-1', errors='replace')
        
        # Process by line
        lines = content.splitlines()
        current_user = None
        debug_count = 0
        found_users = set()
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Print sample lines for debugging
            if 15 <= i <= 25:
                print(f"Debug Line {i}: {line}")
            
            # Check for RID and Username pattern (they're on consecutive lines)
            if "RID" in line and ":" in line and i + 1 < len(lines):
                user_line = lines[i + 1].strip()
                if "User" in user_line and ":" in user_line:
                    username_parts = user_line.split(":", 1)
                    if len(username_parts) > 1:
                        current_user = username_parts[1].strip()
                        found_users.add(current_user)
                        debug_count += 1
                        print(f"Found user: {current_user}")
            
            # Check for NTLM hash
            if current_user and "Hash NTLM" in line and ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    ntlm_hash = parts[1].strip().lower()
                    users_data[current_user]['ntlm'] = ntlm_hash
                    print(f"Found NTLM hash for {current_user}: {ntlm_hash[:8]}...")
            
            # Check for LM hash
            if current_user and "Hash LM" in line and ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    lm_hash = parts[1].strip().lower()
                    if lm_hash and lm_hash != '0'*32:  # Skip empty LM hashes
                        users_data[current_user]['lm'] = lm_hash
                        print(f"Found LM hash for {current_user}: {lm_hash[:8]}...")
            
            i += 1
        
        print(f"Debug: Found {debug_count} user entries and {len(found_users)} unique users")
                        
    except Exception as e:
        print(f"Error parsing mimikatz output: {e}")
        import traceback
        traceback.print_exc()
        
    return users_data

def parse_username_pass_ntlm(filename):
    """Parse the username:password:ntlm file."""
    users_data = defaultdict(dict)
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//'):  # Skip empty lines or comments
                    continue
                    
                parts = line.split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    password = parts[1]
                    ntlm = parts[2].lower()
                    
                    users_data[username]['password'] = password
                    users_data[username]['ntlm'] = ntlm
                    
    except Exception as e:
        print(f"Error parsing username:password:ntlm file: {e}")
        
    return users_data

def merge_user_data(mimikatz_data, pass_ntlm_data):
    """Merge data from both sources."""
    all_data = defaultdict(dict)
    
    # First add all mimikatz data
    for username, data in mimikatz_data.items():
        all_data[username].update(data)
        
    # Then add/update with password data
    for username, data in pass_ntlm_data.items():
        if username in all_data:
            all_data[username].update(data)
        else:
            all_data[username] = data
            
    return all_data

def write_output(data, output_filename):
    """Write the merged data to output file."""
    with open(output_filename, 'w', encoding='utf-8') as f:
        f.write("// Complete User Hash Data - Format: username:password:ntlm:lm\n")
        f.write("// Note: password and LM hash may be empty if not available\n\n")
        
        for username, user_data in sorted(data.items()):
            password = user_data.get('password', '')
            ntlm = user_data.get('ntlm', '')
            lm = user_data.get('lm', '')
            
            # Only include users that have at least an NTLM hash
            if ntlm:
                f.write(f"{username}:{password}:{ntlm}:{lm}\n")

def main():
    mimikatz_file = '/workspaces/JaiziahGreene/mimikatz_output.txt'
    pass_ntlm_file = '/workspaces/JaiziahGreene/complete_username_pass_ntlm.txt'
    output_file = '/workspaces/JaiziahGreene/complete_user_hash_data.txt'
    
    print(f"Parsing mimikatz output from {mimikatz_file}...")
    mimikatz_data = parse_mimikatz_output(mimikatz_file)
    print(f"Found {len(mimikatz_data)} users from mimikatz output.")
    
    print(f"Parsing username:password:ntlm data from {pass_ntlm_file}...")
    pass_ntlm_data = parse_username_pass_ntlm(pass_ntlm_file)
    print(f"Found {len(pass_ntlm_data)} users from password:ntlm file.")
    
    print("Merging data...")
    merged_data = merge_user_data(mimikatz_data, pass_ntlm_data)
    print(f"Total unique users after merging: {len(merged_data)}")
    
    print(f"Writing output to {output_file}...")
    write_output(merged_data, output_file)
    print("Done!")
    
    # Print some statistics
    users_with_passwords = sum(1 for data in merged_data.values() if 'password' in data)
    users_with_lm = sum(1 for data in merged_data.values() if 'lm' in data)
    
    print(f"Statistics:")
    print(f"- Total users: {len(merged_data)}")
    print(f"- Users with passwords: {users_with_passwords}")
    print(f"- Users with LM hashes: {users_with_lm}")
    print(f"- Users with only NTLM hashes: {len(merged_data) - users_with_passwords}")

if __name__ == "__main__":
    main()
