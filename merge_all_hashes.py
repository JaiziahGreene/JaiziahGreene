#!/usr/bin/env python3
"""
This script combines data from all mimikatz output files and existing username:password:ntlm file
to create a comprehensive, de-duplicated output with the format:
username:password:ntlm:lm (with password and lm being optional)
"""

import re
import os
import sys
from collections import defaultdict
import glob

def parse_mimikatz_output(filename):
    """Parse the mimikatz output file and extract user data."""
    users_data = defaultdict(dict)
    
    try:
        # Try to read with different encodings
        encodings = ['utf-8', 'utf-16-le', 'latin-1']
        content = None
        
        for encoding in encodings:
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    content = f.read()
                print(f"Successfully decoded {filename} with {encoding}")
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            print(f"Could not decode {filename} with any encoding")
            return users_data
            
        # Simplest method: use regex to find RID and User patterns
        rid_user_pattern = re.compile(r'RID\s+:\s+[0-9a-f]+\s+\(\d+\)[^\n]*\nUser\s+:\s+([^\n]+)', re.MULTILINE)
        matches = rid_user_pattern.finditer(content)
        
        for match in matches:
            username = match.group(1).strip()
            
            # Skip system accounts
            if username in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                continue
                
            # Record this user in our data
            users_data[username] = {}
        
        if "PC 4 Dump" in filename:
            print(f"PC 4 Dump - Found {len(users_data)} users using pattern matching")
        
        # If no users found, try alternate method
        if not users_data and "PC 4" in filename:
            print("Using alternative parsing for PC 4 Dump")
            
            lines = content.splitlines()
            current_user = None
            
            for line in lines:
                if "User" in line and ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        username = parts[1].strip()
                        
                        # Skip system accounts
                        if username and username not in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                            users_data[username] = {}
                            current_user = username
                
            print(f"Alternative method found {len(users_data)} users")
    
    except Exception as e:
        print(f"Error parsing mimikatz file {filename}: {e}")
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
                    
                    if password:
                        users_data[username]['password'] = password
                    if ntlm:
                        users_data[username]['ntlm'] = ntlm
                    
                    # Check if LM hash is present (4th field)
                    if len(parts) >= 4 and parts[3]:
                        lm = parts[3].lower()
                        if lm and lm != '0'*32:
                            users_data[username]['lm'] = lm
                    
    except Exception as e:
        print(f"Error parsing username:password:ntlm file: {e}")
        
    return users_data

def merge_user_data(all_mimikatz_data, pass_ntlm_data):
    """Merge data from both sources."""
    all_data = defaultdict(dict)
    
    # First add all mimikatz user names
    for username, data in all_mimikatz_data.items():
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
            
            # Include all users found in any file
            f.write(f"{username}:{password}:{ntlm}:{lm}\n")

def main():
    # Find all mimikatz dump files
    mimikatz_files = [
        "/workspaces/JaiziahGreene/mimikatz_output.txt",
        "/workspaces/JaiziahGreene/New MimiKatz Dumps/mimikatz PC 2.txt",
        "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 3 Dump.txt",
        "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 4 Dump.txt"
    ]
    
    # Filter to only files that exist
    mimikatz_files = [f for f in mimikatz_files if os.path.exists(f)]
    
    if not mimikatz_files:
        print("Error: No mimikatz dump files found!")
        return
    
    print(f"Found {len(mimikatz_files)} mimikatz dump files:")
    for file in mimikatz_files:
        print(f"  - {file}")
    
    pass_ntlm_file = '/workspaces/JaiziahGreene/complete_username_pass_ntlm.txt'
    output_file = '/workspaces/JaiziahGreene/complete_user_hash_data.txt'
    
    # Process all mimikatz files and collect user data
    all_mimikatz_data = defaultdict(dict)
    for file in mimikatz_files:
        print(f"\nParsing mimikatz output from {file}...")
        file_data = parse_mimikatz_output(file)
        print(f"Found {len(file_data)} users in this file.")
        
        # Merge into all_mimikatz_data
        for username, data in file_data.items():
            all_mimikatz_data[username].update(data)
    
    print(f"\nFound a total of {len(all_mimikatz_data)} unique users from all mimikatz files.")
    
    print(f"\nParsing username:password:ntlm data from {pass_ntlm_file}...")
    pass_ntlm_data = parse_username_pass_ntlm(pass_ntlm_file)
    print(f"Found {len(pass_ntlm_data)} users from password:ntlm file.")
    
    print("\nMerging all data...")
    merged_data = merge_user_data(all_mimikatz_data, pass_ntlm_data)
    print(f"Total unique users after merging: {len(merged_data)}")
    
    print(f"\nWriting output to {output_file}...")
    write_output(merged_data, output_file)
    print("Done!")
    
    # Print some statistics
    users_with_passwords = sum(1 for data in merged_data.values() if 'password' in data and data['password'])
    users_with_lm = sum(1 for data in merged_data.values() if 'lm' in data and data['lm'])
    users_with_ntlm = sum(1 for data in merged_data.values() if 'ntlm' in data and data['ntlm'])
    users_without_hash = len(merged_data) - users_with_ntlm
    
    print(f"\nStatistics:")
    print(f"- Total users: {len(merged_data)}")
    print(f"- Users with passwords: {users_with_passwords}")
    print(f"- Users with NTLM hashes: {users_with_ntlm}")
    print(f"- Users with LM hashes: {users_with_lm}")
    print(f"- Users with only account name (no hash): {users_without_hash}")

if __name__ == "__main__":
    main()
