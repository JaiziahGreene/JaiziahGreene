#!/usr/bin/env python3
"""
This script combines data from all mimikatz output files and existing username:password:ntlm file
to create a comprehensive, de-duplicated output with the format:
username:password:ntlm:lm (with password and lm being optional)

It properly handles various mimikatz output formats and different encodings.
"""

import re
import os
import sys
from collections import defaultdict
import glob

def parse_mimikatz_output(filename):
    """Parse the mimikatz output file and extract user data including LM and NTLM hashes."""
    users_data = defaultdict(dict)
    
    try:
        # Try to read with UTF-16-LE first (as specified), then fallback to other encodings
        encodings = ['utf-16-le', 'utf-8', 'latin-1']
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
            
        # Special handling for PC 4 dump which has a different format
        if "PC 4 Dump" in filename:
            print("Using special parsing for PC 4 dump...")
            
            # This pattern works for the specific format in PC 4 dump
            # Note that in this format, the hash lines are properly indented with spaces
            pc4_pattern = re.compile(
                r'RID\s+:\s+[0-9a-f]+\s+\(\d+\)\s*\n'
                r'User\s+:\s+([^\n]+)\s*\n'
                r'(?:\s{2}Hash\s+LM\s+:\s+([0-9a-f]{32}))?\s*\n'
                r'(?:\s{2}Hash\s+NTLM:\s+([0-9a-f]{32}))?',
                re.MULTILINE
            )
            
            # Extract a segment of the content for debugging
            debug_segment = content[12000:13000] if len(content) > 13000 else content
            print(f"Debug sample from PC 4 dump (around line 12000):")
            print(debug_segment[:200] + "...")
            
            matches = list(pc4_pattern.finditer(content))
            print(f"Found {len(matches)} potential user hash entries in PC 4 dump")
            
            for match in matches:
                username = match.group(1).strip()
                lm_hash = match.group(2) if match.group(2) else ""
                ntlm_hash = match.group(3) if match.group(3) else ""
                
                if username and (lm_hash or ntlm_hash) and username not in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                    users_data[username]['lm'] = lm_hash.lower() if lm_hash and lm_hash != '0'*32 else ''
                    users_data[username]['ntlm'] = ntlm_hash.lower() if ntlm_hash else ''
                    print(f"Found user {username} with {'LM and ' if lm_hash else ''}NTLM hash")
            
            if len(users_data) > 0:
                print(f"PC4 special format found {len(users_data)} users")
                return users_data
                
            # If the above pattern didn't work, try an alternate pattern
            print("Trying alternate PC 4 pattern...")
            alt_pattern = re.compile(
                r'RID\s+:\s+[0-9a-f]+\s+\(\d+\)\s*\n'
                r'User\s+:\s+([^\n]+)\s*\n.*?'
                r'Hash\s+LM\s+:\s+([0-9a-f]{32}).*?\n.*?'
                r'Hash\s+NTLM:\s+([0-9a-f]{32})',
                re.DOTALL
            )
            
            matches = list(alt_pattern.finditer(content))
            print(f"Found {len(matches)} potential user hash entries with alternate pattern")
            
            for match in matches:
                username = match.group(1).strip()
                lm_hash = match.group(2) if match.group(2) else ""
                ntlm_hash = match.group(3) if match.group(3) else ""
                
                if username and (lm_hash or ntlm_hash) and username not in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                    users_data[username]['lm'] = lm_hash.lower() if lm_hash and lm_hash != '0'*32 else ''
                    users_data[username]['ntlm'] = ntlm_hash.lower() if ntlm_hash else ''
            
            if len(users_data) > 0:
                print(f"PC4 alternate format found {len(users_data)} users")
                return users_data
        
        # First, handle the format with explicit LM and NTLM hashes
        # Pattern for lines like:
        #   User : lmullane
        #   Hash LM  : 4ce9efe5885e8c845d3872c04445e010
        #   Hash NTLM: 9146cca50481dbe3a7790d58ee6f371a
        user_hash_sections = re.finditer(r'User\s+:\s+([^\n]+)(?:\n.*?)?(?:Hash\s+LM\s+:\s+([0-9a-f]{32}))?(?:\n.*?)?(?:Hash\s+NTLM(?:\s+)?:\s+([0-9a-f]{32}))?', content, re.DOTALL)
        
        for match in user_hash_sections:
            username = match.group(1).strip()
            lm_hash = match.group(2) if match.group(2) else ""
            ntlm_hash = match.group(3) if match.group(3) else ""
            
            if username and (lm_hash or ntlm_hash) and username not in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                users_data[username]['lm'] = lm_hash.lower() if lm_hash and lm_hash != '0'*32 else ''
                users_data[username]['ntlm'] = ntlm_hash.lower() if ntlm_hash else ''
                
        # If no hashes found with the above pattern, use a different approach
        if len(users_data) == 0:
            # Find all user sections based on RID and User pattern
            rid_pattern = re.compile(r'RID\s+:\s+[0-9a-f]+\s+\(\d+\)')
            user_pattern = re.compile(r'User\s+:\s+([^\n]+)')
            lm_hash_pattern = re.compile(r'Hash\s+LM\s+:\s+([0-9a-f]{32})')
            ntlm_hash_pattern = re.compile(r'Hash\s+NTLM(?:\s+)?:\s+([0-9a-f]{32})')
            
            # Split content into sections by RID
            rid_matches = list(rid_pattern.finditer(content))
            
            for i, rid_match in enumerate(rid_matches):
                # Get section end (next RID or end of file)
                section_start = rid_match.start()
                section_end = rid_matches[i+1].start() if i+1 < len(rid_matches) else len(content)
                
                # Extract section content
                section = content[section_start:section_end]
                
                # Extract user, LM and NTLM from this section
                user_match = user_pattern.search(section)
                if not user_match:
                    continue
                
                username = user_match.group(1).strip()
                if not username or username in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                    continue
                
                lm_hash_match = lm_hash_pattern.search(section)
                lm_hash = lm_hash_match.group(1).lower() if lm_hash_match else ""
                
                ntlm_hash_match = ntlm_hash_pattern.search(section)
                ntlm_hash = ntlm_hash_match.group(1).lower() if ntlm_hash_match else ""
                
                if lm_hash and lm_hash == '0'*32:
                    lm_hash = ""  # Don't store empty LM hashes
                
                if username not in users_data or not users_data[username].get('ntlm'):
                    users_data[username]['lm'] = lm_hash
                    if ntlm_hash:
                        users_data[username]['ntlm'] = ntlm_hash
                
    except Exception as e:
        print(f"Error parsing mimikatz file {filename}: {e}")
        import traceback
        traceback.print_exc()
        
    print(f"Found {sum(1 for u in users_data.values() if 'ntlm' in u)} users with NTLM hashes")
    print(f"Found {sum(1 for u in users_data.values() if 'lm' in u and u['lm'])} users with LM hashes")
    
    return users_data

def parse_username_pass_ntlm(filename):
    """Parse the username:password:ntlm:lm file."""
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
                    ntlm = parts[2].lower() if parts[2] else ""
                    
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
    """Merge data from both sources, avoiding duplicates."""
    all_data = defaultdict(dict)
    
    # First add all mimikatz user data
    for username, data in all_mimikatz_data.items():
        all_data[username].update(data)
        
    # Then add/update with password data
    for username, data in pass_ntlm_data.items():
        if username in all_data:
            # If we already have NTLM hash for this user, only update password
            if 'ntlm' in all_data[username] and 'ntlm' in data:
                # If different NTLM hash, create a new entry with suffix
                if all_data[username]['ntlm'] != data['ntlm']:
                    all_data[f"{username}_variant"] = data
                else:
                    if 'password' in data:
                        all_data[username]['password'] = data['password']
                    if 'lm' in data and data['lm']:
                        all_data[username]['lm'] = data['lm']
            else:
                all_data[username].update(data)
        else:
            all_data[username] = data
            
    return all_data

def write_output(data, output_filename):
    """Write the merged data to output file."""
    with open(output_filename, 'w', encoding='utf-8') as f:
        f.write("// Complete User Hash Data - Format: username:password:ntlm:lm\n")
        f.write("// Note: password and LM hash may be empty if not available\n\n")
        
        # Sort by username alphabetically
        for username, user_data in sorted(data.items(), key=lambda x: x[0].lower()):
            password = user_data.get('password', '')
            ntlm = user_data.get('ntlm', '')
            lm = user_data.get('lm', '')
            
            # Only include users that have at least an NTLM hash or LM hash
            if ntlm or lm:
                f.write(f"{username}:{password}:{ntlm}:{lm}\n")

def main():
    # Define the mimikatz dump files to process
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
        
        # Merge into all_mimikatz_data without overwriting existing entries
        for username, data in file_data.items():
            if username in all_mimikatz_data:
                # If we already have NTLM for this user and new data has a different NTLM,
                # create a variant
                if 'ntlm' in all_mimikatz_data[username] and 'ntlm' in data:
                    if all_mimikatz_data[username]['ntlm'] != data['ntlm']:
                        all_mimikatz_data[f"{username}_variant"] = data
                    elif 'lm' in data and data['lm'] and 'lm' not in all_mimikatz_data[username]:
                        all_mimikatz_data[username]['lm'] = data['lm']
            else:
                all_mimikatz_data[username] = data
    
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
    
    print(f"\nStatistics:")
    print(f"- Total users: {len(merged_data)}")
    print(f"- Users with passwords: {users_with_passwords}")
    print(f"- Users with NTLM hashes: {users_with_ntlm}")
    print(f"- Users with LM hashes: {users_with_lm}")
    print(f"- Users with only account name (no hash): {len(merged_data) - users_with_ntlm - users_with_lm}")

if __name__ == "__main__":
    main()
