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
import glob
from collections import defaultdict

def parse_mimikatz_output(filename):
    """Parse the mimikatz output file and extract user data including LM and NTLM hashes."""
    users_data = defaultdict(dict)
    
    try:
        # Try to read with different encodings
        encodings = ['utf-8', 'utf-16-le', 'latin-1']
        content = None
        successful_encoding = None
        
        for encoding in encodings:
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    content = f.read()
                successful_encoding = encoding
                print(f"Successfully decoded {filename} with {encoding}")
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            # Try binary mode as a last resort
            try:
                with open(filename, 'rb') as f:
                    binary_content = f.read()
                
                # Try to find binary patterns in the file
                if b"Hash LM" in binary_content and b"Hash NTLM" in binary_content:
                    print(f"Using binary processing for {filename}")
                    
                    # Convert binary to string (lossy conversion is ok for extraction)
                    content = binary_content.decode('utf-8', errors='ignore')
                else:
                    print(f"Could not decode {filename} with any encoding")
                    return users_data
            except Exception as e:
                print(f"Error opening file in binary mode: {e}")
                return users_data
        
        # Use a more robust pattern that can handle slight format variations
        pattern = re.compile(
            r'RID\s+:\s+[0-9a-fA-F]+\s+\(\d+\)[^\r\n]*[\r\n]+'
            r'User\s+:\s+([^\r\n]+)[\r\n]+'
            r'(?:[^\r\n]*[\r\n]+)*?'
            r'(?:Hash\s+LM\s+:\s+([0-9a-fA-F]{32}))?[^\r\n]*[\r\n]+'
            r'(?:[^\r\n]*[\r\n]+)*?'
            r'(?:Hash\s+NTLM(?:\s+)?:\s+([0-9a-fA-F]{32}))?',
            re.DOTALL
        )
        
        matches = list(pattern.finditer(content))
        print(f"Found {len(matches)} user hash entries with primary pattern")
        
        for match in matches:
            try:
                username = match.group(1).strip()
                lm_hash = match.group(2) if match.group(2) else ""
                ntlm_hash = match.group(3) if match.group(3) else ""
                
                # Skip built-in accounts
                if username in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                    continue
                    
                # Clean up any non-hex characters that might have slipped into the hashes
                lm_hash = ''.join(c for c in lm_hash if c in '0123456789abcdefABCDEF')
                ntlm_hash = ''.join(c for c in ntlm_hash if c in '0123456789abcdefABCDEF')
                
                # Validate hash length
                if len(ntlm_hash) == 32:
                    users_data[username]['ntlm'] = ntlm_hash.lower()
                    # Only add LM hash if it's valid and not all zeros
                    if len(lm_hash) == 32 and lm_hash != '0'*32:
                        users_data[username]['lm'] = lm_hash.lower()
                    else:
                        users_data[username]['lm'] = ''
            except Exception as e:
                print(f"Error processing match: {e}")
        
        # If first pattern didn't find anything, try alternate patterns
        if len(users_data) == 0:
            print("Standard pattern failed, trying alternate pattern...")
            
            # Try a simpler pattern that focuses on proximity
            alt_pattern = re.compile(
                r'User\s+:\s+([^\r\n]+).*?'
                r'Hash\s+LM\s+:\s+([0-9a-fA-F]+).*?'
                r'Hash\s+NTLM(?:\s+)?:\s+([0-9a-fA-F]+)',
                re.DOTALL
            )
            
            matches = list(alt_pattern.finditer(content))
            print(f"Found {len(matches)} matches with alternate pattern")
            
            for match in matches:
                try:
                    username = match.group(1).strip()
                    lm_hash = match.group(2) if match.group(2) else ""
                    ntlm_hash = match.group(3) if match.group(3) else ""
                    
                    # Skip built-in accounts
                    if username in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                        continue
                        
                    # Clean and validate hashes
                    lm_hash = ''.join(c for c in lm_hash if c in '0123456789abcdefABCDEF')
                    ntlm_hash = ''.join(c for c in ntlm_hash if c in '0123456789abcdefABCDEF')
                    
                    if len(ntlm_hash) == 32:
                        users_data[username]['ntlm'] = ntlm_hash.lower()
                        if len(lm_hash) == 32 and lm_hash != '0'*32:
                            users_data[username]['lm'] = lm_hash.lower()
                        else:
                            users_data[username]['lm'] = ''
                except Exception as e:
                    print(f"Error processing match with alternate pattern: {e}")
            
            # If still no results, try splitting by RID sections
            if len(users_data) == 0:
                print("Alternate pattern failed, trying section-based parsing...")
                
                # Split the content by RID markers and process each section
                sections = re.split(r'RID\s+:\s+[0-9a-fA-F]+\s+\(\d+\)', content)
                
                for section in sections[1:]:  # Skip the first section (before first RID)
                    try:
                        # Extract username
                        user_match = re.search(r'User\s+:\s+([^\r\n]+)', section)
                        if not user_match:
                            continue
                        
                        username = user_match.group(1).strip()
                        
                        # Skip built-in accounts
                        if username in ['Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']:
                            continue
                        
                        # Extract LM hash
                        lm_match = re.search(r'Hash\s+LM\s+:\s+([0-9a-fA-F]{32})', section)
                        lm_hash = lm_match.group(1) if lm_match else ""
                        
                        # Extract NTLM hash
                        ntlm_match = re.search(r'Hash\s+NTLM(?:\s+)?:\s+([0-9a-fA-F]{32})', section)
                        ntlm_hash = ntlm_match.group(1) if ntlm_match else ""
                        
                        # Clean and validate hashes
                        if ntlm_hash:
                            users_data[username]['ntlm'] = ntlm_hash.lower()
                        if lm_hash and lm_hash != '0'*32:
                            users_data[username]['lm'] = lm_hash.lower()
                    except Exception as e:
                        print(f"Error processing section: {e}")
    except Exception as e:
        print(f"Error parsing mimikatz file {filename}: {e}")
        import traceback
        traceback.print_exc()
    
    # Count users with different types of hashes    
    ntlm_count = sum(1 for u in users_data.values() if u.get('ntlm'))
    lm_count = sum(1 for u in users_data.values() if u.get('lm'))
    
    print(f"Found {ntlm_count} users with NTLM hashes")
    print(f"Found {lm_count} users with LM hashes")
    
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
    
    # Count users with different types of data
    password_count = sum(1 for u in users_data.values() if 'password' in u)
    ntlm_count = sum(1 for u in users_data.values() if 'ntlm' in u)
    lm_count = sum(1 for u in users_data.values() if 'lm' in u)
    
    print(f"Found {password_count} users with passwords")
    print(f"Found {ntlm_count} users with NTLM hashes")
    print(f"Found {lm_count} users with LM hashes")
    
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
                # Update with any missing data
                for key, value in data.items():
                    if key not in all_data[username] or not all_data[username][key]:
                        all_data[username][key] = value
        else:
            all_data[username] = data
            
    return all_data

def find_mimikatz_dumps(base_path):
    """Find all mimikatz dump files in the given path."""
    mimikatz_files = []
    
    # Check the known main dumps first
    standard_dumps = [
        os.path.join(base_path, "mimikatz_output.txt"),
        os.path.join(base_path, "New MimiKatz Dumps", "mimikatz PC 2.txt"),
        os.path.join(base_path, "New MimiKatz Dumps", "Mimikatz PC 3 Dump.txt"),
        os.path.join(base_path, "New MimiKatz Dumps", "Mimikatz PC 4 Dump.txt")
    ]
    
    # Add files that exist to our list
    for dump in standard_dumps:
        if os.path.isfile(dump):
            mimikatz_files.append(dump)
    
    # Search for additional dumps
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.lower().endswith(".txt") and ("mimikatz" in file.lower() or "dump" in file.lower()):
                full_path = os.path.join(root, file)
                if full_path not in mimikatz_files:  # Avoid duplicates
                    mimikatz_files.append(full_path)
    
    return mimikatz_files

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
    workspace_path = "/workspaces/JaiziahGreene"
    
    # Find all mimikatz dump files
    mimikatz_files = find_mimikatz_dumps(workspace_path)
    
    if not mimikatz_files:
        print("Error: No mimikatz dump files found!")
        return
    
    print(f"Found {len(mimikatz_files)} mimikatz dump files:")
    for file in mimikatz_files:
        print(f"  - {file}")
    
    pass_ntlm_file = os.path.join(workspace_path, 'complete_username_pass_ntlm.txt')
    output_file = os.path.join(workspace_path, 'complete_user_hash_data.txt')
    
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
                elif 'ntlm' not in all_mimikatz_data[username] and 'ntlm' in data:
                    all_mimikatz_data[username]['ntlm'] = data['ntlm']
                
                if 'lm' not in all_mimikatz_data[username] and 'lm' in data:
                    all_mimikatz_data[username]['lm'] = data['lm']
            else:
                all_mimikatz_data[username] = data
    
    # Count users with different types of hashes
    mimikatz_users_count = len(all_mimikatz_data)
    mimikatz_ntlm_count = sum(1 for u in all_mimikatz_data.values() if 'ntlm' in u)
    mimikatz_lm_count = sum(1 for u in all_mimikatz_data.values() if 'lm' in u and u['lm'])
    
    print(f"\nFound a total of {mimikatz_users_count} unique users from all mimikatz files.")
    print(f"- Users with NTLM hashes: {mimikatz_ntlm_count}")
    print(f"- Users with LM hashes: {mimikatz_lm_count}")
    
    print(f"\nParsing username:password:ntlm data from {pass_ntlm_file}...")
    pass_ntlm_data = parse_username_pass_ntlm(pass_ntlm_file)
    print(f"Found {len(pass_ntlm_data)} users from password:ntlm file.")
    
    print("\nMerging all data...")
    merged_data = merge_user_data(all_mimikatz_data, pass_ntlm_data)
    print(f"Total unique users after merging: {len(merged_data)}")
    
    # Count users with different types of data in merged results
    users_with_password = sum(1 for u in merged_data.values() if 'password' in u)
    users_with_ntlm = sum(1 for u in merged_data.values() if 'ntlm' in u)
    users_with_lm = sum(1 for u in merged_data.values() if 'lm' in u and u['lm'])
    users_with_only_name = len([u for u in merged_data if 'ntlm' not in merged_data[u] and 'lm' not in merged_data[u]])
    
    print(f"\nWriting output to {output_file}...")
    write_output(merged_data, output_file)
    print("Done!")
    
    print("\nStatistics:")
    print(f"- Total users: {len(merged_data)}")
    print(f"- Users with passwords: {users_with_password}")
    print(f"- Users with NTLM hashes: {users_with_ntlm}")
    print(f"- Users with LM hashes: {users_with_lm}")
    print(f"- Users with only account name (no hash): {users_with_only_name}")

if __name__ == "__main__":
    main()
