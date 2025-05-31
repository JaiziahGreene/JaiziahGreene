#!/usr/bin/env python3
"""
Advanced hash integrity validator

This script performs a thorough verification of hash data integrity by:
1. Directly extracting hash data from Mimikatz dumps with careful parsing
2. Comparing against the generated accurate hash files
3. Checking for any remaining discrepancies or issues
"""

import re
import os
import sys
from collections import defaultdict

# Enable debug mode
debug = True

def debug_print(*args, **kwargs):
    if debug:
        print(*args, **kwargs)

# File paths
workspace_path = "/workspaces/JaiziahGreene"
# Use the exact paths from file system
mimikatz_files = [
    os.path.join(workspace_path, "New MimiKatz Dumps", "mimikatz PC 2.txt"),
    os.path.join(workspace_path, "New MimiKatz Dumps", "Mimikatz PC 3 Dump.txt"),
    os.path.join(workspace_path, "New MimiKatz Dumps", "Mimikatz PC 4 Dump.txt"),
    os.path.join(workspace_path, "mimikatz_output.txt")
]
accurate_file = os.path.join(workspace_path, "complete_user_hash_data_accurate.txt")
ntlm_lm_file = os.path.join(workspace_path, "ntlm_lm_hashes_accurate.txt") 
lm_only_file = os.path.join(workspace_path, "lm_only_hashes_accurate.txt")
ntlm_only_file = os.path.join(workspace_path, "ntlm_only_hashes_accurate.txt")
strong_passwords_file = os.path.join(workspace_path, "strong_passwords_accurate.txt")
validation_report = os.path.join(workspace_path, "hash_validation_report.md")

# Print debug info to stdout instead of debug_print
print("Checking file paths:")
for idx, file_path in enumerate(mimikatz_files):
    print(f"Mimikatz file {idx+1}: {file_path} - Exists: {os.path.exists(file_path)}")
print(f"Accurate file: {accurate_file} - Exists: {os.path.exists(accurate_file)}")
print(f"Strong passwords file: {strong_passwords_file} - Exists: {os.path.exists(strong_passwords_file)}")

def extract_hash_data_directly(mimikatz_file):
    """
    Extract hash data directly from a mimikatz file with careful parsing
    This function uses more thorough and careful parsing techniques to ensure accuracy
    """
    print(f"Extracting hash data from: {os.path.basename(mimikatz_file)}")
    users_data = {}
    
    try:
        # Try different encodings
        content = None
        for encoding in ['utf-8', 'utf-16-le', 'latin-1']:
            try:
                with open(mimikatz_file, 'r', encoding=encoding) as f:
                    content = f.read()
                    if content:
                        print(f"Successfully read {mimikatz_file} with {encoding}")
                        break
            except UnicodeDecodeError:
                continue
                
        if not content:
            print(f"Could not read {mimikatz_file} with any encoding")
            return users_data
        
        # The most reliable way to parse mimikatz dumps is to find each user section
        # and then carefully extract the hash information
        
        # First split by RID sections to isolate each user's data
        user_sections = re.split(r'RID\s+:\s+[0-9a-fA-F]+\s+\(\d+\)', content)
        
        for section in user_sections[1:]:  # Skip the first section (before the first RID)
            try:
                # Extract username
                username_match = re.search(r'User\s+:\s+([^\r\n]+)', section)
                if not username_match:
                    continue
                    
                username = username_match.group(1).strip()
                
                # Skip built-in accounts
                if username in ['Administrator', 'Guest', 'DefaultAccount']:
                    continue
                
                # Extract NTLM hash - be very precise with the pattern
                ntlm_match = re.search(r'Hash\s+NTLM(?:\s+)?:\s+([0-9a-fA-F]{32})', section)
                ntlm_hash = ntlm_match.group(1).lower() if ntlm_match else ""
                
                # Extract LM hash - be very precise with the pattern
                lm_match = re.search(r'Hash\s+LM\s+:\s+([0-9a-fA-F]{32})', section)
                lm_hash = lm_match.group(1).lower() if lm_match else ""
                
                # Skip entries with no hash data
                if not ntlm_hash and not lm_hash:
                    continue
                
                # Skip empty or all-zero LM hashes
                if lm_hash == "0"*32:
                    lm_hash = ""
                
                # Store the data
                if username not in users_data:
                    users_data[username] = {
                        'ntlm': ntlm_hash,
                        'lm': lm_hash,
                        'source': mimikatz_file
                    }
                else:
                    # If we have multiple entries for the same user, report it
                    if ntlm_hash and users_data[username]['ntlm'] and ntlm_hash != users_data[username]['ntlm']:
                        print(f"Multiple NTLM hashes for {username} in {mimikatz_file}:")
                        print(f"  - Existing: {users_data[username]['ntlm']}")
                        print(f"  - New: {ntlm_hash}")
                        
                        # We'll keep a record of both versions
                        variant_name = f"{username}_variant"
                        counter = 1
                        while variant_name in users_data:
                            variant_name = f"{username}_variant{counter}"
                            counter += 1
                            
                        users_data[variant_name] = {
                            'ntlm': ntlm_hash,
                            'lm': lm_hash,
                            'source': mimikatz_file,
                            'note': f"Variant of {username}"
                        }
            except Exception as e:
                print(f"Error processing section for file {mimikatz_file}: {str(e)}")
    
    except Exception as e:
        print(f"Error reading {mimikatz_file}: {str(e)}")
    
    print(f"Extracted {len(users_data)} users from {mimikatz_file}")
    return users_data

def read_hash_file(file_path):
    """
    Read a hash file in username:password:ntlm:lm format
    """
    users_data = {}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                
                parts = line.split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    password = parts[1] if len(parts) > 1 else ""
                    ntlm = parts[2].lower() if len(parts) > 2 and parts[2] else ""
                    lm = parts[3].lower() if len(parts) > 3 and parts[3] else ""
                    
                    users_data[username] = {
                        'password': password,
                        'ntlm': ntlm,
                        'lm': lm
                    }
    except Exception as e:
        print(f"Error reading {file_path}: {str(e)}")
    
    return users_data

def validate_hash_integrity():
    """
    Validate hash integrity by comparing direct extraction from dumps 
    with the accurate hash files
    """
    print("\nStarting advanced hash integrity validation...\n")
    
    # First extract data directly from all mimikatz dumps
    all_direct_data = {}
    
    for file_path in mimikatz_files:
        if os.path.exists(file_path):
            print(f"Processing {file_path} directly...")
            file_data = extract_hash_data_directly(file_path)
            
            # Merge the data
            for username, data in file_data.items():
                if username not in all_direct_data:
                    all_direct_data[username] = data
                else:
                    # Keep track of any discrepancies between files
                    if all_direct_data[username]['ntlm'] != data['ntlm']:
                        variant_name = f"{username}_variant"
                        counter = 1
                        while variant_name in all_direct_data:
                            variant_name = f"{username}_variant{counter}"
                            counter += 1
                        
                        all_direct_data[variant_name] = data
    
    # Read the accurate hash file
    accurate_data = read_hash_file(accurate_file)
    print(f"\nRead {len(accurate_data)} users from {accurate_file}")
    
    # Compare the data
    missing_users = []
    mismatched_ntlm = []
    mismatched_lm = []
    extra_users = []
    
    # Check for users in direct extraction but not in accurate file
    for username, data in all_direct_data.items():
        if username not in accurate_data:
            extra_users.append({
                'username': username,
                'ntlm': data['ntlm'],
                'lm': data['lm'],
                'source': data['source']
            })
            continue
            
        # Check for mismatched NTLM hashes
        if data['ntlm'] and accurate_data[username]['ntlm'] and data['ntlm'] != accurate_data[username]['ntlm']:
            mismatched_ntlm.append({
                'username': username,
                'direct_ntlm': data['ntlm'],
                'accurate_ntlm': accurate_data[username]['ntlm'],
                'source': data['source']
            })
        
        # Check for mismatched LM hashes (only when both exist)
        if data['lm'] and accurate_data[username]['lm'] and data['lm'] != accurate_data[username]['lm']:
            mismatched_lm.append({
                'username': username,
                'direct_lm': data['lm'],
                'accurate_lm': accurate_data[username]['lm'],
                'source': data['source']
            })
    
    # Check for users in accurate file but not in direct extraction
    for username, data in accurate_data.items():
        if username not in all_direct_data and not username.endswith('_variant'):
            missing_users.append({
                'username': username,
                'ntlm': data['ntlm'],
                'lm': data['lm']
            })
    
    # Check strong passwords file accuracy
    strong_passwords = {}
    with open(strong_passwords_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            parts = line.split(':')
            if len(parts) >= 2:
                username = parts[0]
                ntlm = parts[1]
                strong_passwords[username] = ntlm
    
    strong_password_issues = []
    for username, ntlm in strong_passwords.items():
        # Verify the user exists in our direct extraction
        if username not in all_direct_data:
            strong_password_issues.append({
                'username': username,
                'issue': 'User not found in direct extraction',
                'ntlm': ntlm
            })
            continue
            
        # Verify NTLM hash matches
        if all_direct_data[username]['ntlm'] != ntlm:
            strong_password_issues.append({
                'username': username,
                'issue': 'NTLM hash mismatch',
                'direct_ntlm': all_direct_data[username]['ntlm'],
                'file_ntlm': ntlm
            })
            continue
            
        # Verify user has no LM hash
        if all_direct_data[username]['lm']:
            strong_password_issues.append({
                'username': username,
                'issue': 'User has LM hash but is in strong passwords file',
                'lm': all_direct_data[username]['lm']
            })
    
    # Check for users that should be in the strong passwords file but aren't
    missing_strong_users = []
    for username, data in all_direct_data.items():
        if data['ntlm'] and not data['lm'] and username not in strong_passwords:
            missing_strong_users.append({
                'username': username,
                'ntlm': data['ntlm']
            })
    
    # Generate validation report
    with open(validation_report, 'w', encoding='utf-8') as f:
        f.write("# Hash Data Validation Report\n\n")
        
        f.write("## Summary\n\n")
        f.write(f"- Direct extraction users: {len(all_direct_data)}\n")
        f.write(f"- Accurate file users: {len(accurate_data)}\n")
        f.write(f"- Strong passwords file users: {len(strong_passwords)}\n")
        f.write(f"- Users in dumps but not in accurate file: {len(extra_users)}\n")
        f.write(f"- Users in accurate file but not in dumps: {len(missing_users)}\n")
        f.write(f"- Users with mismatched NTLM hashes: {len(mismatched_ntlm)}\n")
        f.write(f"- Users with mismatched LM hashes: {len(mismatched_lm)}\n")
        f.write(f"- Issues with strong passwords file: {len(strong_password_issues)}\n")
        f.write(f"- Users missing from strong passwords file: {len(missing_strong_users)}\n\n")
        
        if extra_users:
            f.write("## Users in Dumps but Not in Accurate File\n\n")
            f.write("| Username | NTLM | LM | Source |\n")
            f.write("|----------|------|----|---------|\n")
            for user in extra_users[:20]:
                username = user['username']
                ntlm = user['ntlm'] or "(none)"
                lm = user['lm'] or "(none)"
                source = os.path.basename(user['source'])
                f.write(f"| {username} | {ntlm} | {lm} | {source} |\n")
            if len(extra_users) > 20:
                f.write(f"\n*... and {len(extra_users) - 20} more users.*\n\n")
        
        if missing_users:
            f.write("\n## Users in Accurate File but Not in Dumps\n\n")
            f.write("| Username | NTLM | LM |\n")
            f.write("|----------|------|----|\n")
            for user in missing_users[:20]:
                username = user['username']
                ntlm = user['ntlm'] or "(none)"
                lm = user['lm'] or "(none)"
                f.write(f"| {username} | {ntlm} | {lm} |\n")
            if len(missing_users) > 20:
                f.write(f"\n*... and {len(missing_users) - 20} more users.*\n\n")
        
        if mismatched_ntlm:
            f.write("\n## Users with Mismatched NTLM Hashes\n\n")
            f.write("| Username | Direct NTLM | Accurate NTLM | Source |\n")
            f.write("|----------|------------|--------------|--------|\n")
            for user in mismatched_ntlm[:20]:
                username = user['username']
                direct_ntlm = user['direct_ntlm']
                accurate_ntlm = user['accurate_ntlm']
                source = os.path.basename(user['source'])
                f.write(f"| {username} | {direct_ntlm} | {accurate_ntlm} | {source} |\n")
            if len(mismatched_ntlm) > 20:
                f.write(f"\n*... and {len(mismatched_ntlm) - 20} more users.*\n\n")
        
        if mismatched_lm:
            f.write("\n## Users with Mismatched LM Hashes\n\n")
            f.write("| Username | Direct LM | Accurate LM | Source |\n")
            f.write("|----------|----------|------------|--------|\n")
            for user in mismatched_lm[:20]:
                username = user['username']
                direct_lm = user['direct_lm']
                accurate_lm = user['accurate_lm']
                source = os.path.basename(user['source'])
                f.write(f"| {username} | {direct_lm} | {accurate_lm} | {source} |\n")
            if len(mismatched_lm) > 20:
                f.write(f"\n*... and {len(mismatched_lm) - 20} more users.*\n\n")
        
        if strong_password_issues:
            f.write("\n## Issues with Strong Passwords File\n\n")
            f.write("| Username | Issue | Details |\n")
            f.write("|----------|-------|--------|\n")
            for issue in strong_password_issues:
                username = issue['username']
                issue_type = issue['issue']
                
                if issue_type == 'User not found in direct extraction':
                    details = f"NTLM: {issue['ntlm']}"
                elif issue_type == 'NTLM hash mismatch':
                    details = f"Direct: {issue['direct_ntlm']}, File: {issue['file_ntlm']}"
                elif issue_type == 'User has LM hash but is in strong passwords file':
                    details = f"LM hash: {issue['lm']}"
                else:
                    details = ""
                    
                f.write(f"| {username} | {issue_type} | {details} |\n")
        
        if missing_strong_users:
            f.write("\n## Users Missing from Strong Passwords File\n\n")
            f.write("| Username | NTLM |\n")
            f.write("|----------|------|\n")
            for user in missing_strong_users[:20]:
                username = user['username']
                ntlm = user['ntlm']
                f.write(f"| {username} | {ntlm} |\n")
            if len(missing_strong_users) > 20:
                f.write(f"\n*... and {len(missing_strong_users) - 20} more users.*\n\n")
        
        f.write("\n## Conclusion\n\n")
        if not mismatched_ntlm and not mismatched_lm and not strong_password_issues and not missing_strong_users:
            f.write("The hash data integrity validation found no significant issues. The data is accurate according to the source Mimikatz dumps.\n")
        else:
            f.write("There are still some data integrity issues that need to be addressed. Review the above findings and update the hash files accordingly.\n")

    return {
        'extra_users': extra_users,
        'missing_users': missing_users,
        'mismatched_ntlm': mismatched_ntlm,
        'mismatched_lm': mismatched_lm,
        'strong_password_issues': strong_password_issues,
        'missing_strong_users': missing_strong_users
    }

if __name__ == "__main__":
    try:
        debug_print("Starting hash integrity validation...")
        
        # Check if we can access the files
        for file_path in mimikatz_files:
            if not os.path.exists(file_path):
                print(f"ERROR: Mimikatz file not found: {file_path}")
                sys.exit(1)
                
        if not os.path.exists(accurate_file):
            print(f"ERROR: Accurate hash file not found: {accurate_file}")
            sys.exit(1)
            
        # Run validation
        debug_print("All required files found, running validation...")
        results = validate_hash_integrity()
        
        print("\nValidation complete! Results summary:")
        print(f"- Users in dumps but not in accurate file: {len(results['extra_users'])}")
        print(f"- Users in accurate file but not in dumps: {len(results['missing_users'])}")
        print(f"- Users with mismatched NTLM hashes: {len(results['mismatched_ntlm'])}")
        print(f"- Users with mismatched LM hashes: {len(results['mismatched_lm'])}")
        print(f"- Issues with strong passwords file: {len(results['strong_password_issues'])}")
        print(f"- Users missing from strong passwords file: {len(results['missing_strong_users'])}")
        print(f"\nFull report written to {validation_report}")
        
    except Exception as e:
        print(f"ERROR: An exception occurred: {str(e)}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)
