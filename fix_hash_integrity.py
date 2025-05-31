#!/usr/bin/env python3
"""
Complete hash integrity fixer and variant generator.
This script:
1. Extracts hash data directly from mimikatz dumps with high accuracy
2. Creates fixed hash data file with correct NTLM and LM values
3. Generates variant files for different password cracking needs
4. Properly identifies strong password users (NTLM-only)
"""

import re
import os
from collections import defaultdict

# File paths
workspace_path = "/workspaces/JaiziahGreene"
mimikatz_files = [
    os.path.join(workspace_path, "New MimiKatz Dumps", "mimikatz PC 2.txt"),
    os.path.join(workspace_path, "New MimiKatz Dumps", "Mimikatz PC 3 Dump.txt"),
    os.path.join(workspace_path, "New MimiKatz Dumps", "Mimikatz PC 4 Dump.txt"),
    os.path.join(workspace_path, "mimikatz_output.txt")
]
output_file = os.path.join(workspace_path, "complete_user_hash_data_accurate.txt")
ntlm_lm_file = os.path.join(workspace_path, "ntlm_lm_hashes_accurate.txt")
lm_only_file = os.path.join(workspace_path, "lm_only_hashes_accurate.txt")
ntlm_only_file = os.path.join(workspace_path, "ntlm_only_hashes_accurate.txt")
strong_passwords_file = os.path.join(workspace_path, "strong_passwords_accurate.txt")
report_file = os.path.join(workspace_path, "hash_integrity_report.md")

# For clear manual corrections
manual_corrections = {
    "jean-marc.samson": {"ntlm": "155d1254d37e9d54bf4bd4d80e55153b", "lm": ""},
}

def extract_hash_from_mimikatz(filename):
    """Extract NTLM and LM hashes from mimikatz dump files very carefully."""
    users_data = defaultdict(dict)
    
    try:
        # Try different encodings
        for encoding in ['utf-8', 'utf-16-le', 'latin-1']:
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    content = f.read()
                print(f"Successfully decoded {filename} with {encoding}")
                break
            except UnicodeDecodeError:
                continue
        
        # Split by RID sections, which should reliably separate user entries
        rid_sections = re.split(r'RID\s+:\s+[0-9a-fA-F]+\s+\(\d+\)', content)
        
        # Process each section
        for i, section in enumerate(rid_sections[1:], 1):
            try:
                # Extract username - the most critical piece
                user_match = re.search(r'User\s+:\s+([^\r\n]+)', section)
                if not user_match:
                    continue
                    
                username = user_match.group(1).strip()
                
                # Skip built-in accounts except specific ones we want to keep
                if username in ['Administrator', 'Guest', 'DefaultAccount']:
                    continue
                    
                # Extract NTLM hash - using explicit "Hash NTLM" pattern
                ntlm_match = re.search(r'Hash\s+NTLM(?:\s+)?:\s+([0-9a-fA-F]{32})', section)
                ntlm_hash = ntlm_match.group(1).lower() if ntlm_match else ""
                
                # Extract LM hash - using explicit "Hash LM" pattern
                lm_match = re.search(r'Hash\s+LM\s+:\s+([0-9a-fA-F]{32})', section)
                lm_hash = lm_match.group(1).lower() if lm_match else ""
                
                # Skip entries with no hash data
                if not ntlm_hash and not lm_hash:
                    continue
                    
                # Skip empty or all-zero LM hashes
                if lm_hash and lm_hash == "0"*32:
                    lm_hash = ""
                
                # Log what we found
                if ntlm_hash or lm_hash:
                    if username in users_data:
                        # If we already have data, we'll need to resolve conflicts
                        if ntlm_hash and users_data[username].get('ntlm') and ntlm_hash != users_data[username]['ntlm']:
                            print(f"WARNING: Different NTLM hash for {username}:")
                            print(f"  - Existing: {users_data[username]['ntlm']}")
                            print(f"  - New from {filename}: {ntlm_hash}")
                            # We'll keep both versions as different entries
                            users_data[f"{username}_variant"] = {
                                'ntlm': ntlm_hash,
                                'lm': lm_hash,
                                'source': filename
                            }
                        else:
                            # Keep existing data, but add missing fields
                            if ntlm_hash and not users_data[username].get('ntlm'):
                                users_data[username]['ntlm'] = ntlm_hash
                            if lm_hash and not users_data[username].get('lm'):
                                users_data[username]['lm'] = lm_hash
                    else:
                        # Add new user data
                        users_data[username] = {
                            'ntlm': ntlm_hash,
                            'lm': lm_hash,
                            'source': filename
                        }
            except Exception as e:
                print(f"Error processing section {i} in {filename}: {str(e)}")
    
    except Exception as e:
        print(f"Error processing file {filename}: {str(e)}")
    
    return users_data

def read_password_data(filename):
    """Read any existing password data from username:password:ntlm file if available"""
    password_data = {}
    
    if not os.path.exists(filename):
        print(f"Password file {filename} not found, skipping.")
        return password_data
        
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                
                parts = line.split(':')
                if len(parts) >= 3 and parts[1]:
                    username = parts[0]
                    password = parts[1]
                    password_data[username] = password
    except Exception as e:
        print(f"Error reading password data: {str(e)}")
    
    return password_data

def create_variant_files(users_data):
    """Create various hash files for different password cracking needs"""
    
    # Write complete user hash data file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("// Complete User Hash Data (Accurate) - Format: username:password:ntlm:lm\n")
        f.write("// Note: password and LM hash may be empty if not available\n")
        f.write("// Generated with accurate hash extraction from mimikatz dumps\n\n")
        
        for username, data in sorted(users_data.items(), key=lambda x: x[0].lower()):
            password = data.get('password', '')
            ntlm = data.get('ntlm', '')
            lm = data.get('lm', '')
            f.write(f"{username}:{password}:{ntlm}:{lm}\n")
    
    # NTLM:LM file (just hashes, no usernames)
    with open(ntlm_lm_file, 'w', encoding='utf-8') as f:
        f.write("// NTLM:LM Hashes (Accurate)\n\n")
        for username, data in sorted(users_data.items(), key=lambda x: x[0].lower()):
            ntlm = data.get('ntlm', '')
            lm = data.get('lm', '')
            if ntlm and lm:  # Only include entries with both hashes
                f.write(f"{ntlm}:{lm}\n")
    
    # LM only file
    with open(lm_only_file, 'w', encoding='utf-8') as f:
        f.write("// LM Hashes Only (Accurate)\n\n")
        for username, data in sorted(users_data.items(), key=lambda x: x[0].lower()):
            lm = data.get('lm', '')
            if lm:  # Only include entries with LM hash
                f.write(f"{username}:{lm}\n")
    
    # NTLM only file
    with open(ntlm_only_file, 'w', encoding='utf-8') as f:
        f.write("// NTLM Hashes Only (Accurate)\n\n")
        for username, data in sorted(users_data.items(), key=lambda x: x[0].lower()):
            ntlm = data.get('ntlm', '')
            if ntlm:  # Only include entries with NTLM hash
                f.write(f"{username}:{ntlm}\n")
    
    # Strong passwords file (entries with only NTLM hash, no LM)
    with open(strong_passwords_file, 'w', encoding='utf-8') as f:
        f.write("// Strong Passwords (NTLM only, no LM - indicates stronger passwords)\n\n")
        for username, data in sorted(users_data.items(), key=lambda x: x[0].lower()):
            ntlm = data.get('ntlm', '')
            lm = data.get('lm', '')
            if ntlm and not lm:  # Only include entries with NTLM but no LM hash
                f.write(f"{username}:{ntlm}\n")

def compare_with_original(users_data, original_file):
    """Compare our accurate data with the original file to identify discrepancies"""
    if not os.path.exists(original_file):
        print(f"Original file {original_file} not found, skipping comparison.")
        return []
    
    discrepancies = []
    
    try:
        original_data = {}
        with open(original_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                    
                parts = line.split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    password = parts[1]
                    ntlm = parts[2].lower() if parts[2] else ""
                    lm = parts[3].lower() if len(parts) >= 4 and parts[3] else ""
                    
                    original_data[username] = {
                        'password': password,
                        'ntlm': ntlm,
                        'lm': lm
                    }
        
        # Compare the datasets
        for username, data in original_data.items():
            if username in users_data:
                orig_ntlm = data['ntlm']
                orig_lm = data['lm']
                accurate_ntlm = users_data[username].get('ntlm', '')
                accurate_lm = users_data[username].get('lm', '')
                
                # Check for discrepancies
                if orig_ntlm != accurate_ntlm or (orig_lm and orig_lm != accurate_lm):
                    discrepancies.append({
                        'username': username,
                        'orig_ntlm': orig_ntlm,
                        'accurate_ntlm': accurate_ntlm,
                        'orig_lm': orig_lm,
                        'accurate_lm': accurate_lm
                    })
    
    except Exception as e:
        print(f"Error comparing with original file: {str(e)}")
    
    return discrepancies

def create_integrity_report(users_data, discrepancies):
    """Create a comprehensive report about hash integrity"""
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("# Hash Data Integrity Report\n\n")
        
        f.write("## Summary\n\n")
        total_users = len(users_data)
        users_with_ntlm = sum(1 for d in users_data.values() if d.get('ntlm'))
        users_with_lm = sum(1 for d in users_data.values() if d.get('lm'))
        strong_passwords = sum(1 for d in users_data.values() if d.get('ntlm') and not d.get('lm'))
        
        f.write(f"- Total unique users: {total_users}\n")
        f.write(f"- Users with NTLM hashes: {users_with_ntlm}\n")
        f.write(f"- Users with LM hashes: {users_with_lm}\n")
        f.write(f"- Strong password users (NTLM only): {strong_passwords}\n")
        f.write(f"- Hash discrepancies fixed: {len(discrepancies)}\n\n")
        
        f.write("## Files Created\n\n")
        f.write(f"1. **{os.path.basename(output_file)}** - Complete hash data with username:password:ntlm:lm format\n")
        f.write(f"2. **{os.path.basename(ntlm_lm_file)}** - NTLM:LM pairs (for tools that use this format)\n")
        f.write(f"3. **{os.path.basename(lm_only_file)}** - LM hashes only (easier to crack)\n")
        f.write(f"4. **{os.path.basename(ntlm_only_file)}** - NTLM hashes only\n")
        f.write(f"5. **{os.path.basename(strong_passwords_file)}** - Users with strong passwords (NTLM only)\n\n")
        
        if discrepancies:
            f.write("## Hash Integrity Issues Fixed\n\n")
            f.write("The following discrepancies were found and fixed:\n\n")
            f.write("| Username | Original NTLM | Accurate NTLM | Original LM | Accurate LM |\n")
            f.write("|----------|--------------|--------------|-------------|------------|\n")
            
            for i, d in enumerate(discrepancies[:20]):
                username = d['username']
                orig_ntlm = d['orig_ntlm'] or "(empty)"
                accurate_ntlm = d['accurate_ntlm'] or "(empty)"
                orig_lm = d['orig_lm'] or "(empty)"
                accurate_lm = d['accurate_lm'] or "(none)"
                
                f.write(f"| {username} | {orig_ntlm} | {accurate_ntlm} | {orig_lm} | {accurate_lm} |\n")
            
            if len(discrepancies) > 20:
                f.write(f"\n*... and {len(discrepancies) - 20} more discrepancies.*\n\n")
                
        f.write("\n## Strong Password Users (NTLM only)\n\n")
        f.write("These users have only NTLM hashes (no LM hashes), indicating they likely have stronger passwords:\n\n")
        
        strong_users = [username for username, data in users_data.items() 
                       if data.get('ntlm') and not data.get('lm')]
        
        for i, username in enumerate(sorted(strong_users)[:20]):
            f.write(f"{i+1}. {username}\n")
        
        if len(strong_users) > 20:
            f.write(f"\n*... and {len(strong_users) - 20} more users.*\n")

def main():
    # Extract accurate data from mimikatz dumps
    print("Extracting accurate hash data from mimikatz dumps...")
    all_users_data = defaultdict(dict)
    
    for file in mimikatz_files:
        if os.path.exists(file):
            print(f"\nProcessing {file}...")
            users_data = extract_hash_from_mimikatz(file)
            print(f"Found {len(users_data)} users in {file}")
            
            # Merge with main data
            for username, data in users_data.items():
                if username in all_users_data and 'ntlm' in all_users_data[username] and 'ntlm' in data:
                    if all_users_data[username]['ntlm'] != data['ntlm']:
                        # Different NTLM values - keep as variant
                        all_users_data[f"{username}_variant"] = data
                    elif 'lm' in data and data['lm'] and 'lm' not in all_users_data[username]:
                        all_users_data[username]['lm'] = data['lm']
                else:
                    all_users_data[username].update(data)
    
    # Read password data if available
    pass_file = os.path.join(workspace_path, "complete_username_pass_ntlm.txt")
    print(f"\nReading password data from {pass_file}...")
    password_data = read_password_data(pass_file)
    print(f"Found {len(password_data)} users with passwords")
    
    # Add passwords to our data
    for username, password in password_data.items():
        if username in all_users_data:
            all_users_data[username]['password'] = password
    
    # Apply manual corrections if needed
    for username, corrections in manual_corrections.items():
        if username in all_users_data:
            print(f"Applying manual correction for {username}")
            for key, value in corrections.items():
                all_users_data[username][key] = value
    
    # Compare with original file to identify discrepancies
    original_file = os.path.join(workspace_path, "complete_user_hash_data.txt")
    print(f"\nComparing with original file {original_file}...")
    discrepancies = compare_with_original(all_users_data, original_file)
    print(f"Found {len(discrepancies)} hash discrepancies")
    
    # Create all variant files
    print("\nCreating variant files...")
    create_variant_files(all_users_data)
    
    # Create report
    print("Creating hash integrity report...")
    create_integrity_report(all_users_data, discrepancies)
    
    # Print statistics
    print("\nStatistics:")
    print(f"- Total unique users: {len(all_users_data)}")
    ntlm_count = sum(1 for d in all_users_data.values() if d.get('ntlm'))
    lm_count = sum(1 for d in all_users_data.values() if d.get('lm'))
    strong_count = sum(1 for d in all_users_data.values() if d.get('ntlm') and not d.get('lm'))
    print(f"- Users with NTLM hashes: {ntlm_count}")
    print(f"- Users with LM hashes: {lm_count}")
    print(f"- Strong password users (NTLM only): {strong_count}")
    print(f"- Hash discrepancies fixed: {len(discrepancies)}")
    
    # Summary of files created
    print("\nFiles created:")
    print(f"1. {output_file}")
    print(f"2. {ntlm_lm_file}")
    print(f"3. {lm_only_file}")
    print(f"4. {ntlm_only_file}")
    print(f"5. {strong_passwords_file}")
    print(f"6. {report_file}")
    
    print("\nDone!")

if __name__ == "__main__":
    main()
