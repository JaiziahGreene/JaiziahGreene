#!/usr/bin/env python3
"""
Comprehensive User Hash Validator

This script performs a detailed validation of each user's hash data by:
1. Directly extracting hash data from original Mimikatz dumps
2. Comparing against the accurate hash files
3. Reporting any discrepancies for each username
"""

import re
import os
import sys
from collections import defaultdict

# File paths
workspace_path = "/workspaces/JaiziahGreene"
mimikatz_files = [
    os.path.join(workspace_path, "New MimiKatz Dumps", "mimikatz PC 2.txt"),
    os.path.join(workspace_path, "New MimiKatz Dumps", "Mimikatz PC 3 Dump.txt"),
    os.path.join(workspace_path, "New MimiKatz Dumps", "Mimikatz PC 4 Dump.txt"),
    os.path.join(workspace_path, "mimikatz_output.txt")
]
accurate_file = os.path.join(workspace_path, "complete_user_hash_data_accurate.txt")
validation_report = os.path.join(workspace_path, "user_hash_verification_report.md")

# Username regex patterns for mimikatz output
username_patterns = [
    r'Authentication Id\s+:\s+\d+;\s+\d+\s+\([^)]+\)\s+User Name\s+:\s+([^\r\n]+)',
    r'User\s*:\s*([^\r\n]+)',
    r'Username\s*:\s*([^\r\n]+)'
]

# Hash regex patterns for mimikatz output
ntlm_pattern = r'NTLM\s*:\s*([a-fA-F0-9]{32})'
lm_pattern = r'LM\s*:\s*([a-fA-F0-9]{32})'

def extract_user_hashes_from_dumps():
    """Extract usernames and their NTLM/LM hashes directly from mimikatz dumps"""
    print("Extracting user hash data from Mimikatz dumps...")
    
    user_hash_data = {}
    
    for mimikatz_file in mimikatz_files:
        if not os.path.exists(mimikatz_file):
            print(f"Warning: Mimikatz file not found: {mimikatz_file}")
            continue
            
        print(f"Processing: {os.path.basename(mimikatz_file)}")
        
        with open(mimikatz_file, 'r', errors='ignore') as f:
            content = f.read()
            
        # Split the content into authentication sessions
        sessions = re.split(r'Authentication Id\s+:\s+\d+;\s+\d+', content)
        
        for session in sessions:
            if not session.strip():
                continue
                
            # Try different patterns to extract username
            username = None
            for pattern in username_patterns:
                match = re.search(pattern, session)
                if match and match.group(1).strip():
                    username = match.group(1).strip()
                    break
                    
            if not username:
                continue
                
            # Clean up username
            username = username.lower()
            
            # Extract NTLM hash
            ntlm_match = re.search(ntlm_pattern, session)
            ntlm_hash = ntlm_match.group(1) if ntlm_match else None
            
            # Extract LM hash
            lm_match = re.search(lm_pattern, session)
            lm_hash = lm_match.group(1) if lm_match else None
            
            # Only add if we found at least one hash
            if ntlm_hash or lm_hash:
                if username not in user_hash_data:
                    user_hash_data[username] = {
                        "ntlm": [],
                        "lm": [],
                        "sources": []
                    }
                
                if ntlm_hash and ntlm_hash not in user_hash_data[username]["ntlm"]:
                    user_hash_data[username]["ntlm"].append(ntlm_hash)
                if lm_hash and lm_hash not in user_hash_data[username]["lm"]:
                    user_hash_data[username]["lm"].append(lm_hash)
                
                user_hash_data[username]["sources"].append(os.path.basename(mimikatz_file))
    
    # Cleanup username variations and handle empty LM hashes
    cleaned_data = {}
    for username, data in user_hash_data.items():
        # Skip empty or system usernames
        if not username or username == '(null)' or username == 'system' or username == 'local service' or username == 'network service':
            continue
            
        # Remove domain prefixes if present
        if '\\' in username:
            username = username.split('\\')[-1]
            
        # Clean up any whitespace or special chars
        username = username.strip()
        
        if username not in cleaned_data:
            cleaned_data[username] = {
                "ntlm": data["ntlm"],
                "lm": [lm for lm in data["lm"] if lm and lm != 'aad3b435b51404eeaad3b435b51404ee'],
                "sources": list(set(data["sources"]))
            }
        else:
            # Merge data for same username
            for ntlm in data["ntlm"]:
                if ntlm not in cleaned_data[username]["ntlm"]:
                    cleaned_data[username]["ntlm"].append(ntlm)
            
            for lm in data["lm"]:
                if lm and lm != 'aad3b435b51404eeaad3b435b51404ee' and lm not in cleaned_data[username]["lm"]:
                    cleaned_data[username]["lm"].append(lm)
            
            for source in data["sources"]:
                if source not in cleaned_data[username]["sources"]:
                    cleaned_data[username]["sources"].append(source)
    
    print(f"Found {len(cleaned_data)} unique users with hash data")
    return cleaned_data

def load_accurate_hash_data():
    """Load the accurate hash data from the fixed file"""
    print("Loading accurate hash data...")
    
    accurate_data = {}
    
    if not os.path.exists(accurate_file):
        print(f"Error: Accurate hash file not found: {accurate_file}")
        return accurate_data
    
    with open(accurate_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue
                
            parts = line.split(':')
            if len(parts) >= 3:
                username = parts[0].lower()
                password = parts[1]
                ntlm = parts[2] if parts[2] else None
                lm = parts[3] if len(parts) >= 4 and parts[3] else None
                
                accurate_data[username] = {
                    "password": password,
                    "ntlm": ntlm,
                    "lm": lm
                }
    
    print(f"Loaded {len(accurate_data)} user entries from accurate hash file")
    return accurate_data

def verify_user_hash_data():
    """Verify each user's hash data against dumps and fixed file"""
    print("Starting comprehensive user hash verification...")
    
    # Extract data from dumps
    dump_data = extract_user_hashes_from_dumps()
    
    # Load accurate data
    accurate_data = load_accurate_hash_data()
    
    # Results collection
    discrepancies = []
    verified_users = []
    users_not_in_dumps = []
    users_not_in_accurate = []
    
    # Check each user in the accurate file
    for username, acc_data in accurate_data.items():
        if username in dump_data:
            # User exists in dumps, verify the data
            dump_ntlms = dump_data[username]["ntlm"]
            dump_lms = dump_data[username]["lm"]
            acc_ntlm = acc_data["ntlm"]
            acc_lm = acc_data["lm"]
            
            has_discrepancy = False
            discrepancy_details = {
                "username": username,
                "issue_type": [],
                "accurate_data": {"ntlm": acc_ntlm, "lm": acc_lm},
                "dump_data": {"ntlm": dump_ntlms, "lm": dump_lms},
                "sources": dump_data[username]["sources"]
            }
            
            # Check NTLM hash
            if acc_ntlm and acc_ntlm not in dump_ntlms:
                has_discrepancy = True
                discrepancy_details["issue_type"].append("NTLM hash mismatch")
            
            # Check LM hash
            if acc_lm:
                if not dump_lms or acc_lm not in dump_lms:
                    has_discrepancy = True
                    discrepancy_details["issue_type"].append("LM hash mismatch")
            elif dump_lms:
                has_discrepancy = True
                discrepancy_details["issue_type"].append("LM hash missing in accurate file")
            
            if has_discrepancy:
                discrepancies.append(discrepancy_details)
            else:
                verified_users.append(username)
        else:
            # User not found in dumps
            users_not_in_dumps.append({
                "username": username,
                "accurate_data": {"ntlm": acc_data["ntlm"], "lm": acc_data["lm"]},
                "password": acc_data["password"]
            })
    
    # Check for users in dumps but not in accurate file
    for username, dump_data_user in dump_data.items():
        if username not in accurate_data:
            users_not_in_accurate.append({
                "username": username,
                "dump_data": {"ntlm": dump_data_user["ntlm"], "lm": dump_data_user["lm"]},
                "sources": dump_data_user["sources"]
            })
    
    # Generate report
    with open(validation_report, 'w') as f:
        f.write("# User Hash Verification Report\n\n")
        f.write("This report verifies each user's hash data against the original Mimikatz dumps.\n\n")
        
        # Summary stats
        f.write("## Summary\n\n")
        f.write(f"- Total users in accurate file: {len(accurate_data)}\n")
        f.write(f"- Total users found in dumps: {len(dump_data)}\n")
        f.write(f"- Users verified as accurate: {len(verified_users)}\n")
        f.write(f"- Users with discrepancies: {len(discrepancies)}\n")
        f.write(f"- Users in accurate file but not in dumps: {len(users_not_in_dumps)}\n")
        f.write(f"- Users in dumps but not in accurate file: {len(users_not_in_accurate)}\n")
        
        # Users with discrepancies
        if discrepancies:
            f.write("\n## Users with Hash Discrepancies\n\n")
            f.write("| Username | Issue | Accurate Data | Dump Data | Sources |\n")
            f.write("|----------|-------|--------------|-----------|--------|\n")
            
            for discrepancy in discrepancies:
                username = discrepancy["username"]
                issue_type = ", ".join(discrepancy["issue_type"])
                accurate_data_str = f"NTLM: {discrepancy['accurate_data']['ntlm'] or 'None'}, LM: {discrepancy['accurate_data']['lm'] or 'None'}"
                dump_data_str = f"NTLM: {', '.join(discrepancy['dump_data']['ntlm']) or 'None'}, LM: {', '.join(discrepancy['dump_data']['lm']) or 'None'}"
                sources = ", ".join(discrepancy["sources"])
                
                f.write(f"| {username} | {issue_type} | {accurate_data_str} | {dump_data_str} | {sources} |\n")
        
        # Users not in dumps
        if users_not_in_dumps:
            f.write("\n## Users in Accurate File but Not in Dumps\n\n")
            f.write("| Username | NTLM | LM | Password |\n")
            f.write("|----------|------|----|---------|\n")
            
            for user in users_not_in_dumps[:30]:  # Limit to 30 entries
                username = user["username"]
                ntlm = user["accurate_data"]["ntlm"] or "None"
                lm = user["accurate_data"]["lm"] or "None"
                password = user["password"] or "None"
                
                f.write(f"| {username} | {ntlm} | {lm} | {password} |\n")
                
            if len(users_not_in_dumps) > 30:
                f.write(f"\n*... and {len(users_not_in_dumps) - 30} more users*\n")
        
        # Users not in accurate file
        if users_not_in_accurate:
            f.write("\n## Users in Dumps but Not in Accurate File\n\n")
            f.write("| Username | NTLM | LM | Sources |\n")
            f.write("|----------|------|----|---------|\n")
            
            for user in users_not_in_accurate[:30]:  # Limit to 30 entries
                username = user["username"]
                ntlm = ", ".join(user["dump_data"]["ntlm"]) or "None"
                lm = ", ".join(user["dump_data"]["lm"]) or "None"
                sources = ", ".join(user["sources"])
                
                f.write(f"| {username} | {ntlm} | {lm} | {sources} |\n")
                
            if len(users_not_in_accurate) > 30:
                f.write(f"\n*... and {len(users_not_in_accurate) - 30} more users*\n")
        
        # Verified users section
        f.write("\n## Verified Users (Sample)\n\n")
        sample_size = min(10, len(verified_users))
        
        f.write(f"The following {sample_size} users (out of {len(verified_users)}) were verified to have accurate hash data:\n\n")
        for username in verified_users[:sample_size]:
            f.write(f"- {username}\n")
        
        # Conclusion
        f.write("\n## Conclusion\n\n")
        accuracy_pct = (len(verified_users) / len(accurate_data)) * 100 if accurate_data else 0
        f.write(f"The hash data is {accuracy_pct:.2f}% accurate based on verification against the original dumps.\n")
        
        if discrepancies:
            f.write("\nDiscrepancies need to be reviewed and corrected to ensure 100% accuracy.\n")
        else:
            f.write("\nNo discrepancies found. The hash data appears to be completely accurate.\n")
    
    print(f"Verification complete! Report written to {validation_report}")
    return {
        "discrepancies": discrepancies,
        "verified_users": verified_users,
        "users_not_in_dumps": users_not_in_dumps,
        "users_not_in_accurate": users_not_in_accurate
    }

if __name__ == "__main__":
    results = verify_user_hash_data()
    
    # Print summary to console
    print("\n=== VERIFICATION SUMMARY ===")
    print(f"Verified users: {len(results['verified_users'])}")
    print(f"Users with discrepancies: {len(results['discrepancies'])}")
    print(f"Users not found in dumps: {len(results['users_not_in_dumps'])}")
    print(f"Users not in accurate file: {len(results['users_not_in_accurate'])}")
    print(f"\nFull report written to {validation_report}")
