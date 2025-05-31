#!/usr/bin/env python3
"""
Improved User Hash Validator

This script performs a detailed validation of each user's hash data by:
1. Using improved extraction methods from the fix_hash_integrity.py script
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

def extract_hash_from_mimikatz(filename):
    """Extract NTLM and LM hashes from mimikatz dump files using improved methods."""
    print(f"Extracting from {os.path.basename(filename)}...")
    users_data = defaultdict(dict)
    
    try:
        # Try different encodings
        content = None
        for encoding in ['utf-8', 'latin-1', 'utf-16-le']:
            try:
                with open(filename, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if not content:
            print(f"Failed to read {filename} with any encoding")
            return users_data
        
        # Split by RID sections which separate user entries
        rid_pattern = r'RID\s+:\s+[0-9a-fA-F]+\s+\(\d+\)'
        rid_matches = list(re.finditer(rid_pattern, content))
        
        for i, match in enumerate(rid_matches):
            start_pos = match.end()
            end_pos = rid_matches[i+1].start() if i+1 < len(rid_matches) else len(content)
            section = content[start_pos:end_pos]
            
            # Extract username
            user_match = re.search(r'User\s+:\s+([^\r\n]+)', section)
            if not user_match:
                continue
                
            username = user_match.group(1).strip()
            
            # Skip built-in accounts
            if username.lower() in ['administrator', 'guest', 'defaultaccount', '(null)', 'local service', 'network service']:
                continue
                
            username = username.lower()
            
            # Extract NTLM hash - using explicit "Hash NTLM" pattern
            ntlm_match = re.search(r'Hash\s+NTLM(?:\s+)?:\s+([0-9a-fA-F]{32})', section)
            ntlm_hash = ntlm_match.group(1).lower() if ntlm_match else ""
            
            # Extract LM hash - using explicit "Hash LM" pattern
            lm_match = re.search(r'Hash\s+LM(?:\s+)?:\s+([0-9a-fA-F]{32})', section)
            lm_hash = lm_match.group(1).lower() if lm_match else ""
            
            # Skip empty LM hashes (aad3b435b51404eeaad3b435b51404ee)
            if lm_hash.lower() == "aad3b435b51404eeaad3b435b51404ee":
                lm_hash = ""
            
            # Store user data
            users_data[username] = {
                'ntlm': ntlm_hash,
                'lm': lm_hash,
                'source': os.path.basename(filename)
            }
            
        # Also try the older wdigest pattern which appears in some dumps
        wdigest_sections = re.split(r'Authentication\s+Id\s+:\s+\d+\s*;\s*\d+', content)
        
        for section in wdigest_sections[1:]:  # Skip the first split which is before any match
            user_match = re.search(r'User\s+Name\s*:\s*([^\r\n]+)', section)
            if not user_match:
                continue
                
            username = user_match.group(1).strip()
            if not username or username.lower() in ['(null)', 'local service', 'network service']:
                continue
                
            username = username.lower()
            
            # Handle domain prefixes
            if '\\' in username:
                username = username.split('\\')[-1]
            
            # Extract NTLM hash
            ntlm_match = re.search(r'NTLM\s*:\s*([0-9a-fA-F]{32})', section)
            ntlm_hash = ntlm_match.group(1).lower() if ntlm_match else ""
            
            # Extract LM hash
            lm_match = re.search(r'LM\s*:\s*([0-9a-fA-F]{32})', section)
            lm_hash = lm_match.group(1).lower() if lm_match else ""
            
            # Skip empty LM hashes
            if lm_hash.lower() == "aad3b435b51404eeaad3b435b51404ee":
                lm_hash = ""
            
            if ntlm_hash:  # Only add if we found an NTLM hash
                # Update existing user or add new
                if username in users_data:
                    if not users_data[username]['ntlm'] and ntlm_hash:
                        users_data[username]['ntlm'] = ntlm_hash
                    if not users_data[username]['lm'] and lm_hash:
                        users_data[username]['lm'] = lm_hash
                else:
                    users_data[username] = {
                        'ntlm': ntlm_hash,
                        'lm': lm_hash,
                        'source': os.path.basename(filename)
                    }
        
        print(f"  Found {len(users_data)} users in {os.path.basename(filename)}")
        return users_data
        
    except Exception as e:
        print(f"Error processing {filename}: {str(e)}")
        return users_data

def extract_all_hash_data():
    """Extract hash data from all mimikatz dump files"""
    print("Extracting hash data from mimikatz dumps...")
    
    all_users = {}
    
    for mimikatz_file in mimikatz_files:
        if not os.path.exists(mimikatz_file):
            print(f"Warning: Mimikatz file not found: {mimikatz_file}")
            continue
            
        users_data = extract_hash_from_mimikatz(mimikatz_file)
        
        # Merge with existing data
        for username, data in users_data.items():
            if username in all_users:
                # Keep original data if it has values not in the new data
                if not all_users[username]['ntlm'] and data['ntlm']:
                    all_users[username]['ntlm'] = data['ntlm']
                if not all_users[username]['lm'] and data['lm']:
                    all_users[username]['lm'] = data['lm']
                # Update source
                all_users[username]['source'] += f", {data['source']}"
            else:
                all_users[username] = data
    
    print(f"Total unique users found: {len(all_users)}")
    return all_users

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
    dump_data = extract_all_hash_data()
    
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
            dump_ntlm = dump_data[username]["ntlm"]
            dump_lm = dump_data[username]["lm"]
            acc_ntlm = acc_data["ntlm"]
            acc_lm = acc_data["lm"]
            
            has_discrepancy = False
            discrepancy_details = {
                "username": username,
                "issue_type": [],
                "accurate_data": {"ntlm": acc_ntlm, "lm": acc_lm},
                "dump_data": {"ntlm": dump_ntlm, "lm": dump_lm},
                "source": dump_data[username]["source"]
            }
            
            # Check NTLM hash
            if acc_ntlm and dump_ntlm and acc_ntlm != dump_ntlm:
                has_discrepancy = True
                discrepancy_details["issue_type"].append("NTLM hash mismatch")
            
            # Check LM hash
            if acc_lm and dump_lm and acc_lm != dump_lm:
                has_discrepancy = True
                discrepancy_details["issue_type"].append("LM hash mismatch")
            elif acc_lm and not dump_lm:
                has_discrepancy = True
                discrepancy_details["issue_type"].append("LM hash in accurate file but not in dump")
            elif not acc_lm and dump_lm:
                has_discrepancy = True
                discrepancy_details["issue_type"].append("LM hash in dump but not in accurate file")
            
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
                "source": dump_data_user["source"]
            })
    
    # Generate report
    with open(validation_report, 'w') as f:
        f.write("# User Hash Verification Report\n\n")
        f.write("This report verifies each user's hash data against the original Mimikatz dumps.\n\n")
        
        # Summary stats
        f.write("## Summary\n\n")
        f.write(f"- Total users in accurate file: {len(accurate_data)}\n")
        f.write(f"- Total users found in dumps: {len(dump_data)}\n")
        f.write(f"- Users verified as accurate: {len(verified_users)} ({(len(verified_users)/len(accurate_data))*100:.1f}%)\n")
        f.write(f"- Users with discrepancies: {len(discrepancies)}\n")
        f.write(f"- Users in accurate file but not in dumps: {len(users_not_in_dumps)}\n")
        f.write(f"- Users in dumps but not in accurate file: {len(users_not_in_accurate)}\n")
        
        # Users with discrepancies
        if discrepancies:
            f.write("\n## Users with Hash Discrepancies\n\n")
            f.write("| Username | Issue | Accurate Data | Dump Data | Source |\n")
            f.write("|----------|-------|--------------|-----------|--------|\n")
            
            for discrepancy in discrepancies:
                username = discrepancy["username"]
                issue_type = ", ".join(discrepancy["issue_type"])
                accurate_data_str = f"NTLM: {discrepancy['accurate_data']['ntlm'] or 'None'}, LM: {discrepancy['accurate_data']['lm'] or 'None'}"
                dump_data_str = f"NTLM: {discrepancy['dump_data']['ntlm'] or 'None'}, LM: {discrepancy['dump_data']['lm'] or 'None'}"
                source = discrepancy["source"]
                
                f.write(f"| {username} | {issue_type} | {accurate_data_str} | {dump_data_str} | {source} |\n")
        
        # Users not in dumps (sample)
        if users_not_in_dumps:
            f.write("\n## Users in Accurate File but Not in Dumps (Sample)\n\n")
            f.write("| Username | NTLM | LM | Password |\n")
            f.write("|----------|------|----|---------|\n")
            
            for user in users_not_in_dumps[:20]:  # Limit to 20 entries
                username = user["username"]
                ntlm = user["accurate_data"]["ntlm"] or "None"
                lm = user["accurate_data"]["lm"] or "None"
                password = user["password"] or "None"
                
                f.write(f"| {username} | {ntlm} | {lm} | {password} |\n")
                
            if len(users_not_in_dumps) > 20:
                f.write(f"\n*... and {len(users_not_in_dumps) - 20} more users*\n")
        
        # Users not in accurate file (sample)
        if users_not_in_accurate:
            f.write("\n## Users in Dumps but Not in Accurate File (Sample)\n\n")
            f.write("| Username | NTLM | LM | Source |\n")
            f.write("|----------|------|----|---------|\n")
            
            for user in users_not_in_accurate[:20]:  # Limit to 20 entries
                username = user["username"]
                ntlm = user["dump_data"]["ntlm"] or "None"
                lm = user["dump_data"]["lm"] or "None"
                source = user["source"]
                
                f.write(f"| {username} | {ntlm} | {lm} | {source} |\n")
                
            if len(users_not_in_accurate) > 20:
                f.write(f"\n*... and {len(users_not_in_accurate) - 20} more users*\n")
        
        # Verified users section (sample)
        if verified_users:
            f.write("\n## Verified Users (Sample)\n\n")
            sample_size = min(20, len(verified_users))
            
            f.write(f"The following {sample_size} users (out of {len(verified_users)}) were verified to have accurate hash data:\n\n")
            for username in verified_users[:sample_size]:
                f.write(f"- {username}\n")
        
        # Special checks for critical users
        f.write("\n## Special Checks for Critical Users\n\n")
        
        # Jean-Marc Samson check
        jean_marc = "jean-marc.samson"
        jean_marc_accurate = jean_marc in accurate_data
        jean_marc_dump = jean_marc in dump_data
        
        f.write("### Jean-Marc Samson Check\n\n")
        if jean_marc_accurate:
            acc_ntlm = accurate_data[jean_marc]["ntlm"]
            acc_lm = accurate_data[jean_marc]["lm"] or "None"
            f.write(f"- Found in accurate file: ✓ (NTLM: {acc_ntlm}, LM: {acc_lm})\n")
        else:
            f.write("- Found in accurate file: ✗\n")
            
        if jean_marc_dump:
            dump_ntlm = dump_data[jean_marc]["ntlm"]
            dump_lm = dump_data[jean_marc]["lm"] or "None"
            f.write(f"- Found in dumps: ✓ (NTLM: {dump_ntlm}, LM: {dump_lm})\n")
        else:
            f.write("- Found in dumps: ✗\n")
            
        # Ashley Williams check
        ashley = "ashleywilliams"
        ashley_accurate = ashley in accurate_data
        ashley_dump = ashley in dump_data
        
        f.write("\n### Ashley Williams Check\n\n")
        if ashley_accurate:
            acc_ntlm = accurate_data[ashley]["ntlm"]
            acc_lm = accurate_data[ashley]["lm"] or "None"
            f.write(f"- Found in accurate file: ✓ (NTLM: {acc_ntlm}, LM: {acc_lm})\n")
        else:
            f.write("- Found in accurate file: ✗\n")
            
        if ashley_dump:
            dump_ntlm = dump_data[ashley]["ntlm"]
            dump_lm = dump_data[ashley]["lm"] or "None"
            f.write(f"- Found in dumps: ✓ (NTLM: {dump_ntlm}, LM: {dump_lm})\n")
        else:
            f.write("- Found in dumps: ✗\n")
        
        # Conclusion
        f.write("\n## Conclusion\n\n")
        accuracy_pct = (len(verified_users) / len(accurate_data)) * 100 if accurate_data else 0
        f.write(f"The hash data is {accuracy_pct:.2f}% accurate based on verification against the original dumps.\n")
        
        if discrepancies:
            f.write("\nDiscrepancies need to be reviewed and corrected to ensure 100% accuracy.\n")
            f.write("\nNote: Some users appearing only in the accurate file might be from other data sources not included in the current Mimikatz dumps.\n")
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
    print(f"Verified users: {len(results['verified_users'])} ({(len(results['verified_users'])/len(results['verified_users']) + len(results['discrepancies']))*100:.1f}% match)")
    print(f"Users with discrepancies: {len(results['discrepancies'])}")
    print(f"Users not found in dumps: {len(results['users_not_in_dumps'])}")
    print(f"Users not in accurate file: {len(results['users_not_in_accurate'])}")
    print(f"\nFull report written to {validation_report}")
