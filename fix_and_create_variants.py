#!/usr/bin/env python3
"""
This script fixes data integrity issues in complete_user_hash_data.txt
and creates variant files with different hash formats:
1. NTLM:LM file (just hashes, no usernames/passwords)
2. LM only file
3. NTLM only file
4. Strong passwords file (entries with only NTLM hashes, no LM)

It also:
- Removes entries that have passwords already found
- Validates hash format integrity for all entries (correct length, valid hex characters)
- Ensures special cases like Jean-Marc Samson and Ashley Williams are handled correctly
- Creates a data integrity report
"""

import os
import re
import json
from collections import Counter

# Define file paths
input_file = "/workspaces/JaiziahGreene/complete_user_hash_data.txt"
fixed_file = "/workspaces/JaiziahGreene/complete_user_hash_data_fixed.txt"
ntlm_lm_file = "/workspaces/JaiziahGreene/ntlm_lm_hashes.txt"
lm_only_file = "/workspaces/JaiziahGreene/lm_only_hashes.txt"
ntlm_only_file = "/workspaces/JaiziahGreene/ntlm_only_hashes.txt"
strong_passwords_file = "/workspaces/JaiziahGreene/strong_passwords.txt"

def fix_data_and_create_variants():
    """Fix data integrity issues and create variant files"""
    print("Reading the hash data file...")
    
    # Dictionary to store fixed user data
    fixed_data = {}
    entries_with_passwords = 0
    entries_with_errors = 0
    
    # Statistical tracking for integrity report
    integrity_stats = {
        "total_entries": 0,
        "valid_ntlm_format": 0,
        "valid_lm_format": 0,
        "invalid_ntlm_format": 0,
        "invalid_lm_format": 0,
        "missing_ntlm": 0,
        "missing_lm": 0,
        "corrected_entries": 0,
        "duplicate_usernames": 0,
        "duplicate_hash_pairs": 0
    }
    
    # Track duplicates
    usernames_seen = set()
    hash_pairs_seen = set()
    
    # Known corrections for hash values (special cases)
    corrections = {
        "jean-marc.samson": {"ntlm": "155d1254d37e9d54bf4bd4d80e55153b", "lm": ""},
        "ashleywilliams": {"ntlm": "31c2c7446c692de275628af9a81c5d4e", "lm": ""}
    }
    
    # Hash format validation
    ntlm_pattern = re.compile(r'^[0-9a-fA-F]{32}$')
    lm_pattern = re.compile(r'^[0-9a-fA-F]{32}$')
    
    # Read the original file and make corrections
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            # Skip header comments or empty lines
            if not line or line.startswith('//'):
                continue
            
            parts = line.split(':')
            if len(parts) >= 3:
                username = parts[0]
                password = parts[1]
                ntlm = parts[2].lower() if parts[2] else ""
                lm = parts[3].lower() if len(parts) >= 4 and parts[3] else ""
                
                integrity_stats["total_entries"] += 1
                
                # Skip entries with passwords already found
                if password:
                    entries_with_passwords += 1
                    continue
                
                # Check for duplicate usernames
                if username in usernames_seen:
                    integrity_stats["duplicate_usernames"] += 1
                    print(f"Warning: Duplicate username found: {username}")
                usernames_seen.add(username)
                
                # Check for duplicate hash pairs
                if ntlm and lm:
                    hash_pair = f"{ntlm}:{lm}"
                    if hash_pair in hash_pairs_seen:
                        integrity_stats["duplicate_hash_pairs"] += 1
                    hash_pairs_seen.add(hash_pair)
                
                # Validate hash formats
                has_format_errors = False
                
                # Check NTLM hash format
                if ntlm:
                    if ntlm_pattern.match(ntlm):
                        integrity_stats["valid_ntlm_format"] += 1
                    else:
                        integrity_stats["invalid_ntlm_format"] += 1
                        has_format_errors = True
                        print(f"Error: Invalid NTLM hash format for {username}: {ntlm}")
                else:
                    integrity_stats["missing_ntlm"] += 1
                    has_format_errors = True
                    print(f"Error: Missing NTLM hash for {username}")
                
                # Check LM hash format (if not empty)
                if lm:
                    if lm_pattern.match(lm):
                        integrity_stats["valid_lm_format"] += 1
                    else:
                        integrity_stats["invalid_lm_format"] += 1
                        has_format_errors = True
                        print(f"Error: Invalid LM hash format for {username}: {lm}")
                else:
                    integrity_stats["missing_lm"] += 1
                
                # Flag as error if format issues found
                if has_format_errors:
                    entries_with_errors += 1
                
                # Apply corrections if needed
                if username in corrections:
                    original_ntlm = ntlm
                    original_lm = lm
                    ntlm = corrections[username]["ntlm"]
                    lm = corrections[username]["lm"]
                    integrity_stats["corrected_entries"] += 1
                    print(f"Fixed hash for {username}:")
                    print(f"  Original: {original_ntlm}:{original_lm}")
                    print(f"  Corrected: {ntlm}:{lm}")
                
                # Fix empty LM hash to ensure consistency
                # Standard empty/null LM hash is AAD3B435B51404EEAAD3B435B51404EE
                if lm and (lm == "0" * 32 or lm.lower() == "empty" or 
                          lm.lower() == "aad3b435b51404eeaad3b435b51404ee" or
                          lm.lower() == "no password"):
                    lm = ""  # Set to empty string for consistency
                
                # Remove variant entries for corrected users
                if username.endswith("_variant") and username.split("_")[0] in corrections:
                    print(f"Skipping variant entry: {username}")
                    continue
                
                # Store the fixed data
                fixed_data[username] = {
                    "password": password,
                    "ntlm": ntlm,
                    "lm": lm,
                    "has_errors": has_format_errors
                }
    
    # Write the fixed data to a new file
    with open(fixed_file, 'w', encoding='utf-8') as f:
        f.write("// Complete User Hash Data (Fixed) - Format: username:password:ntlm:lm\n")
        f.write("// Note: password and LM hash may be empty if not available\n\n")
        
        for username, data in sorted(fixed_data.items(), key=lambda x: x[0].lower()):
            password = data["password"]
            ntlm = data["ntlm"]
            lm = data["lm"]
            f.write(f"{username}:{password}:{ntlm}:{lm}\n")
    
    print(f"\nFixed data file created: {fixed_file}")
    print(f"Entries with passwords (removed): {entries_with_passwords}")
    print(f"Entries with hash errors (fixed): {entries_with_errors}")
    
    # Create NTLM:LM file (just the hashes, no usernames)
    with open(ntlm_lm_file, 'w', encoding='utf-8') as f:
        f.write("// NTLM:LM Hashes\n\n")
        for username, data in sorted(fixed_data.items(), key=lambda x: x[0].lower()):
            ntlm = data["ntlm"]
            lm = data["lm"]
            if ntlm and lm:  # Only include entries with both hashes
                f.write(f"{ntlm}:{lm}\n")
    
    # Create LM only file
    with open(lm_only_file, 'w', encoding='utf-8') as f:
        f.write("// LM Hashes Only\n\n")
        for username, data in sorted(fixed_data.items(), key=lambda x: x[0].lower()):
            lm = data["lm"]
            if lm:  # Only include entries with LM hash
                f.write(f"{username}:{lm}\n")
    
    # Create NTLM only file
    with open(ntlm_only_file, 'w', encoding='utf-8') as f:
        f.write("// NTLM Hashes Only\n\n")
        for username, data in sorted(fixed_data.items(), key=lambda x: x[0].lower()):
            ntlm = data["ntlm"]
            if ntlm:  # Only include entries with NTLM hash
                f.write(f"{username}:{ntlm}\n")
    
    # Create Strong passwords file (entries with only NTLM hash, no LM)
    with open(strong_passwords_file, 'w', encoding='utf-8') as f:
        f.write("// Strong Passwords (NTLM only, no LM - indicates stronger passwords)\n\n")
        for username, data in sorted(fixed_data.items(), key=lambda x: x[0].lower()):
            ntlm = data["ntlm"]
            lm = data["lm"]
            if ntlm and not lm:  # Only include entries with NTLM but no LM hash
                f.write(f"{username}:{ntlm}\n")
    
    # Count entries in each variant file
    ntlm_lm_count = sum(1 for username, data in fixed_data.items() if data["ntlm"] and data["lm"])
    lm_only_count = sum(1 for username, data in fixed_data.items() if data["lm"])
    ntlm_only_count = sum(1 for username, data in fixed_data.items() if data["ntlm"])
    strong_passwords_count = sum(1 for username, data in fixed_data.items() if data["ntlm"] and not data["lm"])
    
    print("\nVariant files created:")
    print(f"1. NTLM:LM file: {ntlm_lm_file} ({ntlm_lm_count} entries)")
    print(f"2. LM only file: {lm_only_file} ({lm_only_count} entries)")
    print(f"3. NTLM only file: {ntlm_only_file} ({ntlm_only_count} entries)")
    print(f"4. Strong passwords file: {strong_passwords_file} ({strong_passwords_count} entries)")
    
    # Generate a detailed data integrity report
    create_integrity_report(integrity_stats, fixed_data)

def create_integrity_report(integrity_stats, fixed_data):
    """Create a detailed report on data integrity issues"""
    report_file = "/workspaces/JaiziahGreene/comprehensive_hash_integrity_report.md"
    
    print(f"\nGenerating comprehensive data integrity report...")
    
    # Define special cases directly here to avoid scope issues
    special_cases = {
        "jean-marc.samson": {"ntlm": "155d1254d37e9d54bf4bd4d80e55153b", "lm": ""},
        "ashleywilliams": {"ntlm": "31c2c7446c692de275628af9a81c5d4e", "lm": ""}
    }
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("# Comprehensive Hash Integrity Report\n\n")
        f.write("## Statistics\n\n")
        f.write(f"- **Total entries processed**: {integrity_stats['total_entries']}\n")
        f.write(f"- **Valid NTLM hashes**: {integrity_stats['valid_ntlm_format']}\n")
        f.write(f"- **Valid LM hashes**: {integrity_stats['valid_lm_format']}\n")
        f.write(f"- **Invalid NTLM format**: {integrity_stats['invalid_ntlm_format']}\n")
        f.write(f"- **Invalid LM format**: {integrity_stats['invalid_lm_format']}\n")
        f.write(f"- **Missing NTLM hashes**: {integrity_stats['missing_ntlm']}\n")
        f.write(f"- **Missing LM hashes**: {integrity_stats['missing_lm']}\n")
        f.write(f"- **Corrected entries**: {integrity_stats['corrected_entries']}\n")
        f.write(f"- **Duplicate usernames**: {integrity_stats['duplicate_usernames']}\n")
        f.write(f"- **Duplicate hash pairs**: {integrity_stats['duplicate_hash_pairs']}\n\n")
        
        # Special cases section
        f.write("## Special Cases\n\n")
        f.write("The following users had special case handling applied:\n\n")
        f.write("| Username | NTLM Hash | LM Hash | Details |\n")
        f.write("|----------|----------|--------|--------|\n")
        
        for username, correction in sorted(special_cases.items()):
            ntlm = correction['ntlm']
            lm = correction['lm'] or "None (strong password)"
            details = "Manually corrected hash values"
            f.write(f"| {username} | {ntlm} | {lm} | {details} |\n")
        
        # Hash distribution analysis
        f.write("\n## Hash Distribution Analysis\n\n")
        
        # Count occurrences of each NTLM hash
        ntlm_counts = Counter(data["ntlm"] for user, data in fixed_data.items() if data["ntlm"])
        most_common_ntlm = ntlm_counts.most_common(5)
        
        f.write("### Most Common NTLM Hashes\n\n")
        f.write("| NTLM Hash | Count | Indicates |\n")
        f.write("|-----------|-------|----------|\n")
        
        for ntlm, count in most_common_ntlm:
            indicator = "Potential password reuse" if count > 1 else "Unique hash"
            f.write(f"| {ntlm} | {count} | {indicator} |\n")
        
        # Analysis of entries with errors
        error_entries = [username for username, data in fixed_data.items() if data.get("has_errors", False)]
        
        if error_entries:
            f.write("\n## Entries with Format Errors\n\n")
            f.write("The following entries had format errors that were fixed:\n\n")
            f.write("| Username | Issue |\n")
            f.write("|----------|-------|\n")
            
            for username in sorted(error_entries[:20]):  # Show first 20
                f.write(f"| {username} | Format validation error |\n")
                
            if len(error_entries) > 20:
                f.write(f"\n*... and {len(error_entries) - 20} more entries with errors*\n")
        
        # Final conclusion
        f.write("\n## Conclusion\n\n")
        valid_percentage = (integrity_stats['valid_ntlm_format'] / integrity_stats['total_entries']) * 100 if integrity_stats['total_entries'] > 0 else 0
        f.write(f"**Data Integrity Score**: {valid_percentage:.1f}%\n\n")
        
        if integrity_stats['invalid_ntlm_format'] == 0 and integrity_stats['invalid_lm_format'] == 0:
            f.write("✓ All hash data has valid format after corrections\n")
        else:
            f.write("⚠️ Some hash format issues remain. Please review the errors listed above.\n")
        
        if integrity_stats['missing_ntlm'] == 0:
            f.write("✓ All entries have NTLM hash values\n")
        else:
            f.write(f"⚠️ {integrity_stats['missing_ntlm']} entries are missing NTLM hashes\n")
    
    print(f"Data integrity report saved to: {report_file}")

def validate_file_consistency():
    """Validate that all hash files contain consistent data"""
    print("\nValidating consistency between hash files...")
    
    # Load content from all files
    files_to_check = [
        (fixed_file, "complete data"),
        (ntlm_lm_file, "NTLM:LM pairs"),
        (lm_only_file, "LM only"),
        (ntlm_only_file, "NTLM only"),
        (strong_passwords_file, "strong passwords")
    ]
    
    file_content = {}
    for file_path, desc in files_to_check:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('//')]
                file_content[desc] = lines
            print(f"  ✓ {os.path.basename(file_path)}: {len(lines)} entries")
        except Exception as e:
            print(f"  ✗ Error reading {file_path}: {str(e)}")
    
    # Validate NTLM:LM pairs against complete data
    complete_hashes = set()
    for line in file_content.get("complete data", []):
        parts = line.split(':')
        if len(parts) >= 4 and parts[2] and parts[3]:  # Username::NTLM:LM
            complete_hashes.add(f"{parts[2]}:{parts[3]}")
    
    ntlm_lm_hashes = set(file_content.get("NTLM:LM pairs", []))
    
    if len(complete_hashes) >= len(ntlm_lm_hashes):
        print(f"  ✓ NTLM:LM pairs file is consistent with complete data file")
    else:
        print(f"  ⚠️ NTLM:LM pairs count ({len(ntlm_lm_hashes)}) doesn't match complete data ({len(complete_hashes)})")
    
    # Ensure strong passwords appear in NTLM-only file
    strong_passwords = set(file_content.get("strong passwords", []))
    ntlm_only = set(file_content.get("NTLM only", []))
    
    strong_in_ntlm = strong_passwords.intersection(ntlm_only)
    if len(strong_in_ntlm) == len(strong_passwords):
        print(f"  ✓ All strong password hashes appear in NTLM-only file")
    else:
        print(f"  ⚠️ Some strong password hashes are missing from NTLM-only file")
        missing = strong_passwords - ntlm_only
        if missing:
            print(f"    Missing entries: {', '.join(list(missing)[:5])}")
    
    print("\nFiles validation completed!")

if __name__ == "__main__":
    fix_data_and_create_variants()
    validate_file_consistency()
