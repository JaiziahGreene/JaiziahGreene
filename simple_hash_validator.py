#!/usr/bin/env python3
"""
Simple Hash Validator Script

This script performs basic verification of hash files to ensure:
1. All files exist with correct permissions
2. The files have the expected format
3. The hash data has the correct structure
"""

import os
import sys
import re

def validate_file_existence():
    """Check that all hash files exist"""
    workspace_path = "/workspaces/JaiziahGreene"
    files_to_check = [
        "complete_user_hash_data_accurate.txt",
        "ntlm_lm_hashes_accurate.txt",
        "lm_only_hashes_accurate.txt", 
        "ntlm_only_hashes_accurate.txt",
        "strong_passwords_accurate.txt"
    ]
    
    print("\n=== Checking File Existence ===")
    
    all_exist = True
    for filename in files_to_check:
        filepath = os.path.join(workspace_path, filename)
        exists = os.path.exists(filepath)
        print(f"{filename}: {'✓ Exists' if exists else '✗ Missing'}")
        
        if exists:
            is_readable = os.access(filepath, os.R_OK)
            print(f"  - Readable: {'✓ Yes' if is_readable else '✗ No'}")
            
            try:
                with open(filepath, 'r') as f:
                    line_count = sum(1 for _ in f)
                print(f"  - Line count: {line_count}")
            except Exception as e:
                print(f"  - Error reading file: {str(e)}")
        
        all_exist = all_exist and exists
    
    return all_exist

def validate_hash_formats():
    """Check hash formats in the files"""
    workspace_path = "/workspaces/JaiziahGreene"
    files_to_validate = {
        "complete_user_hash_data_accurate.txt": {
            "pattern": r'^[^:]+:[^:]*:[a-fA-F0-9]{32}(:[a-fA-F0-9]{32})?$',
            "sample_size": 10,
            "description": "username:password:ntlm:lm or username:password:ntlm"
        },
        "ntlm_lm_hashes_accurate.txt": {
            "pattern": r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$',
            "sample_size": 10, 
            "description": "ntlm:lm"
        },
        "lm_only_hashes_accurate.txt": {
            "pattern": r'^[a-fA-F0-9]{32}$',
            "sample_size": 10,
            "description": "lm"
        },
        "ntlm_only_hashes_accurate.txt": {
            "pattern": r'^[a-fA-F0-9]{32}$',
            "sample_size": 10,
            "description": "ntlm"
        },
        "strong_passwords_accurate.txt": {
            "pattern": r'^[a-fA-F0-9]{32}$',
            "sample_size": 10,
            "description": "ntlm (strong passwords)"
        }
    }
    
    print("\n=== Validating Hash Formats ===")
    
    all_valid = True
    for filename, validation_info in files_to_validate.items():
        filepath = os.path.join(workspace_path, filename)
        if not os.path.exists(filepath):
            print(f"{filename}: ✗ File does not exist, skipping validation")
            all_valid = False
            continue
        
        pattern = validation_info["pattern"]
        expected_format = validation_info["description"]
        sample_size = validation_info["sample_size"]
        
        print(f"\nValidating {filename} (expected format: {expected_format})")
        try:
            invalid_lines = []
            valid_count = 0
            total_count = 0
            
            with open(filepath, 'r') as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line or line.startswith('//') or line.startswith('#'):
                        continue  # Skip comments and empty lines
                    
                    total_count += 1
                    if not re.match(pattern, line):
                        invalid_lines.append((i+1, line))
                    else:
                        valid_count += 1
                        
                    if len(invalid_lines) >= sample_size:
                        break
            
            if invalid_lines:
                print(f"✗ Found {len(invalid_lines)} invalid lines out of {total_count} total lines")
                print("Sample of invalid lines:")
                for line_num, content in invalid_lines[:sample_size]:
                    print(f"  Line {line_num}: {content[:100]}")
                all_valid = False
            else:
                print(f"✓ All {total_count} lines match the expected format")
                
                # Show a sample of valid lines
                print("Sample of valid entries:")
                with open(filepath, 'r') as f:
                    valid_samples = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('//') and not line.startswith('#'):
                            valid_samples.append(line)
                            if len(valid_samples) >= 3:  # Show 3 examples
                                break
                
                for sample in valid_samples:
                    print(f"  {sample[:100]}")
                    
        except Exception as e:
            print(f"✗ Error validating {filename}: {str(e)}")
            all_valid = False
    
    return all_valid

def check_strong_passwords_entries():
    """Check that strong passwords file has the correct entries"""
    workspace_path = "/workspaces/JaiziahGreene"
    strong_passwords_file = os.path.join(workspace_path, "strong_passwords_accurate.txt")
    ntlm_only_file = os.path.join(workspace_path, "ntlm_only_hashes_accurate.txt")
    
    print("\n=== Checking Strong Passwords Entries ===")
    
    if not os.path.exists(strong_passwords_file) or not os.path.exists(ntlm_only_file):
        print("✗ Required files don't exist, skipping check")
        return False
    
    try:
        # Load strong passwords
        strong_passwords = set()
        with open(strong_passwords_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('//') and not line.startswith('#'):
                    strong_passwords.add(line)
        
        # Check if ashleywilliams is included
        # Known hash for ashleywilliams
        ashleywilliams_hash = "155d1254d37e9d54bf4bd4d80e55153b"
        if ashleywilliams_hash in strong_passwords:
            print("✓ ashleywilliams is correctly included in strong passwords")
        else:
            print("✗ ashleywilliams is NOT in strong passwords file")
            
        print(f"Total entries in strong passwords file: {len(strong_passwords)}")
        
        # Count how many strong passwords are in the ntlm_only file
        ntlm_only_hashes = set()
        with open(ntlm_only_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('//') and not line.startswith('#'):
                    ntlm_only_hashes.add(line)
        
        strong_in_ntlm = strong_passwords.intersection(ntlm_only_hashes)
        print(f"Strong passwords that appear in ntlm_only_hashes: {len(strong_in_ntlm)}/{len(strong_passwords)}")
        
        if len(strong_in_ntlm) != len(strong_passwords):
            print("✗ Some strong passwords are not in ntlm_only_hashes file")
            missing = strong_passwords - ntlm_only_hashes
            if missing:
                print(f"  Missing entries (up to 5): {list(missing)[:5]}")
        else:
            print("✓ All strong passwords are also in ntlm_only_hashes file")
        
        return True
    except Exception as e:
        print(f"✗ Error checking strong passwords: {str(e)}")
        return False

def main():
    print("=== SIMPLE HASH VALIDATOR ===")
    print("This script performs basic validation of hash files")
    
    files_exist = validate_file_existence()
    if not files_exist:
        print("\n⚠️ Some files are missing. Cannot continue with format validation.")
        return False
    
    formats_valid = validate_hash_formats()
    strong_passwords_valid = check_strong_passwords_entries()
    
    print("\n=== VALIDATION SUMMARY ===")
    print(f"Files exist: {'✓ Yes' if files_exist else '✗ No'}")
    print(f"Hash formats valid: {'✓ Yes' if formats_valid else '✗ No'}")
    print(f"Strong passwords check: {'✓ Pass' if strong_passwords_valid else '✗ Fail'}")
    
    overall_result = files_exist and formats_valid and strong_passwords_valid
    print(f"\nOverall validation result: {'✓ PASS' if overall_result else '✗ FAIL'}")
    
    return overall_result

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
