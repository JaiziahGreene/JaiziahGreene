#!/usr/bin/env python3
"""
Hash Variants Verification Script

This script verifies that all hash variants have the correct format and content,
particularly focusing on the special cases of Jean-Marc Samson and Ashley Williams.
"""

import os
import sys
import re

# File paths
workspace_path = "/workspaces/JaiziahGreene"
complete_file = os.path.join(workspace_path, "complete_user_hash_data_accurate.txt")
ntlm_lm_file = os.path.join(workspace_path, "ntlm_lm_hashes_accurate.txt")
lm_only_file = os.path.join(workspace_path, "lm_only_hashes_accurate.txt")
ntlm_only_file = os.path.join(workspace_path, "ntlm_only_hashes_accurate.txt")
strong_passwords_file = os.path.join(workspace_path, "strong_passwords_accurate.txt")

# Special hashes to verify
JEAN_MARC_NTLM = "155d1254d37e9d54bf4bd4d80e55153b"
ASHLEY_NTLM = "31c2c7446c692de275628af9a81c5d4e"

def check_file_formats():
    """Check that all hash files have the correct format"""
    print("\n=== Checking Hash File Formats ===")
    
    # Complete user hash data format: username::ntlm(:lm)
    with open(complete_file, 'r', encoding='utf-8') as f:
        content = f.read()
        complete_valid = True
        
        # Check for username::ntlm(:lm) format
        lines = [line for line in content.split('\n') if line.strip() and not line.startswith('//')]
        for line in lines:
            if not re.match(r'^[^:]+::[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$', line):
                print(f"❌ Invalid format in {os.path.basename(complete_file)}: {line}")
                complete_valid = False
        
        if complete_valid:
            print(f"✅ {os.path.basename(complete_file)} has valid format")
    
    # NTLM:LM hash format: ntlm:lm
    with open(ntlm_lm_file, 'r', encoding='utf-8') as f:
        content = f.read()
        ntlm_lm_valid = True
        
        # Check for ntlm:lm format
        lines = [line for line in content.split('\n') if line.strip() and not line.startswith('//')]
        for line in lines:
            if not re.match(r'^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$', line):
                print(f"❌ Invalid format in {os.path.basename(ntlm_lm_file)}: {line}")
                ntlm_lm_valid = False
        
        if ntlm_lm_valid:
            print(f"✅ {os.path.basename(ntlm_lm_file)} has valid format")
    
    # LM-only hash format: lm
    with open(lm_only_file, 'r', encoding='utf-8') as f:
        content = f.read()
        lm_only_valid = True
        
        # Check for lm format
        lines = [line for line in content.split('\n') if line.strip() and not line.startswith('//')]
        for line in lines:
            if not re.match(r'^[0-9a-fA-F]{32}$', line):
                print(f"❌ Invalid format in {os.path.basename(lm_only_file)}: {line}")
                lm_only_valid = False
        
        if lm_only_valid:
            print(f"✅ {os.path.basename(lm_only_file)} has valid format")
    
    # NTLM-only hash format: ntlm
    with open(ntlm_only_file, 'r', encoding='utf-8') as f:
        content = f.read()
        ntlm_only_valid = True
        
        # Check for ntlm format
        lines = [line for line in content.split('\n') if line.strip() and not line.startswith('//')]
        for line in lines:
            if not re.match(r'^[0-9a-fA-F]{32}$', line):
                print(f"❌ Invalid format in {os.path.basename(ntlm_only_file)}: {line}")
                ntlm_only_valid = False
        
        if ntlm_only_valid:
            print(f"✅ {os.path.basename(ntlm_only_file)} has valid format")
    
    # Strong passwords file format: ntlm
    with open(strong_passwords_file, 'r', encoding='utf-8') as f:
        content = f.read()
        strong_valid = True
        
        # Check for ntlm format
        lines = [line for line in content.split('\n') if line.strip() and not line.startswith('//')]
        for line in lines:
            if not re.match(r'^[0-9a-fA-F]{32}$', line):
                print(f"❌ Invalid format in {os.path.basename(strong_passwords_file)}: {line}")
                strong_valid = False
        
        if strong_valid:
            print(f"✅ {os.path.basename(strong_passwords_file)} has valid format")
    
    return complete_valid and ntlm_lm_valid and lm_only_valid and ntlm_only_valid and strong_valid

def check_special_cases():
    """Check that Jean-Marc Samson and Ashley Williams are handled correctly"""
    print("\n=== Checking Special Cases ===")
    
    # Check complete user hash data
    with open(complete_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
        jean_marc_entry = re.search(r'jean-marc\.samson::[0-9a-fA-F]{32}', content, re.IGNORECASE)
        ashley_entry = re.search(r'ashleywilliams::[0-9a-fA-F]{32}', content, re.IGNORECASE)
        
        if jean_marc_entry:
            jean_marc_hash = jean_marc_entry.group(0).split('::')[1]
            if jean_marc_hash == JEAN_MARC_NTLM:
                print(f"✅ Jean-Marc Samson's hash is correct in complete_user_hash_data_accurate.txt")
            else:
                print(f"❌ Jean-Marc Samson's hash is incorrect: {jean_marc_hash}")
        else:
            print("❌ Jean-Marc Samson not found in complete_user_hash_data_accurate.txt")
        
        if ashley_entry:
            ashley_hash = ashley_entry.group(0).split('::')[1]
            if ashley_hash == ASHLEY_NTLM:
                print(f"✅ Ashley Williams's hash is correct in complete_user_hash_data_accurate.txt")
            else:
                print(f"❌ Ashley Williams's hash is incorrect: {ashley_hash}")
        else:
            print("❌ Ashley Williams not found in complete_user_hash_data_accurate.txt")
    
    # Check strong passwords file
    with open(strong_passwords_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
        if JEAN_MARC_NTLM in content:
            print(f"✅ Jean-Marc Samson's hash is in the strong passwords file")
        else:
            print(f"❌ Jean-Marc Samson's hash is not in the strong passwords file")
        
        if ASHLEY_NTLM in content:
            print(f"✅ Ashley Williams's hash is in the strong passwords file")
        else:
            print(f"❌ Ashley Williams's hash is not in the strong passwords file")
    
    # Check NTLM only file
    with open(ntlm_only_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
        if JEAN_MARC_NTLM in content:
            print(f"✅ Jean-Marc Samson's hash is in the NTLM only file")
        else:
            print(f"❌ Jean-Marc Samson's hash is not in the NTLM only file")
        
        if ASHLEY_NTLM in content:
            print(f"✅ Ashley Williams's hash is in the NTLM only file")
        else:
            print(f"❌ Ashley Williams's hash is not in the NTLM only file")
    
    # Check that these hashes are NOT in the NTLM:LM file
    with open(ntlm_lm_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
        if f"{JEAN_MARC_NTLM}:" not in content:
            print(f"✅ Jean-Marc Samson's hash is correctly excluded from the NTLM:LM file")
        else:
            print(f"❌ Jean-Marc Samson's hash should not be in the NTLM:LM file")
        
        if f"{ASHLEY_NTLM}:" not in content:
            print(f"✅ Ashley Williams's hash is correctly excluded from the NTLM:LM file")
        else:
            print(f"❌ Ashley Williams's hash should not be in the NTLM:LM file")

def main():
    print("=== HASH VARIANTS VERIFICATION ===")
    
    # Check file formats
    format_valid = check_file_formats()
    
    # Check special cases
    check_special_cases()
    
    # Final assessment
    print("\n=== Final Assessment ===")
    if format_valid:
        print("✅ All hash files have the correct format")
    else:
        print("❌ Some hash files have incorrect format")
    
    print("\nVerification complete!")

if __name__ == "__main__":
    main()
