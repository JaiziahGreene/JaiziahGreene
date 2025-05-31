#!/usr/bin/env python3
import os
import re
import codecs

# Known to be a UTF-16LE file
dump_file = "/workspaces/JaiziahGreene/New MimiKatz Dumps/mimikatz PC 2.txt"

try:
    # Open the file with UTF-16LE encoding
    with codecs.open(dump_file, 'r', encoding='utf-16-le', errors='ignore') as f:
        content = f.read()
    
    # Find all user sections
    user_pattern = r'User\s*:\s*([^\r\n]+)[\s\S]+?(?=(?:User\s*:|$))'
    user_sections = re.findall(user_pattern, content)
    
    print(f"Found {len(user_sections)} user sections")
    
    # Process each user section
    users_with_ntlm_only = []
    all_users = []
    
    for section in content.split('User : '):
        if not section.strip():
            continue
            
        lines = section.split('\n')
        if not lines:
            continue
            
        username = lines[0].strip()
        all_users.append(username)
        
        has_ntlm = False
        has_lm = False
        ntlm_hash = None
        lm_hash = None
        
        for line in lines:
            if 'Hash NTLM:' in line:
                has_ntlm = True
                ntlm_match = re.search(r'Hash NTLM:\s*([0-9a-fA-F]{32})', line)
                if ntlm_match:
                    ntlm_hash = ntlm_match.group(1).lower()
            elif 'Hash LM:' in line:
                has_lm = True
                lm_match = re.search(r'Hash LM:\s*([0-9a-fA-F]{32})', line)
                if lm_match:
                    lm_hash = lm_match.group(1).lower()
        
        # Check if this user has NTLM but no LM hash
        if has_ntlm and not has_lm and username:
            users_with_ntlm_only.append((username, ntlm_hash))
            
    # Special users
    for username in ['jean-marc.samson', 'ashleywilliams']:
        for i, user in enumerate(all_users):
            if username.lower() in user.lower():
                print(f"Found special user: {user}")
                # Find the user section
                section = content.split('User : ')[i+1]
                # Print a few lines
                lines = section.split('\n')[:15]
                for line in lines:
                    if 'Hash' in line:
                        print(f"  {line.strip()}")
    
    # Print users with only NTLM hash
    print(f"\nUsers with only NTLM hash ({len(users_with_ntlm_only)} users):")
    for username, ntlm_hash in users_with_ntlm_only:
        print(f"{username}: {ntlm_hash}")
    
except Exception as e:
    print(f"Error processing file: {str(e)}")
