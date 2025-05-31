#!/usr/bin/env python3
# Script to match NTLM hashes with usernames and passwords

import re

# Files to use
ntlm_passwords_file = '/workspaces/JaiziahGreene/all the found ntlms pc 1.txt'
user_ntlm_file = '/workspaces/JaiziahGreene/user_ntlm_passwords.txt'
mimikatz_file = '/workspaces/JaiziahGreene/mimikatz_output.txt'
output_file = '/workspaces/JaiziahGreene/username_pass_ntlm.txt'

# Dictionary to store hash -> password mappings
hash_to_password = {}

# Dictionary to store hash -> username mappings
hash_to_username = {}

# Load hash:password pairs from the ntlm_passwords_file
print(f"Loading hash:password pairs from {ntlm_passwords_file}...")
with open(ntlm_passwords_file, 'r') as f:
    # Skip the first line (comment/header)
    lines = f.readlines()[1:]
    for line in lines:
        parts = line.strip().split(':')
        if len(parts) == 2:
            ntlm_hash = parts[0].lower()
            password = parts[1]
            hash_to_password[ntlm_hash] = password
            
print(f"Loaded {len(hash_to_password)} hash:password pairs")

# Load username:hash pairs from user_ntlm_file
print(f"Loading username:hash pairs from {user_ntlm_file}...")
with open(user_ntlm_file, 'r') as f:
    # Skip the first two lines (header and separator)
    lines = f.readlines()[2:]
    for line in lines:
        parts = line.strip().split('\t')
        if len(parts) >= 2:
            username = parts[0]
            ntlm_hash = parts[1].lower()
            hash_to_username[ntlm_hash] = username
            
print(f"Loaded {len(hash_to_username)} username:hash pairs")

# Try to extract more username:hash pairs from mimikatz output
print(f"Extracting username:hash pairs from {mimikatz_file}...")
pattern = re.compile(r'User\s*:\s*(\S+).*?Hash\s*NTLM:\s*([a-fA-F0-9]{32})', re.DOTALL)

# Alternative pattern for mimikatz SAM dump format
alt_pattern = re.compile(r'User\s*:\s*(\S+).*?RID\s*:.*?Supplemental', re.DOTALL)

try:
    with open(mimikatz_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        matches = pattern.findall(content)
        for username, ntlm_hash in matches:
            ntlm_hash = ntlm_hash.lower()
            hash_to_username[ntlm_hash] = username
            
    print(f"After mimikatz extraction, we have {len(hash_to_username)} username:hash pairs")
except Exception as e:
    print(f"Error processing mimikatz file: {e}")

# Now let's try an alternative approach for the mimikatz SAM dump format
try:
    print("Trying alternative extraction method for SAM dump format...")
    with open(mimikatz_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
        # Split by "RID" to get user blocks
        sections = content.split("RID  :")
        
        for section in sections[1:]:  # Skip the first split which is before the first RID
            # Extract username
            user_match = re.search(r'User\s*:\s*(\S+)', section)
            if user_match:
                username = user_match.group(1)
                
                # Look for NTLM hash in this section
                hash_match = re.search(r'Hash\s*NTLM:\s*([a-fA-F0-9]{32})', section)
                
                # If no NTLM hash directly mentioned, try to find any 32-character hex string
                if not hash_match:
                    # Look for direct NTLM hash in supplemental section
                    supp_section = section.split("Supplemental Credentials:", 1)
                    if len(supp_section) > 1:
                        # Find any 32-character hex string that might be a hash
                        hex_matches = re.findall(r'(?<![a-fA-F0-9])([a-fA-F0-9]{32})(?![a-fA-F0-9])', supp_section[1])
                        if hex_matches:
                            hash_match = hex_matches[0]
                
                if hash_match:
                    ntlm_hash = hash_match if isinstance(hash_match, str) else hash_match.group(1)
                    ntlm_hash = ntlm_hash.lower()
                    hash_to_username[ntlm_hash] = username
                    
    print(f"After alternative extraction, we have {len(hash_to_username)} username:hash pairs")
except Exception as e:
    print(f"Error in alternative extraction: {e}")

# Now create the final output with username:pass:ntlm format
print(f"Creating output file {output_file}...")
with open(output_file, 'w') as out_f:
    for ntlm_hash, password in hash_to_password.items():
        username = hash_to_username.get(ntlm_hash, "unknown")
        out_f.write(f"{username}:{password}:{ntlm_hash}\n")
        
print(f"Output saved to {output_file}")

# Additionally, let's directly analyze the mimikatz SAM dump format
print("Directly analyzing the mimikatz SAM dump format...")
with open(mimikatz_file, 'r', encoding='utf-8', errors='ignore') as f:
    current_user = None
    user_hashes = {}
    
    for line in f:
        line = line.strip()
        
        # Look for user line
        user_match = re.search(r'User\s*:\s*(\S+)', line)
        if user_match:
            current_user = user_match.group(1)
            continue
            
        # If we have a current user, look for NTLM hash
        if current_user and "Primary:NTLM-Strong-NTOWF" in line:
            # The next few lines might contain a hash
            continue
            
        # Check if this line might be a 32-character hex string (potential hash)
        hex_match = re.search(r'(?<![a-fA-F0-9])([a-fA-F0-9]{32})(?![a-fA-F0-9])', line)
        if current_user and hex_match:
            ntlm_hash = hex_match.group(1).lower()
            user_hashes[ntlm_hash] = current_user
            
    # Update our main hash_to_username dictionary
    hash_to_username.update(user_hashes)
    print(f"Found {len(user_hashes)} additional user:hash pairs")

# Create an updated output with any new information
print(f"Creating updated output file {output_file}...")
with open(output_file, 'w') as out_f:
    for ntlm_hash, password in hash_to_password.items():
        username = hash_to_username.get(ntlm_hash, "unknown")
        out_f.write(f"{username}:{password}:{ntlm_hash}\n")
        
print(f"Updated output saved to {output_file}")
