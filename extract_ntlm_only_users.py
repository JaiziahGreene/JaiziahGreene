#!/usr/bin/env python3
import os
import re

dumps = [
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/mimikatz PC 2.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 3 Dump.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 4 Dump.txt"
]

def process_dump_file(filepath):
    ntlm_only = []
    current_user = None
    has_lm = False
    has_ntlm = False
    ntlm_hash = None
    
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            if "User : " in line:
                # Process previous user if exists
                if current_user and has_ntlm and not has_lm:
                    ntlm_only.append((current_user, ntlm_hash))
                
                # Start new user
                current_user = line.split("User : ")[1].strip()
                has_lm = False
                has_ntlm = False
                ntlm_hash = None
            elif "Hash LM" in line:
                has_lm = True
            elif "Hash NTLM" in line:
                has_ntlm = True
                ntlm_match = re.search(r'Hash NTLM:\s*([0-9a-fA-F]{32})', line)
                if ntlm_match:
                    ntlm_hash = ntlm_match.group(1)
    
    # Check last user
    if current_user and has_ntlm and not has_lm:
        ntlm_only.append((current_user, ntlm_hash))
    
    return ntlm_only

print("Looking for users with only NTLM hashes (no LM hash)...")
all_ntlm_only = []

for dump_file in dumps:
    if os.path.exists(dump_file):
        print(f"\nProcessing {os.path.basename(dump_file)}...")
        ntlm_only_users = process_dump_file(dump_file)
        
        for user, ntlm in ntlm_only_users:
            print(f" - {user}: {ntlm}")
            all_ntlm_only.append((user, ntlm, os.path.basename(dump_file)))
    else:
        print(f"Warning: File not found - {dump_file}")

print("\n===== All NTLM-only users across dumps =====")
for user, ntlm, source in all_ntlm_only:
    print(f"{user}: {ntlm} (from {source})")

# Save results to file
with open("ntlm_only_users.txt", "w") as f:
    f.write("# Users with only NTLM hash (no LM hash)\n")
    f.write("# format: username:ntlm_hash:source_file\n\n")
    
    for user, ntlm, source in all_ntlm_only:
        f.write(f"{user}:{ntlm}:{source}\n")

print("\nResults saved to ntlm_only_users.txt")
