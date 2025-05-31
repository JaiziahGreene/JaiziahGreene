#!/usr/bin/env python3
import os
import re
import codecs

def extract_user_data(file_path):
    users_data = []
    
    try:
        # Handle UTF-16 if needed
        if os.path.basename(file_path).startswith("mimikatz PC 2"):
            with codecs.open(file_path, 'r', encoding='utf-16-le') as f:
                content = f.read()
        else:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
        
        # Extract user blocks
        user_blocks = re.findall(r'User\s*:\s*([^\r\n]+)[\s\S]+?(?=User\s*:|$)', content)
        
        for block in user_blocks:
            lines = block.split('\n')
            username = lines[0].strip()
            
            # Find NTLM hash
            ntlm_hash = None
            lm_hash = None
            
            for line in lines:
                if "Hash NTLM" in line:
                    ntlm_match = re.search(r'Hash NTLM\s*:\s*([a-fA-F0-9]{32})', line)
                    if ntlm_match:
                        ntlm_hash = ntlm_match.group(1).lower()
                elif "Hash LM" in line:
                    lm_match = re.search(r'Hash LM\s*:\s*([a-fA-F0-9]{32})', line)
                    if lm_match:
                        lm_hash = lm_match.group(1).lower()
            
            if ntlm_hash:  # Only consider users with NTLM hash
                users_data.append({
                    'username': username,
                    'ntlm_hash': ntlm_hash,
                    'lm_hash': lm_hash,
                    'has_lm': lm_hash is not None
                })
                
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
    
    return users_data

# Process all dump files
dump_files = [
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/mimikatz PC 2.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 3 Dump.txt",
    "/workspaces/JaiziahGreene/New MimiKatz Dumps/Mimikatz PC 4 Dump.txt"
]

all_users = []
special_users = []
ntlm_only_users = []

for dump_file in dump_files:
    print(f"Processing {dump_file}...")
    users = extract_user_data(dump_file)
    all_users.extend(users)
    
    # Check for special cases
    for user in users:
        if user['username'].lower() in ['jean-marc.samson', 'ashleywilliams']:
            special_users.append({**user, 'source': os.path.basename(dump_file)})
        
        if not user['has_lm']:
            ntlm_only_users.append({**user, 'source': os.path.basename(dump_file)})

# Print special cases
print("\n===== Special Cases =====")
for user in special_users:
    print(f"Username: {user['username']}")
    print(f"NTLM Hash: {user['ntlm_hash']}")
    print(f"LM Hash: {user['lm_hash'] or 'None'}")
    print(f"Source: {user['source']}")
    print()

# Print users with only NTLM hash
print("\n===== Users with only NTLM hash (no LM) =====")
for user in ntlm_only_users:
    print(f"{user['username']}: {user['ntlm_hash']} ({user['source']})")

# Count statistics
total_users = len(all_users)
ntlm_only_count = len(ntlm_only_users)

print(f"\nTotal users across all dumps: {total_users}")
if total_users > 0:
    print(f"Users with only NTLM hash (no LM): {ntlm_only_count} ({ntlm_only_count/total_users*100:.1f}%)")
else:
    print(f"Users with only NTLM hash (no LM): {ntlm_only_count} (0.0%)")

# Write results to file
with open("/workspaces/JaiziahGreene/special_cases_analysis.txt", "w") as f:
    f.write("# Special Cases Analysis\n\n")
    
    f.write("## Special Users\n\n")
    for user in special_users:
        f.write(f"Username: {user['username']}\n")
        f.write(f"NTLM Hash: {user['ntlm_hash']}\n")
        f.write(f"LM Hash: {user['lm_hash'] or 'None'}\n")
        f.write(f"Source: {user['source']}\n\n")
    
    f.write("## Users with only NTLM hash (no LM)\n\n")
    for user in ntlm_only_users:
        f.write(f"{user['username']}:{user['ntlm_hash']}:{user['source']}\n")

print(f"\nResults saved to /workspaces/JaiziahGreene/special_cases_analysis.txt")
