#!/usr/bin/env python3
# filepath: /workspaces/JaiziahGreene/merge_ntlm_hashes.py
import re

# Input and output file paths
mimikatz_output_file = 'mimikatz_output.txt'
existing_hashes_file = 'ntlm_hashes_only.txt'  # Existing file with NTLM hashes
mimikatz_by_user_file = 'mimikatz_hashes_by_user.txt'  # File with hashes by user
final_output_file = 'all_ntlm_hashes.txt'  # Final merged output file

# Set to store all unique NTLM hashes
all_hashes = set()

# Pattern to match NTLM hashes in the mimikatz output
ntlm_regex = re.compile(r'\s*Hash\s*NTLM:\s*([a-fA-F0-9]{32})', re.IGNORECASE)
lm_regex = re.compile(r'\s*Hash\s*LM\s*:\s*([a-fA-F0-9]{32})', re.IGNORECASE)

# Extract NTLM hashes from mimikatz_output.txt (UTF-16-LE encoded)
try:
    with open(mimikatz_output_file, 'r', encoding='utf-16-le', errors='ignore') as f:
        content = f.read()
        
    print(f"Processing {mimikatz_output_file}...")
    for match in ntlm_regex.finditer(content):
        hash_value = match.group(1)
        all_hashes.add(hash_value)
        
    print(f"Found {len(all_hashes)} NTLM hashes in {mimikatz_output_file}")
except Exception as e:
    print(f"Error processing {mimikatz_output_file}: {e}")

# Extract hashes from the existing ntlm_hashes_only.txt file
try:
    with open(existing_hashes_file, 'r', encoding='utf-8', errors='ignore') as f:
        existing_hashes = [line.strip() for line in f if line.strip()]
    
    print(f"Processing {existing_hashes_file}...")
    existing_count = 0
    for hash_value in existing_hashes:
        if re.match(r'^[a-fA-F0-9]{32}$', hash_value):  # Ensure it's a valid hash
            all_hashes.add(hash_value)
            existing_count += 1
            
    print(f"Found {existing_count} valid NTLM hashes in {existing_hashes_file}")
except Exception as e:
    print(f"Error processing {existing_hashes_file}: {e}")

# Extract hashes from mimikatz_hashes_by_user.txt (might contain more context)
try:
    with open(mimikatz_by_user_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    print(f"Processing {mimikatz_by_user_file}...")
    user_file_count = 0
    
    # Try to extract NTLM hashes - different possible formats
    for pattern in [
        r'NTLM\s*:\s*([a-fA-F0-9]{32})',  # NTLM: hash
        r'ntlm\s*=\s*([a-fA-F0-9]{32})',  # ntlm=hash
        r'Hash NTLM\s*:\s*([a-fA-F0-9]{32})'  # Hash NTLM: hash
    ]:
        regex = re.compile(pattern, re.IGNORECASE)
        for match in regex.finditer(content):
            hash_value = match.group(1)
            if hash_value not in all_hashes:
                all_hashes.add(hash_value)
                user_file_count += 1
    
    print(f"Found {user_file_count} additional NTLM hashes in {mimikatz_by_user_file}")
except Exception as e:
    print(f"Error processing {mimikatz_by_user_file}: {e}")

# Write all unique hashes to the output file
with open(final_output_file, 'w') as f:
    for h in sorted(all_hashes):
        f.write(f"{h}\n")

print(f"\nTotal unique NTLM hashes found: {len(all_hashes)}")
print(f"All hashes have been written to {final_output_file}")

# Create formats for hashcat and John the Ripper
hashcat_format_file = 'ntlm_hashcat_format.txt'
jtr_format_file = 'ntlm_jtr_format.txt'

print("\nCreating specialized formats for password cracking tools...")

# Create empty username for hashcat format (username:hash)
with open(hashcat_format_file, 'w') as f:
    for h in sorted(all_hashes):
        f.write(f"user:{h}\n")

# Create John the Ripper format ($NT$hash)
with open(jtr_format_file, 'w') as f:
    for h in sorted(all_hashes):
        f.write(f"user:$NT${h}\n")

print(f"Created hashcat format in {hashcat_format_file}")
print(f"Created John the Ripper format in {jtr_format_file}")
