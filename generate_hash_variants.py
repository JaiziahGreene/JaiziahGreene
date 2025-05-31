#!/usr/bin/env python3
"""
Script to generate different variants of the master_user_hashes_with_variants.txt file:
1. NTLM:LM file - Format will be just the hashes without usernames
2. LM only file - Just the LM hashes (no blanks)
3. NTLM only file - Just the NTLM hashes
4. Strong passwords file - NTLM only for users with no LM

All variants will exclude entries where a password has been found (from found_users_with_passwords.txt).
"""

import os
import sys

output_dir = "hash_variants"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

ntlm_lm_pairs = []
lm_only = []
ntlm_only = []
strong_passwords = []

# Load found users with passwords (username, ntlm)
found_pw_file = "found_users_with_passwords.txt"
found_pw_set = set()
with open(found_pw_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('Username') or line.startswith('-'):
            continue
        parts = line.split('\t')
        if len(parts) >= 2:
            found_pw_set.add((parts[0].lower(), parts[1].lower()))

# Load and process the master hash file
input_file = os.path.join(output_dir, "master_user_hashes_with_variants.txt")
total_entries = 0
skipped_entries = 0

with open(input_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('//'):
            continue
        total_entries += 1
        # username:ntlm:lm:source
        parts = line.split(':')
        if len(parts) < 4:
            continue
        username = parts[0].lower()
        ntlm = parts[1].lower()
        lm = parts[2].lower() if len(parts) > 2 else ""
        # Exclude if in found_pw_set
        if (username, ntlm) in found_pw_set:
            skipped_entries += 1
            continue
        # Add to appropriate lists
        if ntlm and lm:
            ntlm_lm_pairs.append(f"{ntlm}:{lm}")
            lm_only.append(lm)
            ntlm_only.append(ntlm)
        elif ntlm and not lm:
            ntlm_only.append(ntlm)
            strong_passwords.append(ntlm)
            ntlm_lm_pairs.append(f"{ntlm}:")
        elif not ntlm and lm:
            lm_only.append(lm)
            ntlm_lm_pairs.append(f":{lm}")

# Remove blanks from lm_only
lm_only = [h for h in lm_only if h]

with open(os.path.join(output_dir, "ntlm_lm_pairs.txt"), 'w', encoding='utf-8') as f:
    f.write("// NTLM:LM hash pairs (entries with passwords removed)\n\n")
    for entry in sorted(set(ntlm_lm_pairs)):
        f.write(f"{entry}\n")

with open(os.path.join(output_dir, "lm_only.txt"), 'w', encoding='utf-8') as f:
    f.write("// LM hashes only (entries with passwords removed)\n\n")
    for entry in sorted(set(lm_only)):
        f.write(f"{entry}\n")

with open(os.path.join(output_dir, "ntlm_only.txt"), 'w', encoding='utf-8') as f:
    f.write("// NTLM hashes only (entries with passwords removed)\n\n")
    for entry in sorted(set(ntlm_only)):
        f.write(f"{entry}\n")

with open(os.path.join(output_dir, "strong_passwords.txt"), 'w', encoding='utf-8') as f:
    f.write("// Strong passwords - NTLM hashes with no LM hash (entries with passwords removed)\n\n")
    for entry in sorted(set(strong_passwords)):
        f.write(f"{entry}\n")

print(f"Total entries processed: {total_entries}")
print(f"Entries skipped (had passwords): {skipped_entries}")
print(f"Entries included in variants: {total_entries - skipped_entries}")
print(f"NTLM:LM pairs: {len(ntlm_lm_pairs)}")
print(f"LM hashes: {len(lm_only)}")
print(f"NTLM hashes: {len(ntlm_only)}")
print(f"Strong passwords (NTLM only): {len(strong_passwords)}")
print(f"\nAll files written to the '{output_dir}' directory.")
