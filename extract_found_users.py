#!/usr/bin/env python3
# Script to extract only users with known passwords from user_ntlm_passwords.txt and create a clean, organized output

input_file = '/workspaces/JaiziahGreene/user_ntlm_passwords.txt'
output_file = '/workspaces/JaiziahGreene/found_users_with_passwords.txt'

# Read the input file, skipping header lines
with open(input_file, 'r') as f:
    # Skip the first two lines (header and separator)
    lines = f.readlines()[2:]

# Process only entries with known passwords
found_users = []
for line in lines:
    parts = line.strip().split('\t')
    if len(parts) == 3 and parts[2].strip():  # Check if there's a password in the third column
        username = parts[0]
        ntlm_hash = parts[1]
        password = parts[2]
        found_users.append((username, ntlm_hash, password))

# Sort entries by username for better organization
found_users.sort(key=lambda x: x[0].lower())

# Write the output file with a clean format
with open(output_file, 'w') as f:
    f.write("Username\tNTLM Hash\tPassword\n")
    f.write("-" * 80 + "\n")
    for username, ntlm_hash, password in found_users:
        f.write(f"{username}\t{ntlm_hash}\t{password}\n")

print(f"Extracted {len(found_users)} users with known passwords to {output_file}")
