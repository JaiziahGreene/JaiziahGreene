#!/usr/bin/env python3
# filepath: /workspaces/JaiziahGreene/extract_ntlm_only.py
# Script to extract only NTLM hashes from mimikatz output and create a new file

import re

# Input and output file paths
input_file = 'mimikatz_output.txt'
output_file = 'ntlm_only.txt'

# Pattern to match "Hash NTLM: [32-char hex]" with any leading spaces
ntlm_regex = re.compile(r'\s*Hash\s*NTLM:\s*([a-fA-F0-9]{32})', re.IGNORECASE)

try:
    # Open the file with UTF-16-LE encoding (which is what mimikatz output uses)
    with open(input_file, 'r', encoding='utf-16-le', errors='ignore') as f:
        content = f.read()

    print(f"File loaded, size: {len(content)} characters")
    print("Searching for 'Hash NTLM:' pattern...")

    # Extract all NTLM hashes
    hashes = set()
    for match in ntlm_regex.finditer(content):
        hash_value = match.group(1)
        print(f"Found hash: {hash_value}")
        hashes.add(hash_value)

    # Write the unique hashes to the output file
    with open(output_file, 'w') as f:
        for h in sorted(hashes):
            f.write(h + '\n')

    print(f"Extracted {len(hashes)} unique NTLM hashes to {output_file}")
    
except Exception as e:
    print(f"Error: {e}")
