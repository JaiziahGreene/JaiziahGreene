import re

# Input and output file paths
input_file = 'mimikatz_output.txt'
output_file = 'ntlm_hashes_extracted.txt'

# Pattern to match "Hash NTLM: [32-char hex]" with any leading spaces
ntlm_regex = re.compile(r'\s*Hash\s*NTLM:\s*([a-fA-F0-9]{32})', re.IGNORECASE)

# Alternate pattern to match any 32-character hex string that might be a hash
hex_regex = re.compile(r'(?<![a-fA-F0-9])([a-fA-F0-9]{32})(?![a-fA-F0-9])')

# Known SAM key pattern
sam_key_regex = re.compile(r'SAMKey\s*:\s*([a-fA-F0-9]{32})', re.IGNORECASE)
syskey_regex = re.compile(r'SysKey\s*:\s*([a-fA-F0-9]{32})', re.IGNORECASE)

with open(input_file, 'r', encoding='utf-16-le', errors='ignore') as f:
    content = f.read()

print(f"File loaded, size: {len(content)} characters")
print("Searching for 'Hash NTLM:' pattern...")

# First look for the pattern you specified
hashes = set()
for match in ntlm_regex.finditer(content):
    hash_value = match.group(1)
    print(f"Found hash: {hash_value}")
    hashes.add(hash_value)

# If no matches found, try looking for SAM keys and SysKeys
if not hashes:
    for match in sam_key_regex.finditer(content):
        hashes.add(match.group(1))
    
    for match in syskey_regex.finditer(content):
        hashes.add(match.group(1))

# If still no matches, look for any 32-character hex strings that might be hashes
# But exclude common known non-hash hex strings like dates or version numbers
if not hashes:
    # Get all potential 32-char hex strings
    potential_hashes = [match.group(1) for match in hex_regex.finditer(content)]
    
    for hash_candidate in potential_hashes:
        # Basic check to filter out obvious non-hash values
        # Most hashes have a good mix of numbers and letters
        if sum(c.isalpha() for c in hash_candidate) > 3 and sum(c.isdigit() for c in hash_candidate) > 3:
            hashes.add(hash_candidate)

with open(output_file, 'w') as f:
    for h in sorted(hashes):
        f.write(h + '\n')

print(f"Extracted {len(hashes)} unique potential NTLM hashes to {output_file}")
print("Hashes found:")
for h in sorted(hashes):
    print(h)
