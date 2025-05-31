#!/usr/bin/env python3
import os
import re
import codecs
from collections import defaultdict

# --- CONFIG ---
DUMPS_DIR = "/workspaces/JaiziahGreene/All the Mimikatz Dumps"
# Explicitly list all 4 dump files to guarantee inclusion
DUMP_FILES = [
    os.path.join(DUMPS_DIR, "PC 1's Mimikatz Dump.txt"),
    os.path.join(DUMPS_DIR, "mimikatz PC 2.txt"),
    os.path.join(DUMPS_DIR, "Mimikatz PC 3 Dump.txt"),
    os.path.join(DUMPS_DIR, "Mimikatz PC 4 Dump.txt"),
]
FOUND_PASS_FILE = "/workspaces/JaiziahGreene/found_users_with_passwords.txt"
OUTPUT_DIR = "/workspaces/JaiziahGreene/hash_variants"
MASTER_FILE = os.path.join(OUTPUT_DIR, "master_user_hashes_with_variants.txt")

os.makedirs(OUTPUT_DIR, exist_ok=True)

def parse_found_passwords(path):
    found = set()
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.strip() and not line.startswith('---') and not line.lower().startswith('username'):
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    username, ntlm = parts[0].strip().lower(), parts[1].strip().lower()
                    found.add((username, ntlm))
    return found

def parse_mimikatz_dump(path):
    import subprocess
    # Detect encoding
    encoding = 'utf-8'
    file_out = subprocess.check_output(['file', path]).decode()
    if 'Unicode' in file_out or 'UTF-16' in file_out:
        encoding = 'utf-16-le'
    users = []
    with open(path, 'r', encoding=encoding, errors='ignore') as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        line = lines[i].replace('\r', '').strip()
        if re.match(r'^User\s*:\s*', line):
            username = line.split('User : ')[1].strip().lower()
            ntlm, lm = '', ''
            # Look ahead for hashes (up to 20 lines to be robust)
            for j in range(1, 20):
                if i+j >= len(lines): break
                l2 = lines[i+j].replace('\r', '').strip()
                if l2.startswith('Hash NTLM:'):
                    ntlm = l2.split('Hash NTLM:')[1].strip().lower()
                if l2.startswith('Hash LM  :'):
                    lm = l2.split('Hash LM  :')[1].strip().lower()
            if ntlm:
                users.append((username, ntlm, lm, os.path.basename(path)))
        i += 1
    return users

def main():
    # 1. Parse all dumps, collect all (username, ntlm, lm, source)
    all_entries = []
    for path in DUMP_FILES:
        if os.path.exists(path):
            users = parse_mimikatz_dump(path)
            print(f"Parsed {len(users)} users from {os.path.basename(path)}")
            all_entries.extend(users)
        else:
            print(f"Warning: {path} not found!")

    # 2. For each username, collect all unique (ntlm, lm, source)
    user_hashes = defaultdict(list)  # username -> list of (ntlm, lm, source)
    for username, ntlm, lm, source in all_entries:
        if (ntlm, lm, source) not in user_hashes[username]:
            user_hashes[username].append((ntlm, lm, source))

    # 3. Remove any user+ntlm in found passwords
    found = parse_found_passwords(FOUND_PASS_FILE)
    filtered = []
    for username, variants in user_hashes.items():
        for idx, (ntlm, lm, source) in enumerate(variants, 1):
            if (username, ntlm) not in found:
                # Variant naming: username, username#2, username#3, ...
                uname = username if idx == 1 else f"{username}#{idx}"
                filtered.append((uname, ntlm, lm, source))

    # 4. Write master file with variants
    with open(MASTER_FILE, 'w', encoding='utf-8') as f:
        for uname, ntlm, lm, source in filtered:
            f.write(f"{uname}:{ntlm}:{lm}:{source}\n")
    print(f"Wrote {len(filtered)} user hash variants to {MASTER_FILE}")

if __name__ == "__main__":
    main()
