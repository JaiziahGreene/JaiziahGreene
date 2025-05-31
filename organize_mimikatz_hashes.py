#!/usr/bin/env python3
import os
import re
import codecs
from collections import defaultdict

# --- CONFIG ---
DUMPS_DIR = "/workspaces/JaiziahGreene/All the Mimikatz Dumps"
FOUND_PASS_FILE = "/workspaces/JaiziahGreene/found_users_with_passwords.txt"
OUTPUT_DIR = "/workspaces/JaiziahGreene/hash_variants"
MASTER_FILE = os.path.join(OUTPUT_DIR, "master_user_hashes.txt")
NTLM_LM_FILE = os.path.join(OUTPUT_DIR, "ntlm_lm_pairs.txt")
NTLM_ONLY_FILE = os.path.join(OUTPUT_DIR, "ntlm_only.txt")
LM_ONLY_FILE = os.path.join(OUTPUT_DIR, "lm_only.txt")
STRONG_FILE = os.path.join(OUTPUT_DIR, "strong_passwords.txt")

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
    users = []
    with codecs.open(path, 'r', encoding='utf-16-le', errors='ignore') as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('User : '):
            username = line.split('User : ')[1].strip().lower()
            ntlm, lm = '', ''
            # Look ahead for hashes
            for j in range(1, 10):
                if i+j >= len(lines): break
                l2 = lines[i+j].strip()
                if l2.startswith('Hash NTLM:'):
                    ntlm = l2.split('Hash NTLM:')[1].strip().lower()
                if l2.startswith('Hash LM  :'):
                    lm = l2.split('Hash LM  :')[1].strip().lower()
            if ntlm:
                users.append((username, ntlm, lm))
        i += 1
    return users

def main():
    # 1. Parse all dumps
    all_hashes = defaultdict(list)  # username -> list of (ntlm, lm, source)
    for fname in os.listdir(DUMPS_DIR):
        if fname.lower().endswith('.txt'):
            path = os.path.join(DUMPS_DIR, fname)
            for username, ntlm, lm in parse_mimikatz_dump(path):
                all_hashes[username].append((ntlm, lm, fname))

    # 2. Deduplicate: for each username, only keep unique NTLMs
    deduped = dict()  # (username, ntlm) -> lm
    for username, entries in all_hashes.items():
        seen_ntlm = set()
        for ntlm, lm, src in entries:
            if (username, ntlm) not in deduped:
                deduped[(username, ntlm)] = lm

    # 3. Remove users with found passwords
    found = parse_found_passwords(FOUND_PASS_FILE)
    filtered = {k: v for k, v in deduped.items() if k not in found}

    # 4. Write master file
    with open(MASTER_FILE, 'w', encoding='utf-8') as f:
        for (username, ntlm), lm in sorted(filtered.items()):
            f.write(f"{username}:{ntlm}:{lm}\n")

    # 5. Write variants
    with open(NTLM_LM_FILE, 'w', encoding='utf-8') as f:
        for (username, ntlm), lm in sorted(filtered.items()):
            f.write(f"{ntlm}:{lm}\n")
    with open(NTLM_ONLY_FILE, 'w', encoding='utf-8') as f:
        for (username, ntlm), lm in sorted(filtered.items()):
            f.write(f"{ntlm}\n")
    with open(LM_ONLY_FILE, 'w', encoding='utf-8') as f:
        for (username, ntlm), lm in sorted(filtered.items()):
            if lm:
                f.write(f"{lm}\n")
    with open(STRONG_FILE, 'w', encoding='utf-8') as f:
        for (username, ntlm), lm in sorted(filtered.items()):
            if not lm:
                f.write(f"{ntlm}\n")
    print("Done! All files written to:", OUTPUT_DIR)

if __name__ == "__main__":
    main()
