#!/usr/bin/env python3
import os
import re
import codecs
from collections import defaultdict

# --- CONFIG ---
DUMP_FILES = [
    "mimikatz_output.txt",
    "New MimiKatz Dumps/mimikatz PC 2.txt",
    "New MimiKatz Dumps/Mimikatz PC 3 Dump.txt",
    "New MimiKatz Dumps/Mimikatz PC 4 Dump.txt",
]
WORKSPACE = "/workspaces/JaiziahGreene"
DUMP_FILES = [os.path.join(WORKSPACE, f) for f in DUMP_FILES]
FOUND_PASS_FILE = os.path.join(WORKSPACE, "found_users_with_passwords.txt")
OUTPUT_DIR = os.path.join(WORKSPACE, "organized_hashes")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- 1. Parse all dumps ---
user_hashes = defaultdict(list)  # username -> list of (ntlm, lm)
seen = set()

for dump_path in DUMP_FILES:
    if not os.path.exists(dump_path):
        continue
    # All dumps are UTF-16LE
    with codecs.open(dump_path, 'r', encoding='utf-16-le', errors='ignore') as f:
        lines = f.readlines()
    username, ntlm, lm = None, None, None
    for line in lines:
        line = line.strip()
        if line.startswith("User : "):
            if username and ntlm:
                key = (username.lower(), ntlm, lm or "")
                if key not in seen:
                    user_hashes[username.lower()].append((ntlm, lm or ""))
                    seen.add(key)
            username = line.split(":",1)[1].strip()
            ntlm, lm = None, None
        elif line.startswith("Hash NTLM:"):
            ntlm = line.split(":",1)[1].strip().lower()
        elif line.startswith("Hash LM  :") or line.startswith("Hash LM:"):
            lm = line.split(":",1)[1].strip().lower()
    # Last user
    if username and ntlm:
        key = (username.lower(), ntlm, lm or "")
        if key not in seen:
            user_hashes[username.lower()].append((ntlm, lm or ""))
            seen.add(key)

# --- 2. Remove entries with found passwords ---
found_users = set()
if os.path.exists(FOUND_PASS_FILE):
    with open(FOUND_PASS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.strip():
                found_users.add(line.split(':')[0].lower())

# --- 3. Write master file ---
master_path = os.path.join(OUTPUT_DIR, "master_user_hashes.txt")
with open(master_path, 'w', encoding='utf-8') as f:
    for user, hashes in sorted(user_hashes.items()):
        if user in found_users:
            continue
        for idx, (ntlm, lm) in enumerate(hashes):
            uname = user if idx == 0 else f"{user}_alt{idx+1}"
            f.write(f"{uname}:{ntlm}:{lm}\n")

# --- 4. Generate variants ---
ntlm_lm_path = os.path.join(OUTPUT_DIR, "ntlm_lm.txt")
ntlm_only_path = os.path.join(OUTPUT_DIR, "ntlm_only.txt")
lm_only_path = os.path.join(OUTPUT_DIR, "lm_only.txt")
strong_path = os.path.join(OUTPUT_DIR, "strong_passwords.txt")

ntlm_lm, ntlm_only, lm_only, strong = [], [], [], []
with open(master_path, 'r', encoding='utf-8') as f:
    for line in f:
        parts = line.strip().split(':')
        if len(parts) < 3:
            continue
        _, ntlm, lm = parts
        if ntlm:
            ntlm_only.append(ntlm)
            if not lm:
                strong.append(ntlm)
        if lm:
            lm_only.append(lm)
        ntlm_lm.append(f"{ntlm}:{lm}")

with open(ntlm_lm_path, 'w', encoding='utf-8') as f:
    for l in ntlm_lm:
        f.write(l+"\n")
with open(ntlm_only_path, 'w', encoding='utf-8') as f:
    for l in ntlm_only:
        f.write(l+"\n")
with open(lm_only_path, 'w', encoding='utf-8') as f:
    for l in lm_only:
        f.write(l+"\n")
with open(strong_path, 'w', encoding='utf-8') as f:
    for l in strong:
        f.write(l+"\n")

print("All hashes have been parsed and organized correctly. See the 'organized_hashes' folder.")
