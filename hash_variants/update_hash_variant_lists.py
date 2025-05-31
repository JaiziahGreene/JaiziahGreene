#!/usr/bin/env python3
import os
from pathlib import Path
from collections import defaultdict

# Paths
BASE = Path(__file__).parent
FOUND_DIR = BASE / 'All Found Hashes'
OUT_DIR = BASE / 'updated_lists'
OUT_DIR.mkdir(exist_ok=True)

# Helper: parse found files (NTLM:password)
def parse_found_hashes():
    found_ntlm_to_pass = dict()
    for found_file in FOUND_DIR.glob('*.txt'):
        with open(found_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip().replace('\r','')
                if not line or ':' not in line: continue
                ntlm, pw = line.split(':', 1)
                found_ntlm_to_pass[ntlm.lower()] = pw
    return found_ntlm_to_pass

# Helper: parse ntlm_lm_pairs.txt
def parse_ntlm_lm_pairs():
    ntlm_to_lm = dict()
    lm_to_ntlm = dict()
    with open(BASE/'ntlm_lm_pairs.txt', 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('//'): continue
            if ':' in line:
                ntlm, lm = line.split(':', 1)
                ntlm, lm = ntlm.lower(), lm.lower()
                ntlm_to_lm[ntlm] = lm
                if lm: lm_to_ntlm[lm] = ntlm
    return ntlm_to_lm, lm_to_ntlm

def write_lines(path, lines):
    with open(path, 'w', encoding='utf-8') as f:
        for l in lines:
            f.write(l + '\n')

def main():
    found_ntlm_to_pass = parse_found_hashes()
    found_ntlm = set(found_ntlm_to_pass)
    ntlm_to_lm, lm_to_ntlm = parse_ntlm_lm_pairs()
    found_lm = set(ntlm_to_lm[ntlm] for ntlm in found_ntlm if ntlm in ntlm_to_lm and ntlm_to_lm[ntlm])

    # ntlm_only.txt
    with open(BASE/'ntlm_only.txt', 'r', encoding='utf-8', errors='ignore') as f:
        ntlm_hashes = [l.strip().lower() for l in f if l.strip() and not l.startswith('//')]
    found_ntlm_only = [f"{h}:{found_ntlm_to_pass[h]}" for h in ntlm_hashes if h in found_ntlm_to_pass]
    left_ntlm_only = [h for h in ntlm_hashes if h not in found_ntlm_to_pass]
    write_lines(OUT_DIR/'ntlm_only_found.txt', found_ntlm_only)
    write_lines(OUT_DIR/'ntlm_only_left.txt', left_ntlm_only)

    # lm_only.txt
    with open(BASE/'lm_only.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lm_hashes = [l.strip().lower() for l in f if l.strip() and not l.startswith('//')]
    found_lm_only = []
    for lm in lm_hashes:
        if lm in found_lm:
            ntlm = lm_to_ntlm.get(lm)
            pw = found_ntlm_to_pass.get(ntlm, '')
            found_lm_only.append(f"{lm}:{ntlm}:{pw}")
    left_lm_only = [lm for lm in lm_hashes if lm not in found_lm]
    write_lines(OUT_DIR/'lm_only_found.txt', found_lm_only)
    write_lines(OUT_DIR/'lm_only_left.txt', left_lm_only)

    # ntlm_lm_pairs.txt
    with open(BASE/'ntlm_lm_pairs.txt', 'r', encoding='utf-8', errors='ignore') as f:
        pairs = [l.strip() for l in f if l.strip() and not l.startswith('//')]
    found_pairs = []
    left_pairs = []
    for line in pairs:
        if ':' in line:
            ntlm, lm = line.split(':', 1)
            ntlm, lm = ntlm.lower(), lm.lower()
            if ntlm in found_ntlm_to_pass:
                found_pairs.append(f"{ntlm}:{lm}:{found_ntlm_to_pass[ntlm]}")
            else:
                left_pairs.append(f"{ntlm}:{lm}")
    write_lines(OUT_DIR/'ntlm_lm_pairs_found.txt', found_pairs)
    write_lines(OUT_DIR/'ntlm_lm_pairs_left.txt', left_pairs)

    # strong_passwords.txt
    with open(BASE/'strong_passwords.txt', 'r', encoding='utf-8', errors='ignore') as f:
        strong_hashes = [l.strip().lower() for l in f if l.strip() and not l.startswith('//')]
    found_strong = [f"{h}:{found_ntlm_to_pass[h]}" for h in strong_hashes if h in found_ntlm_to_pass]
    left_strong = [h for h in strong_hashes if h not in found_ntlm_to_pass]
    write_lines(OUT_DIR/'strong_passwords_found.txt', found_strong)
    write_lines(OUT_DIR/'strong_passwords_left.txt', left_strong)

if __name__ == '__main__':
    main()
