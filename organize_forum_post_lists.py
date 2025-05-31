import os
import glob
from collections import defaultdict

# Define all relevant input files (old and new)
REFERENCE_DIR = '/workspaces/JaiziahGreene/hash_variants/updated_lists'
NEW_DIR = '/workspaces/JaiziahGreene/Newly Found Hashes by Forum Member'
OUTPUT_DIR = '/workspaces/JaiziahGreene/forum_post_updated_lists'

# File patterns for each category
CATEGORIES = {
    'ntlm_lm_pairs': {
        'left': [
            os.path.join(REFERENCE_DIR, 'ntlm_lm_pairs_left.txt')
        ],
        'found': [
            os.path.join(REFERENCE_DIR, 'ntlm_lm_pairs_found.txt')
        ]
    },
    'ntlm_only': {
        'left': [
            os.path.join(REFERENCE_DIR, 'ntlm_only_left.txt'),
            *glob.glob(os.path.join(NEW_DIR, '*ntlm_only_left*.txt'))
        ],
        'found': [
            os.path.join(REFERENCE_DIR, 'ntlm_only_found.txt'),
            *glob.glob(os.path.join(NEW_DIR, '*ntlm_only_found*.txt'))
        ]
    },
    'lm_only': {
        'left': [
            os.path.join(REFERENCE_DIR, 'lm_only_left.txt')
        ],
        'found': [
            os.path.join(REFERENCE_DIR, 'lm_only_found.txt'),
            *glob.glob(os.path.join(NEW_DIR, '*lm_only_found*.txt'))
        ]
    },
    'strong_passwords': {
        'left': [
            os.path.join(REFERENCE_DIR, 'strong_passwords_left.txt')
        ],
        'found': [
            os.path.join(REFERENCE_DIR, 'strong_passwords_found.txt')
        ]
    }
}

# Helper to read all lines from a list of files
def read_lines(files):
    lines = set()
    for f in files:
        if os.path.exists(f):
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.add(line)
    return lines

def write_lines(filepath, lines):
    with open(filepath, 'w', encoding='utf-8') as fh:
        for line in sorted(lines):
            fh.write(line + '\n')

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # Clean up output dir first
    for f in glob.glob(os.path.join(OUTPUT_DIR, '*.txt')):
        os.remove(f)

    for cat, files in CATEGORIES.items():
        found_lines = read_lines(files['found'])
        left_lines = read_lines(files['left'])

        # For pairs, LM only, and strong, found/left may be hash:pass or hash:hash:pass
        found_hashes = set()
        for l in found_lines:
            if ':' in l:
                found_hashes.add(l.split(':')[0])
            else:
                found_hashes.add(l)

        # Remove found hashes from left
        left_cleaned = set()
        for l in left_lines:
            if ':' in l:
                h = l.split(':')[0]
            else:
                h = l
            if h not in found_hashes:
                left_cleaned.add(l)

        # Write found and left
        write_lines(os.path.join(OUTPUT_DIR, f'{cat}_found.txt'), found_lines)
        write_lines(os.path.join(OUTPUT_DIR, f'{cat}_left.txt'), left_cleaned)

    # This script will:
    # - Remove NTLMs with empty LM fields from ntlm_lm_pairs_left.txt
    # - Place them in ntlm_only_left.txt or strong_passwords_left.txt as appropriate
    # - Ensure all lists are mutually exclusive and correct

    base = '/workspaces/JaiziahGreene/forum_post_updated_lists/'

    # Read all lists
    with open(base + 'ntlm_lm_pairs_left.txt', 'r') as f:
        pairs = [line.strip() for line in f if line.strip()]
    with open(base + 'ntlm_only_left.txt', 'r') as f:
        ntlm_only = set(line.strip() for line in f if line.strip())
    with open(base + 'strong_passwords_left.txt', 'r') as f:
        strong = set(line.strip() for line in f if line.strip())

    # Separate true pairs and NTLMs with empty LM fields
    true_pairs = []
    ntlm_empty_lm = []
    for line in pairs:
        if ':' in line:
            ntlm, lm = line.split(':', 1)
            if lm:
                true_pairs.append(line)
            else:
                ntlm_empty_lm.append(ntlm)
        else:
            ntlm_empty_lm.append(line)

    # Remove all ntlm_empty_lm from ntlm_only and strong to avoid duplicates
    ntlm_only = ntlm_only - set(ntlm_empty_lm)
    strong = strong - set(ntlm_empty_lm)

    # Place each ntlm_empty_lm in strong if it was there originally, else in ntlm_only
    new_strong = [h for h in ntlm_empty_lm if h in strong]
    new_ntlm_only = [h for h in ntlm_empty_lm if h not in strong]

    # Update lists
    with open(base + 'ntlm_lm_pairs_left.txt', 'w') as f:
        for line in true_pairs:
            f.write(line + '\n')
    with open(base + 'ntlm_only_left.txt', 'w') as f:
        for h in sorted(ntlm_only | set(new_ntlm_only)):
            f.write(h + '\n')
    with open(base + 'strong_passwords_left.txt', 'w') as f:
        for h in sorted(strong | set(new_strong)):
            f.write(h + '\n')

    # Rebuild strong_passwords_left.txt and ntlm_only_left.txt to be mutually exclusive and correct
    with open(base + 'ntlm_lm_pairs_left.txt', 'r') as f:
        pair_ntlms = set(line.split(':', 1)[0] for line in f if ':' in line and line.split(':', 1)[1])
    with open(base + 'ntlm_only_left.txt', 'r') as f:
        ntlm_only = set(line.strip() for line in f if line.strip())
    # Strong passwords: NTLMs not in any pair
    strong = ntlm_only - pair_ntlms
    # NTLM only: NTLMs that are in a pair (with LM not found)
    ntlm_only_true = ntlm_only & pair_ntlms
    with open(base + 'strong_passwords_left.txt', 'w') as f:
        for h in sorted(strong):
            f.write(h + '\n')
    with open(base + 'ntlm_only_left.txt', 'w') as f:
        for h in sorted(ntlm_only_true):
            f.write(h + '\n')
    print('strong_passwords_left.txt and ntlm_only_left.txt rebuilt and mutually exclusive.')

    print('All lists merged, deduplicated, and written to', OUTPUT_DIR)
    print('Lists updated and made mutually exclusive.')

if __name__ == '__main__':
    main()
