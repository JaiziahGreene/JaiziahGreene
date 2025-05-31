import os
import glob
from collections import defaultdict

REFERENCE_DIR = '/workspaces/JaiziahGreene/hash_variants/updated_lists'
NEW_DIR = '/workspaces/JaiziahGreene/Newly Found Hashes by Forum Member'
OUTPUT_DIR = '/workspaces/JaiziahGreene/V2 Regen for Forum Update'

# Gather all found files from the forum member folder
forum_found_files = glob.glob(os.path.join(NEW_DIR, '*found*.txt'))

CATEGORIES = {
    'ntlm_lm_pairs': {
        'left': [
            os.path.join(REFERENCE_DIR, 'ntlm_lm_pairs_left.txt')
        ],
        'found': [
            os.path.join(REFERENCE_DIR, 'ntlm_lm_pairs_found.txt')
        ] + [f for f in forum_found_files if 'lm_pairs' in f or 'ntlm_lm' in f]
    },
    'ntlm_only': {
        'left': [
            os.path.join(REFERENCE_DIR, 'ntlm_only_left.txt'),
            *glob.glob(os.path.join(NEW_DIR, '*ntlm_only_left*.txt'))
        ],
        'found': [
            os.path.join(REFERENCE_DIR, 'ntlm_only_found.txt'),
            *[f for f in forum_found_files if 'ntlm_only_found' in f or (f.endswith('found.txt') and 'lm_only' not in f and 'lm_pairs' not in f)]
        ]
    },
    'lm_only': {
        'left': [
            os.path.join(REFERENCE_DIR, 'lm_only_left.txt')
        ],
        'found': [
            os.path.join(REFERENCE_DIR, 'lm_only_found.txt'),
            *[f for f in forum_found_files if 'lm_only_found' in f]
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
    for f in glob.glob(os.path.join(OUTPUT_DIR, '*.txt')):
        os.remove(f)

    for cat, files in CATEGORIES.items():
        found_lines = read_lines(files['found'])
        left_lines = read_lines(files['left'])

        found_hashes = set()
        for l in found_lines:
            if ':' in l:
                found_hashes.add(l.split(':')[0])
            else:
                found_hashes.add(l)

        left_cleaned = set()
        for l in left_lines:
            if ':' in l:
                h = l.split(':')[0]
            else:
                h = l
            if h not in found_hashes:
                left_cleaned.add(l)

        write_lines(os.path.join(OUTPUT_DIR, f'{cat}_found.txt'), found_lines)
        write_lines(os.path.join(OUTPUT_DIR, f'{cat}_left.txt'), left_cleaned)

    base = OUTPUT_DIR + '/'
    with open(base + 'ntlm_lm_pairs_left.txt', 'r') as f:
        pairs = [line.strip() for line in f if line.strip()]
    with open(base + 'ntlm_only_left.txt', 'r') as f:
        ntlm_only = set(line.strip() for line in f if line.strip())
    with open(base + 'strong_passwords_left.txt', 'r') as f:
        strong = set(line.strip() for line in f if line.strip())

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

    ntlm_only = ntlm_only - set(ntlm_empty_lm)
    strong = strong - set(ntlm_empty_lm)

    new_strong = [h for h in ntlm_empty_lm if h in strong]
    new_ntlm_only = [h for h in ntlm_empty_lm if h not in strong]

    with open(base + 'ntlm_lm_pairs_left.txt', 'w') as f:
        for line in true_pairs:
            f.write(line + '\n')
    with open(base + 'ntlm_only_left.txt', 'w') as f:
        for h in sorted(ntlm_only | set(new_ntlm_only)):
            f.write(h + '\n')
    with open(base + 'strong_passwords_left.txt', 'w') as f:
        for h in sorted(strong | set(new_strong)):
            f.write(h + '\n')

    with open(base + 'ntlm_lm_pairs_left.txt', 'r') as f:
        pair_ntlms = set(line.split(':', 1)[0] for line in f if ':' in line and line.split(':', 1)[1])
    with open(base + 'ntlm_only_left.txt', 'r') as f:
        ntlm_only = set(line.strip() for line in f if line.strip())
    strong = ntlm_only - pair_ntlms
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
