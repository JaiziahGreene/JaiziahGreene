# Hash Data Correction & Variant Files Report

## Summary of Changes
The data integrity issue with hash values in the original hash data file has been fixed. In particular:

- Fixed jean-marc.samson's hash from `333dcedf258172e5e001b7d0acd7752c:bd77b745c8b048ab2eac541d19bc1646` to the correct value `155d1254d37e9d54bf4bd4d80e55153b` (no LM hash)
- Removed the `jean-marc.samson_variant` entry which had incorrect hash values
- Removed entries with passwords already found (118 entries)
- Created four variant hash files for different purposes

## File Statistics
1. Original file (`complete_user_hash_data.txt`): 727 entries
2. Fixed file (`complete_user_hash_data_fixed.txt`): 608 entries
   - 118 entries with passwords removed
   - 1 entry with incorrect hash fixed

## Variant Files

### 1. NTLM:LM Hashes (`ntlm_lm_hashes.txt`)
- Format: `NTLM:LM` (just the hashes, no usernames)
- Purpose: Use for cracking tools that take hash pairs
- Entries: 607 (users with both NTLM and LM hashes)

### 2. NTLM-only Hashes (`ntlm_only_hashes.txt`)
- Format: `username:NTLM`
- Purpose: Focus on just NTLM hashes
- Entries: 608 (all users with NTLM hashes)

### 3. LM-only Hashes (`lm_only_hashes.txt`)
- Format: `username:LM`
- Purpose: Focus on just LM hashes, which are typically easier to crack
- Entries: 607 (all users with LM hashes)

### 4. Strong Passwords (`strong_passwords.txt`)
- Format: `username:NTLM`
- Purpose: Contains entries with only NTLM hash (no LM hash), indicating stronger passwords
- Entries: 1 (jean-marc.samson)

## Data Integrity Issue Analysis
The script that generated the original hash data file (`merge_all_hashes_comprehensive.py`) appeared to have assigned incorrect hash values to jean-marc.samson. All three mimikatz dump files (PC 2, PC 3, and PC 4) consistently show jean-marc.samson's NTLM hash as `155d1254d37e9d54bf4bd4d80e55153b`, but the output file contained `333dcedf258172e5e001b7d0acd7752c:bd77b745c8b048ab2eac541d19bc1646` instead.

This could be due to:
1. Hash values from different users being incorrectly merged
2. Parsing errors in the mimikatz output files
3. Logic errors in the merging algorithm

## Usage for Password Cracking
1. **If targeting weaker passwords:**
   - Use `lm_only_hashes.txt` as LM hashes are significantly easier to crack
   - Once the LM hash is cracked, it can be used to derive the NTLM hash

2. **If targeting specific users:**
   - Use `ntlm_only_hashes.txt` to focus on specific usernames
   - For jean-marc.samson, note that this user appears to have a stronger password (no LM hash present)

3. **For bulk cracking:**
   - Use `ntlm_lm_hashes.txt` with tools that support the NTLM:LM format

## Next Steps
- Consider trying to re-extract all hash data from the original mimikatz dumps to ensure there are no other integrity issues
- Use hashcat or John the Ripper with the appropriate hash format for each variant file
- For jean-marc.samson's stronger password, consider using a larger wordlist or more advanced rules

## Technical Details
The `strong_passwords.txt` file contains only one entry (jean-marc.samson) because this is the only user with just an NTLM hash and no corresponding LM hash. This typically indicates the use of a longer or more complex password that couldn't generate an LM hash.
