# Hash Validation Report

This report summarizes the validation of hash files.

## File Statistics

| File | Status | Data Lines | Format |
|------|--------|------------|--------|
| complete_user_hash_data_accurate.txt | ✅ Good | 744 | username:password:ntlm(:lm)? |
| ntlm_lm_hashes_accurate.txt | ✅ Good | 703 | ntlm:lm |
| ntlm_only_hashes_accurate.txt | ✅ Good | 744 | ntlm hash only |
| lm_only_hashes_accurate.txt | ✅ Good | 703 | lm hash only |
| strong_passwords_accurate.txt | ✅ Good | 41 | ntlm hash only (strong passwords) |

## Format Validation

| File | Format Valid | Invalid Lines |
|------|-------------|---------------|
| complete_user_hash_data_accurate.txt | ✅ Valid | 0 |
| ntlm_lm_hashes_accurate.txt | ✅ Valid | 0 |
| ntlm_only_hashes_accurate.txt | ✅ Valid | 0 |
| lm_only_hashes_accurate.txt | ✅ Valid | 0 |
| strong_passwords_accurate.txt | ✅ Valid | 0 |

## Special Checks

### Jean-Marc Samson Hash Check

Overall: ✅ PASS

| File | Status | Entries Found |
|------|--------|---------------|
| complete_user_hash_data_accurate.txt | ✅ Found | 1 |
| strong_passwords_accurate.txt | ✅ Found | 1 |

Entries found in **complete_user_hash_data_accurate.txt**:

- `jean-marc.samson::155d1254d37e9d54bf4bd4d80e55153b` (Match: exact)

Entries found in **strong_passwords_accurate.txt**:

- `155d1254d37e9d54bf4bd4d80e55153b` (Match: exact)

### Ashley Williams Hash Check

Overall: ✅ PASS

| File | Status | Entries Found |
|------|--------|---------------|
| strong_passwords_accurate.txt | ✅ Found | 1 |

Entries found in **strong_passwords_accurate.txt**:

- `155d1254d37e9d54bf4bd4d80e55153b` (Match: exact)


## Cross-Reference Checks

### Strong Passwords Not in NTLM:LM File

Status: ✅ PASS - 0 overlapping entries


## Summary

- File formats: ✅ PASS
- Special checks: ✅ PASS
- Cross-references: ✅ PASS

**Overall Validation: ✅ PASS**

Report generated on: Sat May 24 01:56:43 UTC 2025
