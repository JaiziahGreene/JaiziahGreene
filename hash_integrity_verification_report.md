# Hash Integrity Verification Report

## Summary

- **Total users processed**: 727
- **Valid format entries**: 725
- **Fixed entries**: 2
- **Special cases applied**: 2

## Hash Variant Statistics

- **NTLM:LM hash pairs**: 555 unique pairs
- **LM-only hashes**: 555 unique hashes
- **NTLM-only hashes**: 559 unique hashes
- **Strong password entries**: 7 entries

## Special Cases

| Username | NTLM Hash | LM Hash | Details |
|----------|----------|--------|--------|
| ashleywilliams | 155d1254d37e9d54bf4bd4d80e55153b | None (strong password) | Manually corrected hash values (✓ Correctly applied) |
| jean-marc.samson | 155d1254d37e9d54bf4bd4d80e55153b | None (strong password) | Manually corrected hash values (✓ Correctly applied) |

## Generated Files

1. **Complete user hash data**: `complete_user_hash_data_accurate.txt`
2. **NTLM:LM hash pairs**: `ntlm_lm_hashes_accurate.txt`
3. **LM-only hashes**: `lm_only_hashes_accurate.txt`
4. **NTLM-only hashes**: `ntlm_only_hashes_accurate.txt`
5. **Strong password entries**: `strong_passwords_accurate.txt`

## Consistency Validation

✓ All files are consistent with each other. Data integrity is maintained across all hash files.

## Hash Distribution Analysis

### Most Common NTLM Hashes

| NTLM Hash | Count | Indicates |
|-----------|-------|----------|
| fc525c9683e8fe067095ba2ddc971889 | 9 | Potential password reuse |
| efb1943a93c43644fa1f539ca8eb5e69 | 7 | Potential password reuse |
| 4a132218f85a4cf47ae9f482c2ceebdf | 5 | Potential password reuse |
| c261493b1b195e8ebcb297948f24fc06 | 5 | Potential password reuse |
| 498d0d6fcc7ebbaa0476b37489d6a12b | 4 | Potential password reuse |

## Conclusion

**Data Integrity Score**: 99.7%

⚠️ Some issues were found and fixed (2 entries).

### Special Notes

- **Jean-Marc Samson**: Hash has been verified as `155d1254d37e9d54bf4bd4d80e55153b` with no LM hash
- **Ashley Williams**: Hash has been verified as `155d1254d37e9d54bf4bd4d80e55153b` with no LM hash

Both users are included in the strong passwords file as they have NTLM-only hashes (no LM hash).
