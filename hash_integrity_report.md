# Hash Data Integrity Report

## Summary

- Total unique users: 744
- Users with NTLM hashes: 744
- Users with LM hashes: 703
- Strong password users (NTLM only): 41
- Hash discrepancies fixed: 42

## Files Created

1. **complete_user_hash_data_accurate.txt** - Complete hash data with username:password:ntlm:lm format
2. **ntlm_lm_hashes_accurate.txt** - NTLM:LM pairs (for tools that use this format)
3. **lm_only_hashes_accurate.txt** - LM hashes only (easier to crack)
4. **ntlm_only_hashes_accurate.txt** - NTLM hashes only
5. **strong_passwords_accurate.txt** - Users with strong passwords (NTLM only)

## Hash Integrity Issues Fixed

The following discrepancies were found and fixed:

| Username | Original NTLM | Accurate NTLM | Original LM | Accurate LM |
|----------|--------------|--------------|-------------|------------|
| Afh731044 | d9b9bf9f9f8a3bdb9c23322cf719624b | 2ca9b0bbe89c1fc73d8b8ae1f7fdd67a | 7197622d599c3847acbe7d0765d6db3a | (none) |
| ashleywilliams | d16ef45a777ee7f936bffd748146bd4c | 31c2c7446c692de275628af9a81c5d4e | 3c2985bbeae7086d4fa5418705880aa0 | (none) |
| avincer | 4a132218f85a4cf47ae9f482c2ceebdf | 857c1ddeb2793e7d6b1317645b2f8c13 | 5a0f3036bc17d29dc2265b23734e0dac | (none) |
| bhc470510@gnspes.ca | e3a63e0f0c68b0a32cb61453e5db205a | 9ed24220d4ca734907a2ba6c5855c569 | 1c276230715129d300a7af7ac715311e | (none) |
| blg821324@gnspes.ca | 24346a370864dcf8b635c5db3be84049 | 697f02cb3b1145090611a28d91d6df25 | d9eac3cb19c7d5665bbfe08b771ee483 | (none) |
| bmm853574 | efb1943a93c43644fa1f539ca8eb5e69 | 4dd0a95be75fd2c18cddb643380e9e73 | 91722d792404e3aa4c4e64869a08c817 | (none) |
| bmm853574@gnspes.ca | 4dbd3bbad66b29a42a614958fa2077b3 | 4dd0a95be75fd2c18cddb643380e9e73 | aaa430cb18848bd1c2a20cae7226e17d | (none) |
| cjm890816 | 78e1e554a41885b946d3131ed8f48c4a | 849379afac7157f9bfa517ba168b45ad | 4cc5ed365f6c354f695109ab020e401c | (none) |
| dj729526 | d8f0f48bfd296dbfc9cf850450f7bca2 | 57661758b1c7a7207c96d4c7afca7ee3 | 9b330e961b3594bbb75e0c8d76954a50 | (none) |
| dj729526@gnspes.ca | b0b6841fd50379c949360a59670ad960 | 57661758b1c7a7207c96d4c7afca7ee3 | ff12c2f548a15076695109ab020e401c | (none) |
| dra854861@gnspes.ca | 81cd25eb0010ef533b08c93bee53d8d4 | fc525c9683e8fe067095ba2ddc971889 | a11f29694630b361c20ba3bc60904793 | b34ce522c3e4c87722c34254e51bff62 |
| dra854861@gnspes.ca_variant | fc525c9683e8fe067095ba2ddc971889 | 81cd25eb0010ef533b08c93bee53d8d4 | (empty) | a11f29694630b361c20ba3bc60904793 |
| fpe862567 | 2aaace54d6eca6cf20912c5e8f8cc50e | 210a54025c8998ba72a8d527460ef713 | 50e74e91218e88a1f36a1f81489ab666 | (none) |
| her081126@gnspes.ca | 9f5cb32ee9257684dff86ee6a196a426 | 86ee3fd788cdcf86565461866f1e03d2 | c987432bf3e8794f996615815b64fd2d | (none) |
| hlr586398 | 8d08abbaa8b93ace6e74bafd6f246335 | 69afbfee2f9988d8ba73cc5f6e7a5008 | a3813b37f8f609231104594f8c2ef12b | (none) |
| hsx761637 | 90a598a99a70cdb8d51dee2505a8bece | a6788df690f3e6ed90c4092b60e5f034 | 8f5b571575a4e6fccca11ef51ad1ba6b | (none) |
| jean-marc.samson | 333dcedf258172e5e001b7d0acd7752c | 155d1254d37e9d54bf4bd4d80e55153b | bd77b745c8b048ab2eac541d19bc1646 | (none) |
| kadr861916@gnspes | a3323d3104985d8b5e3592e31e034cf3 | b442fcf0d2b79e7fa4a30bdbbb450451 | da4e27038056d1cee46c44d55f6c0c3d | (none) |
| kadr861916@gnspes.ca | 776e153a5cf5cc664aeebdc0818f8c0f | b442fcf0d2b79e7fa4a30bdbbb450451 | 07c5efa2fc20f7eda741b83a5fd5fed3 | (none) |
| ked174524 | 98eae1d209bdedf4957d47c5c8e995b1 | 6aafc5ee06f56a497f76063218f99a89 | 6d5507e91b5bec7db75e0c8d76954a50 | (none) |

*... and 22 more discrepancies.*


## Strong Password Users (NTLM only)

These users have only NTLM hashes (no LM hashes), indicating they likely have stronger passwords:

1. Afh731044
2. WDAGUtilityAccount
3. ashleywilliams
4. avincer
5. bhc470510@gnspes.ca
6. blg821324@gnspes.ca
7. bmm853574
8. bmm853574@gnspes.ca
9. cjm890816
10. dj729526
11. dj729526@gnspes.ca
12. fpe862567
13. her081126@gnspes.ca
14. hlr586398
15. hsx761637
16. jean-marc.samson
17. kadr861916@gnspes
18. kadr861916@gnspes.ca
19. ked174524
20. koa174516

*... and 21 more users.*
