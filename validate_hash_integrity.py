#!/usr/bin/env python3
"""
Comprehensive Hash Data Validator

This script performs a complete validation of all hash data files to ensure:
1. All hash files have the correct format
2. Special cases (Jean-Marc Samson and Ashley Williams) are handled correctly
3. All data is consistent across all files
4. Data integrity is maintained

This serves as a final verification tool that can be run anytime to check the integrity
of the hash data.
"""

import os
import re
import sys
from collections import Counter

# File paths
WORKSPACE_PATH = "/workspaces/JaiziahGreene"
COMPLETE_FILE = os.path.join(WORKSPACE_PATH, "complete_user_hash_data_accurate.txt")
NTLM_LM_FILE = os.path.join(WORKSPACE_PATH, "ntlm_lm_hashes_accurate.txt")
LM_ONLY_FILE = os.path.join(WORKSPACE_PATH, "lm_only_hashes_accurate.txt")
NTLM_ONLY_FILE = os.path.join(WORKSPACE_PATH, "ntlm_only_hashes_accurate.txt")
STRONG_PASSWORDS_FILE = os.path.join(WORKSPACE_PATH, "strong_passwords_accurate.txt")
LOG_FILE = os.path.join(WORKSPACE_PATH, "hash_validation_log.txt")

# Special cases
SPECIAL_CASES = {
    "jean-marc.samson": {"ntlm": "155d1254d37e9d54bf4bd4d80e55153b", "lm": ""},
    "ashleywilliams": {"ntlm": "31c2c7446c692de275628af9a81c5d4e", "lm": ""}
}

# Regex patterns
NTLM_PATTERN = re.compile(r'^[0-9a-fA-F]{32}$')
LM_PATTERN = re.compile(r'^[0-9a-fA-F]{32}$')
COMPLETE_PATTERN = re.compile(r'^[^:]+::[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$')
NTLM_LM_PATTERN = re.compile(r'^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$')

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

def log(message, level="INFO"):
    """Log a message to both console and log file"""
    timestamp = ""  # Could add timestamp if needed
    log_message = f"[{level}] {timestamp}{message}"
    
    print(log_message)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_message + '\n')

def validate_hash_format(hash_value, hash_type):
    """Validate if a hash value has the correct format"""
    if not hash_value:
        return True  # Empty LM hash is valid
    
    pattern = NTLM_PATTERN if hash_type.upper() == 'NTLM' else LM_PATTERN
    return bool(pattern.match(hash_value))

def load_file_lines(file_path, skip_comments=True):
    """Load lines from a file, optionally skipping comments"""
    if not os.path.exists(file_path):
        raise ValidationError(f"File not found: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            if skip_comments:
                return [line.strip() for line in f 
                       if line.strip() and not line.strip().startswith('//') 
                       and not line.strip().startswith('#')]
            else:
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        raise ValidationError(f"Error reading file {file_path}: {str(e)}")

def validate_complete_hash_data():
    """Validate the complete user hash data file"""
    log("Validating complete user hash data file...")
    
    errors = []
    stats = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "special_cases": 0,
        "with_lm": 0,
        "without_lm": 0
    }
    
    # Load the file
    try:
        lines = load_file_lines(COMPLETE_FILE)
        stats["total"] = len(lines)
        
        # Process each line
        for line in lines:
            if not COMPLETE_PATTERN.match(line):
                errors.append(f"Invalid format: {line}")
                stats["invalid"] += 1
                continue
            
            # Parse the line
            parts = line.split(':')
            username = parts[0]
            ntlm = parts[2].lower() if len(parts) > 2 else ""
            lm = parts[3].lower() if len(parts) > 3 else ""
            
            # Check if NTLM is valid
            if not validate_hash_format(ntlm, 'NTLM'):
                errors.append(f"Invalid NTLM hash for {username}: {ntlm}")
                stats["invalid"] += 1
                continue
            
            # Check if LM is valid (if present)
            if lm and not validate_hash_format(lm, 'LM'):
                errors.append(f"Invalid LM hash for {username}: {lm}")
                stats["invalid"] += 1
                continue
            
            # Check special cases
            if username in SPECIAL_CASES:
                expected_ntlm = SPECIAL_CASES[username]["ntlm"]
                expected_lm = SPECIAL_CASES[username]["lm"]
                
                if ntlm != expected_ntlm:
                    errors.append(f"Special case {username} has incorrect NTLM hash. Expected: {expected_ntlm}, Got: {ntlm}")
                    stats["invalid"] += 1
                    continue
                
                if lm != expected_lm:
                    errors.append(f"Special case {username} has incorrect LM hash. Expected: {expected_lm}, Got: {lm}")
                    stats["invalid"] += 1
                    continue
                
                stats["special_cases"] += 1
            
            # Track valid entries and LM hash presence
            stats["valid"] += 1
            if lm:
                stats["with_lm"] += 1
            else:
                stats["without_lm"] += 1
    
    except ValidationError as e:
        errors.append(str(e))
        return False, stats, errors
    
    # Report results
    if errors:
        log(f"❌ Found {len(errors)} errors in complete hash data", "ERROR")
        for error in errors:
            log(f"   - {error}", "ERROR")
        return False, stats, errors
    
    log(f"✓ Complete hash data validated successfully: {stats['valid']}/{stats['total']} entries valid")
    log(f"  - With LM hash: {stats['with_lm']}")
    log(f"  - Without LM hash: {stats['without_lm']}")
    log(f"  - Special cases: {stats['special_cases']}")
    
    return True, stats, errors

def validate_variant_files():
    """Validate all variant hash files"""
    log("\nValidating variant hash files...")
    
    errors = []
    stats = {
        "ntlm_lm": {"total": 0, "valid": 0, "invalid": 0},
        "lm_only": {"total": 0, "valid": 0, "invalid": 0},
        "ntlm_only": {"total": 0, "valid": 0, "invalid": 0},
        "strong": {"total": 0, "valid": 0, "invalid": 0, "special_case_missing": False}
    }
    
    # 1. Validate NTLM:LM file
    try:
        lines = load_file_lines(NTLM_LM_FILE)
        stats["ntlm_lm"]["total"] = len(lines)
        
        for line in lines:
            if not NTLM_LM_PATTERN.match(line):
                errors.append(f"Invalid format in NTLM:LM file: {line}")
                stats["ntlm_lm"]["invalid"] += 1
                continue
            
            # Check for special case hashes (should NOT be in this file)
            for username, special in SPECIAL_CASES.items():
                if line.startswith(special["ntlm"] + ":"):
                    errors.append(f"Special case hash for {username} found in NTLM:LM file: {line}")
                    stats["ntlm_lm"]["invalid"] += 1
                    break
            else:
                stats["ntlm_lm"]["valid"] += 1
    
    except ValidationError as e:
        errors.append(str(e))
    
    # 2. Validate LM-only file
    try:
        lines = load_file_lines(LM_ONLY_FILE)
        stats["lm_only"]["total"] = len(lines)
        
        for line in lines:
            if not LM_PATTERN.match(line):
                errors.append(f"Invalid format in LM-only file: {line}")
                stats["lm_only"]["invalid"] += 1
                continue
            
            stats["lm_only"]["valid"] += 1
    
    except ValidationError as e:
        errors.append(str(e))
    
    # 3. Validate NTLM-only file
    try:
        lines = load_file_lines(NTLM_ONLY_FILE)
        stats["ntlm_only"]["total"] = len(lines)
        
        # Check for special case hashes (SHOULD be in this file)
        special_hashes = {special["ntlm"] for username, special in SPECIAL_CASES.items() if special["ntlm"]}
        found_special = set()
        
        for line in lines:
            if not NTLM_PATTERN.match(line):
                errors.append(f"Invalid format in NTLM-only file: {line}")
                stats["ntlm_only"]["invalid"] += 1
                continue
            
            # Check if this is a special case hash
            if line in special_hashes:
                found_special.add(line)
            
            stats["ntlm_only"]["valid"] += 1
        
        # Check if any special hashes are missing
        for username, special in SPECIAL_CASES.items():
            if special["ntlm"] and special["ntlm"] not in found_special:
                errors.append(f"Special case hash for {username} missing from NTLM-only file")
                stats["ntlm_only"]["invalid"] += 1
    
    except ValidationError as e:
        errors.append(str(e))
    
    # 4. Validate strong passwords file
    try:
        lines = load_file_lines(STRONG_PASSWORDS_FILE)
        stats["strong"]["total"] = len(lines)
        
        # Check for special case hashes (SHOULD be in this file)
        special_hashes = {special["ntlm"] for username, special in SPECIAL_CASES.items() if special["ntlm"]}
        found_special = set()
        
        for line in lines:
            if not NTLM_PATTERN.match(line):
                errors.append(f"Invalid format in strong passwords file: {line}")
                stats["strong"]["invalid"] += 1
                continue
            
            # Check if this is a special case hash
            if line in special_hashes:
                found_special.add(line)
            
            stats["strong"]["valid"] += 1
        
        # Check if any special hashes are missing
        missing_special = special_hashes - found_special
        if missing_special:
            errors.append(f"Special case hashes missing from strong passwords file: {', '.join(missing_special)}")
            stats["strong"]["special_case_missing"] = True
            stats["strong"]["invalid"] += len(missing_special)
    
    except ValidationError as e:
        errors.append(str(e))
    
    # Report results
    if errors:
        log(f"❌ Found {len(errors)} errors in variant files", "ERROR")
        for error in errors:
            log(f"   - {error}", "ERROR")
        return False, stats, errors
    
    log(f"✓ NTLM:LM file validated: {stats['ntlm_lm']['valid']}/{stats['ntlm_lm']['total']} entries valid")
    log(f"✓ LM-only file validated: {stats['lm_only']['valid']}/{stats['lm_only']['total']} entries valid")
    log(f"✓ NTLM-only file validated: {stats['ntlm_only']['valid']}/{stats['ntlm_only']['total']} entries valid")
    log(f"✓ Strong passwords file validated: {stats['strong']['valid']}/{stats['strong']['total']} entries valid")
    
    return True, stats, errors

def validate_file_consistency():
    """Validate consistency across hash files"""
    log("\nValidating consistency across files...")
    
    errors = []
    
    try:
        # Load all files
        complete_lines = load_file_lines(COMPLETE_FILE)
        ntlm_lm_lines = load_file_lines(NTLM_LM_FILE)
        lm_only_lines = load_file_lines(LM_ONLY_FILE)
        ntlm_only_lines = load_file_lines(NTLM_ONLY_FILE)
        strong_lines = load_file_lines(STRONG_PASSWORDS_FILE)
        
        # Extract NTLM and LM hashes from complete data
        complete_ntlm_hashes = set()
        complete_lm_hashes = set()
        complete_ntlm_lm_pairs = set()
        complete_strong_hashes = set()
        
        for line in complete_lines:
            parts = line.split(':')
            username = parts[0]
            ntlm = parts[2].lower() if len(parts) > 2 else ""
            lm = parts[3].lower() if len(parts) > 3 else ""
            
            if ntlm:
                complete_ntlm_hashes.add(ntlm)
            
            if lm:
                complete_lm_hashes.add(lm)
                complete_ntlm_lm_pairs.add(f"{ntlm}:{lm}")
            else:
                # If no LM hash, should be in strong passwords
                complete_strong_hashes.add(ntlm)
        
        # Convert variant files to sets
        ntlm_lm_set = set(ntlm_lm_lines)
        lm_only_set = set(lm_only_lines)
        ntlm_only_set = set(ntlm_only_lines)
        strong_set = set(strong_lines)
        
        # Check consistency
        # 1. All NTLM:LM pairs from complete should be in ntlm_lm_file
        missing_ntlm_lm = complete_ntlm_lm_pairs - ntlm_lm_set
        if missing_ntlm_lm:
            errors.append(f"NTLM:LM pairs missing from NTLM:LM file: {len(missing_ntlm_lm)} entries")
        
        extra_ntlm_lm = ntlm_lm_set - complete_ntlm_lm_pairs
        if extra_ntlm_lm:
            errors.append(f"Extra NTLM:LM pairs in NTLM:LM file: {len(extra_ntlm_lm)} entries")
        
        # 2. All LM hashes from complete should be in lm_only_file
        missing_lm = complete_lm_hashes - lm_only_set
        if missing_lm:
            errors.append(f"LM hashes missing from LM-only file: {len(missing_lm)} entries")
        
        extra_lm = lm_only_set - complete_lm_hashes
        if extra_lm:
            errors.append(f"Extra LM hashes in LM-only file: {len(extra_lm)} entries")
        
        # 3. All NTLM hashes from complete should be in ntlm_only_file
        missing_ntlm = complete_ntlm_hashes - ntlm_only_set
        if missing_ntlm:
            errors.append(f"NTLM hashes missing from NTLM-only file: {len(missing_ntlm)} entries")
        
        extra_ntlm = ntlm_only_set - complete_ntlm_hashes
        if extra_ntlm:
            errors.append(f"Extra NTLM hashes in NTLM-only file: {len(extra_ntlm)} entries")
        
        # 4. All strong password entries from complete should be in strong_passwords_file
        missing_strong = complete_strong_hashes - strong_set
        if missing_strong:
            errors.append(f"Strong password hashes missing from strong passwords file: {len(missing_strong)} entries")
        
        extra_strong = strong_set - complete_strong_hashes
        if extra_strong:
            errors.append(f"Extra hashes in strong passwords file: {len(extra_strong)} entries")
        
        # 5. Special cases should be consistent
        for username, special in SPECIAL_CASES.items():
            ntlm = special["ntlm"]
            
            # Should be in strong passwords file
            if ntlm not in strong_set:
                errors.append(f"Special case {username} hash missing from strong passwords file")
            
            # Should be in NTLM-only file
            if ntlm not in ntlm_only_set:
                errors.append(f"Special case {username} hash missing from NTLM-only file")
    
    except ValidationError as e:
        errors.append(str(e))
        return False, errors
    
    # Report results
    if errors:
        log(f"❌ Found {len(errors)} consistency issues", "ERROR")
        for error in errors:
            log(f"   - {error}", "ERROR")
        return False, errors
    
    log("✓ All files are consistent with each other")
    log(f"  - Complete data: {len(complete_lines)} entries")
    log(f"  - NTLM:LM pairs: {len(ntlm_lm_set)} unique pairs")
    log(f"  - LM-only hashes: {len(lm_only_set)} unique hashes")
    log(f"  - NTLM-only hashes: {len(ntlm_only_set)} unique hashes")
    log(f"  - Strong password entries: {len(strong_set)} entries")
    
    return True, errors

def analyze_hash_distribution():
    """Analyze hash distribution for patterns"""
    log("\nAnalyzing hash distribution...")
    
    try:
        complete_lines = load_file_lines(COMPLETE_FILE)
        
        # Extract NTLM and LM hashes
        ntlm_hashes = []
        lm_hashes = []
        
        for line in complete_lines:
            parts = line.split(':')
            ntlm = parts[2].lower() if len(parts) > 2 else ""
            lm = parts[3].lower() if len(parts) > 3 else ""
            
            if ntlm:
                ntlm_hashes.append(ntlm)
            
            if lm:
                lm_hashes.append(lm)
        
        # Count occurrences
        ntlm_counter = Counter(ntlm_hashes)
        lm_counter = Counter(lm_hashes)
        
        # Report most common
        log("Most common NTLM hashes (potential password reuse):")
        for ntlm, count in ntlm_counter.most_common(5):
            if count > 1:
                log(f"  - {ntlm}: {count} occurrences")
        
        log("Most common LM hashes (potential password reuse):")
        for lm, count in lm_counter.most_common(5):
            if count > 1:
                log(f"  - {lm}: {count} occurrences")
        
        # Find users with same hash
        duplicate_ntlm = {hash: count for hash, count in ntlm_counter.items() if count > 1}
        if duplicate_ntlm:
            log(f"Found {len(duplicate_ntlm)} NTLM hashes used by multiple users")
        
        duplicate_lm = {hash: count for hash, count in lm_counter.items() if count > 1}
        if duplicate_lm:
            log(f"Found {len(duplicate_lm)} LM hashes used by multiple users")
    
    except ValidationError as e:
        log(f"Error analyzing hash distribution: {str(e)}", "ERROR")

def main():
    """Main validation function"""
    # Clear the log file
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write("=== HASH DATA VALIDATION LOG ===\n\n")
    
    log("=== COMPREHENSIVE HASH DATA VALIDATION ===")
    log(f"Date: {os.popen('date').read().strip()}")
    
    # Step 1: Check if all files exist
    all_files = [COMPLETE_FILE, NTLM_LM_FILE, LM_ONLY_FILE, NTLM_ONLY_FILE, STRONG_PASSWORDS_FILE]
    missing_files = [f for f in all_files if not os.path.exists(f)]
    
    if missing_files:
        log("❌ The following files are missing:", "ERROR")
        for file in missing_files:
            log(f"   - {os.path.basename(file)}", "ERROR")
        return False
    
    # Step 2: Validate complete hash data
    complete_valid, complete_stats, complete_errors = validate_complete_hash_data()
    
    # Step 3: Validate variant files
    variant_valid, variant_stats, variant_errors = validate_variant_files()
    
    # Step 4: Validate consistency across files
    consistency_valid, consistency_errors = validate_file_consistency()
    
    # Step 5: Analyze hash distribution
    analyze_hash_distribution()
    
    # Final assessment
    log("\n=== VALIDATION SUMMARY ===")
    
    if complete_valid and variant_valid and consistency_valid:
        log("✅ ALL VALIDATIONS PASSED - Hash data integrity is 100%")
        
        # Special cases status
        log("\nSpecial Cases:")
        for username, special in SPECIAL_CASES.items():
            log(f"✅ {username}: Correctly set to NTLM={special['ntlm']} with no LM hash")
        
        return True
    else:
        log("❌ VALIDATION FAILED - Issues found in hash data", "ERROR")
        log(f"  - Complete hash data valid: {'Yes' if complete_valid else 'No'}")
        log(f"  - Variant files valid: {'Yes' if variant_valid else 'No'}")
        log(f"  - File consistency valid: {'Yes' if consistency_valid else 'No'}")
        
        # Summary of errors
        total_errors = len(complete_errors) + len(variant_errors) + len(consistency_errors)
        log(f"\nTotal errors found: {total_errors}")
        
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
