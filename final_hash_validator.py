#!/usr/bin/env python3
"""
Final Hash Validator

This script creates a final validation report for all our hash files.
"""

import os
import sys
import re
import json

def validate_all_files():
    """Validate all hash files and create a summary report"""
    workspace_path = "/workspaces/JaiziahGreene"
    output_report = os.path.join(workspace_path, "hash_validation_report.md")
    
    print("Starting comprehensive hash validation...")
    
    # List of files to validate
    files = {
        "complete_user_hash_data_accurate.txt": "username:password:ntlm(:lm)?",
        "ntlm_lm_hashes_accurate.txt": "ntlm:lm",
        "ntlm_only_hashes_accurate.txt": "ntlm hash only",
        "lm_only_hashes_accurate.txt": "lm hash only",
        "strong_passwords_accurate.txt": "ntlm hash only (strong passwords)"
    }
    
    # Special checks
    special_checks = {
        "jean_marc_check": {
            "username": "jean-marc.samson",
            "expected_ntlm": "155d1254d37e9d54bf4bd4d80e55153b",
            "check_files": ["complete_user_hash_data_accurate.txt", "strong_passwords_accurate.txt"]
        },
        "ashley_check": {
            "username": "ashleywilliams",
            "expected_ntlm": "155d1254d37e9d54bf4bd4d80e55153b",  
            "check_files": ["strong_passwords_accurate.txt"]
        }
    }
    
    results = {
        "file_stats": {},
        "format_checks": {},
        "special_checks": {},
        "cross_references": {}
    }
    
    # 1. Collect file statistics
    for filename, desc in files.items():
        filepath = os.path.join(workspace_path, filename)
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    all_lines = f.readlines()
                    data_lines = [l.strip() for l in all_lines if l.strip() and not l.strip().startswith('//') and not l.strip().startswith('#')]
                    results["file_stats"][filename] = {
                        "exists": True,
                        "readable": os.access(filepath, os.R_OK),
                        "total_lines": len(all_lines),
                        "data_lines": len(data_lines),
                        "description": desc
                    }
            except Exception as e:
                results["file_stats"][filename] = {
                    "exists": True,
                    "error": str(e),
                    "description": desc
                }
        else:
            results["file_stats"][filename] = {
                "exists": False,
                "description": desc
            }
    
    # 2. Validate formats
    # Define format patterns
    patterns = {
        "complete_user_hash_data_accurate.txt": r'^[^:]+:[^:]*:[a-fA-F0-9]{32}(:[a-fA-F0-9]{32})?$',
        "ntlm_lm_hashes_accurate.txt": r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$',
        "ntlm_only_hashes_accurate.txt": r'^[a-fA-F0-9]{32}$',
        "lm_only_hashes_accurate.txt": r'^[a-fA-F0-9]{32}$',
        "strong_passwords_accurate.txt": r'^[a-fA-F0-9]{32}$'
    }
    
    for filename, pattern in patterns.items():
        filepath = os.path.join(workspace_path, filename)
        if os.path.exists(filepath) and os.access(filepath, os.R_OK):
            invalid_lines = []
            with open(filepath, 'r') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('//') or line.startswith('#'):
                        continue
                    
                    if not re.match(pattern, line):
                        invalid_lines.append((i, line))
                        if len(invalid_lines) >= 10:  # Sample size
                            break
            
            results["format_checks"][filename] = {
                "is_valid": len(invalid_lines) == 0,
                "invalid_count": len(invalid_lines),
                "invalid_sample": invalid_lines[:10]
            }
    
    # 3. Special checks
    for check_name, check_info in special_checks.items():
        username = check_info["username"]
        expected_ntlm = check_info["expected_ntlm"]
        check_results = {}
        
        for filename in check_info["check_files"]:
            filepath = os.path.join(workspace_path, filename)
            if not os.path.exists(filepath) or not os.access(filepath, os.R_OK):
                check_results[filename] = {"status": "skipped", "reason": "file not accessible"}
                continue
                
            found_entries = []
            is_hash_only = "only" in files.get(filename, "")
                
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('//') or line.startswith('#'):
                        continue
                        
                    if is_hash_only:
                        if line == expected_ntlm:
                            found_entries.append({"match": "exact", "line": line})
                    else:
                        if username in line:
                            found_entries.append({"match": "username", "line": line})
                            
                            # Check if NTLM hash is correct
                            parts = line.split(':')
                            if len(parts) >= 3 and parts[2] == expected_ntlm:
                                found_entries[-1]["match"] = "exact"
            
            check_results[filename] = {
                "found_entries": len(found_entries),
                "entries": found_entries,
                "status": "pass" if found_entries else "fail"
            }
        
        results["special_checks"][check_name] = check_results
    
    # 4. Cross-reference checks
    
    # 4.1. Check that strong passwords are only in NTLM-only file
    strong_passwords_file = os.path.join(workspace_path, "strong_passwords_accurate.txt")
    ntlm_lm_file = os.path.join(workspace_path, "ntlm_lm_hashes_accurate.txt")
    
    strong_passwords = set()
    ntlm_lm_hashes = {}
    
    if os.path.exists(strong_passwords_file) and os.access(strong_passwords_file, os.R_OK):
        with open(strong_passwords_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('#'):
                    continue
                strong_passwords.add(line)
    
    if os.path.exists(ntlm_lm_file) and os.access(ntlm_lm_file, os.R_OK):
        with open(ntlm_lm_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('#'):
                    continue
                if ':' in line:
                    ntlm, lm = line.split(':', 1)
                    ntlm_lm_hashes[ntlm] = lm
    
    # Check for overlap
    overlap = []
    for sp in strong_passwords:
        if sp in ntlm_lm_hashes:
            overlap.append(sp)
    
    results["cross_references"]["strong_passwords_in_ntlm_lm"] = {
        "overlap_count": len(overlap),
        "status": "pass" if len(overlap) == 0 else "fail",
        "overlap_sample": overlap[:10]
    }
    
    # 5. Generate report
    with open(output_report, 'w') as f:
        f.write("# Hash Validation Report\n\n")
        f.write("This report summarizes the validation of hash files.\n\n")
        
        # File statistics
        f.write("## File Statistics\n\n")
        f.write("| File | Status | Data Lines | Format |\n")
        f.write("|------|--------|------------|--------|\n")
        for filename, stats in results["file_stats"].items():
            status = "✅ Good" if stats.get("exists") and stats.get("readable") else "❌ Issue"
            data_lines = stats.get("data_lines", "N/A")
            description = stats.get("description", "")
            f.write(f"| {filename} | {status} | {data_lines} | {description} |\n")
        
        # Format checks
        f.write("\n## Format Validation\n\n")
        f.write("| File | Format Valid | Invalid Lines |\n")
        f.write("|------|-------------|---------------|\n")
        for filename, check in results["format_checks"].items():
            valid = "✅ Valid" if check.get("is_valid") else f"❌ Invalid ({check.get('invalid_count')})"
            f.write(f"| {filename} | {valid} | {check.get('invalid_count', 'N/A')} |\n")
        
        if any(not check.get("is_valid", True) for check in results["format_checks"].values()):
            f.write("\n### Invalid Format Samples\n\n")
            for filename, check in results["format_checks"].items():
                if not check.get("is_valid", True):
                    f.write(f"**{filename}**:\n\n")
                    for line_num, line in check.get("invalid_sample", []):
                        f.write(f"- Line {line_num}: `{line}`\n")
                    f.write("\n")
        
        # Special checks
        f.write("\n## Special Checks\n\n")
        
        for check_name, check_results in results["special_checks"].items():
            if check_name == "jean_marc_check":
                f.write("### Jean-Marc Samson Hash Check\n\n")
            elif check_name == "ashley_check":
                f.write("### Ashley Williams Hash Check\n\n")
            else:
                f.write(f"### {check_name}\n\n")
            
            all_pass = all(r.get("status") == "pass" for r in check_results.values())
            overall = "✅ PASS" if all_pass else "❌ FAIL"
            f.write(f"Overall: {overall}\n\n")
            
            f.write("| File | Status | Entries Found |\n")
            f.write("|------|--------|---------------|\n")
            for filename, result in check_results.items():
                status = "✅ Found" if result.get("status") == "pass" else "❌ Missing"
                count = result.get("found_entries", 0)
                f.write(f"| {filename} | {status} | {count} |\n")
            
            for filename, result in check_results.items():
                entries = result.get("entries", [])
                if entries:
                    f.write(f"\nEntries found in **{filename}**:\n\n")
                    for entry in entries:
                        match_type = entry.get("match", "")
                        line = entry.get("line", "")
                        f.write(f"- `{line}` (Match: {match_type})\n")
            f.write("\n")
        
        # Cross-reference checks
        f.write("\n## Cross-Reference Checks\n\n")
        
        f.write("### Strong Passwords Not in NTLM:LM File\n\n")
        overlap_check = results["cross_references"]["strong_passwords_in_ntlm_lm"]
        status = "✅ PASS" if overlap_check.get("status") == "pass" else "❌ FAIL"
        count = overlap_check.get("overlap_count", 0)
        f.write(f"Status: {status} - {count} overlapping entries\n\n")
        
        if count > 0:
            f.write("Overlapping entries (hashes appearing in both strong passwords and NTLM:LM files):\n\n")
            for entry in overlap_check.get("overlap_sample", []):
                f.write(f"- `{entry}`\n")
        
        # Summary
        format_valid = all(check.get("is_valid", False) for check in results["format_checks"].values())
        special_checks_valid = all(all(r.get("status") == "pass" for r in check_results.values()) for check_results in results["special_checks"].values())
        cross_refs_valid = results["cross_references"]["strong_passwords_in_ntlm_lm"].get("status") == "pass"
        
        overall_result = format_valid and special_checks_valid and cross_refs_valid
        
        f.write("\n## Summary\n\n")
        f.write(f"- File formats: {'✅ PASS' if format_valid else '❌ FAIL'}\n")
        f.write(f"- Special checks: {'✅ PASS' if special_checks_valid else '❌ FAIL'}\n")
        f.write(f"- Cross-references: {'✅ PASS' if cross_refs_valid else '❌ FAIL'}\n")
        f.write(f"\n**Overall Validation: {'✅ PASS' if overall_result else '❌ FAIL'}**\n\n")
        f.write(f"Report generated on: {os.popen('date').read().strip()}\n")
    
    print(f"Validation complete! Report written to {output_report}")
    return results

if __name__ == "__main__":
    print("Running final hash validation...")
    validate_all_files()
    print("Done!")
