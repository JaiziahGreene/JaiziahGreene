#!/usr/bin/env python3
"""
Script to convert Kerberos DES-CBC-MD5 to LM format for hashcat
"""

import argparse
import os
import subprocess

def create_hash_file(output_file):
    """Create a hash file that hashcat can process"""
    # The DES-CBC-MD5 hash
    des_hash = "b09b49d08ab557f2"
    
    # Format for LM hash (mode 3000)
    # LM uses a DES-based algorithm, so we'll try this approach
    lm_format = f"$LM${des_hash}"
    
    with open(output_file, "w") as f:
        f.write(lm_format)
    
    print(f"[+] Created hash file {output_file} with format: {lm_format}")
    print("[+] This uses LM format (hashcat -m 3000) since it's also DES-based")
    
    return output_file

def run_hashcat(hash_file, wordlist):
    """Run hashcat against the hash file"""
    hashcat_path = "/workspaces/JaiziahGreene/hashcat/hashcat"
    
    if not os.path.exists(hashcat_path):
        print(f"[-] Hashcat not found at {hashcat_path}")
        return False
    
    # Command for hashcat using LM format (3000)
    cmd = [
        hashcat_path,
        "-m", "3000",          # LM hash mode
        "-a", "0",             # Dictionary attack
        hash_file,            # Hash file
        wordlist,             # Wordlist
        "--potfile-disable"   # Don't use or update potfile
    ]
    
    print(f"[*] Running hashcat command: {' '.join(cmd)}")
    
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        print(process.stdout)
        
        if "Recovered" in process.stdout and not "Recovered.....: 0/" in process.stdout:
            print("[+] Password successfully cracked!")
            return True
        else:
            print("[-] Password not found with this wordlist")
            return False
            
    except Exception as e:
        print(f"[-] Error running hashcat: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Convert and crack Kerberos DES hash using hashcat")
    parser.add_argument("--wordlist", "-w", default="/workspaces/JaiziahGreene/targeted_wordlist.txt",
                      help="Path to wordlist file")
    args = parser.parse_args()
    
    hash_file = "/workspaces/JaiziahGreene/des_for_hashcat.txt"
    create_hash_file(hash_file)
    
    run_hashcat(hash_file, args.wordlist)
    
    # Also try with rockyou.txt if it exists
    rockyou = "/workspaces/JaiziahGreene/hashcat/rockyou.txt"
    if os.path.exists(rockyou):
        print("\n[*] Also trying with rockyou.txt wordlist")
        run_hashcat(hash_file, rockyou)
    
if __name__ == "__main__":
    main()
