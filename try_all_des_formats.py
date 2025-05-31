#!/usr/bin/env python3
"""
Script to try different John the Ripper formats for cracking 
the Kerberos DES-CBC-MD5 hash of jean-marc.samson
"""

import os
import subprocess
import tempfile

def create_hash_files():
    """Create hash files in various formats"""
    hash_files = []
    
    # User info
    username = "jean-marc.samson"
    des_hash = "b09b49d08ab557f2"
    salt = "SVH-0236-S-17jean-marc.samson"
    
    # Format 1: Basic krb5 format
    format1 = f"{username}:$krb5${salt}${des_hash}"
    file1 = "/workspaces/JaiziahGreene/des_hash_format1.txt"
    with open(file1, "w") as f:
        f.write(format1)
    hash_files.append((file1, "krb5", format1))
    
    # Format 2: krb5tgs-like format 
    format2 = f"{username}:$krb5tgs$23${username}${salt}${des_hash}*$HEX${des_hash}"
    file2 = "/workspaces/JaiziahGreene/des_hash_format2.txt"
    with open(file2, "w") as f:
        f.write(format2)
    hash_files.append((file2, "krb5tgs", format2))
    
    # Format 3: des-cbc-md5 with salt
    format3 = f"{username}:$des,salt=${salt}${des_hash}"
    file3 = "/workspaces/JaiziahGreene/des_hash_format3.txt"
    with open(file3, "w") as f:
        f.write(format3)
    hash_files.append((file3, "des", format3))
    
    # Format 4: descrypt format (traditional Unix crypt)
    format4 = f"{username}:{des_hash}"
    file4 = "/workspaces/JaiziahGreene/des_hash_format4.txt"
    with open(file4, "w") as f:
        f.write(format4)
    hash_files.append((file4, "descrypt", format4))
    
    # Format 5: Try raw DES format
    format5 = f"{username}:$1${des_hash}"
    file5 = "/workspaces/JaiziahGreene/des_hash_format5.txt"
    with open(file5, "w") as f:
        f.write(format5)
    hash_files.append((file5, "descrypt", format5))
    
    # Format 6: Try LM format
    format6 = f"{username}:$LM${des_hash}"
    file6 = "/workspaces/JaiziahGreene/des_hash_format6.txt"
    with open(file6, "w") as f:
        f.write(format6)
    hash_files.append((file6, "lm", format6))
    
    return hash_files

def try_crack_with_john(hash_files, wordlist):
    """Try cracking with different formats"""
    john_path = "/workspaces/JaiziahGreene/john-jumbo/run/john"
    
    if not os.path.exists(john_path):
        print(f"[-] John the Ripper not found at {john_path}")
        return False
    
    for hash_file, format_name, hash_format in hash_files:
        print(f"\n[+] Trying format: {format_name}")
        print(f"[+] Hash format: {hash_format}")
        
        # Try using the format
        cmd = [
            john_path,
            f"--format={format_name}",
            f"--wordlist={wordlist}",
            hash_file
        ]
        
        print(f"[*] Running command: {' '.join(cmd)}")
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # Set a timeout to prevent hanging
            )
            
            print(process.stdout)
            
            if process.returncode != 0:
                print(f"[-] Error with format {format_name}:")
                print(process.stderr)
                continue
            
            # Check if any passwords were found
            show_cmd = [john_path, "--show", f"--format={format_name}", hash_file]
            try:
                show_process = subprocess.run(
                    show_cmd,
                    capture_output=True,
                    text=True
                )
                
                print(f"[+] Results for {format_name}:")
                print(show_process.stdout)
                
                if "password hash" in show_process.stdout and not "0 password hashes cracked" in show_process.stdout:
                    print(f"[+] SUCCESS! Password found using format {format_name}")
                    return True
                
            except Exception as e:
                print(f"[-] Error showing results: {str(e)}")
        
        except subprocess.TimeoutExpired:
            print(f"[-] Command timed out for format {format_name}")
        except Exception as e:
            print(f"[-] Error running John: {str(e)}")
    
    return False

def main():
    """Main function"""
    # Create hash files in various formats
    hash_files = create_hash_files()
    
    # Try with the targeted wordlist
    print("[*] Trying with targeted wordlist")
    wordlist = "/workspaces/JaiziahGreene/targeted_wordlist.txt"
    if try_crack_with_john(hash_files, wordlist):
        print("[+] Password found in targeted wordlist!")
    else:
        # Try with rockyou.txt
        print("\n[*] Trying with rockyou.txt")
        rockyou = "/workspaces/JaiziahGreene/hashcat/rockyou.txt"
        if os.path.exists(rockyou):
            if try_crack_with_john(hash_files, rockyou):
                print("[+] Password found in rockyou.txt!")
            else:
                print("[-] Password not found in rockyou.txt")
        else:
            print(f"[-] Rockyou.txt not found at {rockyou}")
    
if __name__ == "__main__":
    main()
