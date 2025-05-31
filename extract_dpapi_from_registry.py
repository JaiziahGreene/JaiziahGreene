#!/usr/bin/env python3
import sys
import os
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.structure import Structure
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst

def process_hive(hive_file):
    try:
        import winreg
        from impacket.winregistry import Registry
        
        registry = Registry(hive_file)
        root = registry.root()
        
        print(f"Processing registry hive: {hive_file}")
        print("Root key:", root.Name())
        
        # Try to locate DPAPI keys in the registry
        try:
            # For the SYSTEM hive
            if "SYSTEM" in os.path.basename(hive_file).upper():
                print("\n[*] Looking for DPAPI system keys in SYSTEM hive...")
                lsa_key = registry.open_key(root, "ControlSet001\\Control\\Lsa")
                if lsa_key:
                    print("[+] Found LSA key")
                    
                    # Try to get the DPAPI backup key
                    try:
                        dpapi_backup_key = lsa_key.get_value("BackupKeys")
                        print("[+] DPAPI Backup Key:", dpapi_backup_key)
                    except Exception as e:
                        print("[-] Failed to get DPAPI Backup Key:", str(e))
                    
                    # Try to get the GBG value (Group Key)
                    try:
                        gbg_key = lsa_key.get_value("GBG")
                        print("[+] GBG Key (Group Key):", gbg_key.hex() if isinstance(gbg_key, bytes) else gbg_key)
                    except Exception as e:
                        print("[-] Failed to get GBG Key:", str(e))
            
            # For the SECURITY hive
            elif "SECURITY" in os.path.basename(hive_file).upper():
                print("\n[*] Looking for DPAPI keys in SECURITY hive...")
                policy_key = registry.open_key(root, "Policy")
                if policy_key:
                    print("[+] Found Policy key")
                    
                    # Look for Secrets key
                    try:
                        secrets_key = registry.open_key(policy_key, "Secrets")
                        print("[+] Found Secrets key")
                        
                        # Look for the DPAPI secret
                        try:
                            dpapi_secrets = []
                            
                            for secret_name in secrets_key.subkeys():
                                if "DPAPI" in secret_name.Name():
                                    print(f"[+] Found DPAPI secret: {secret_name.Name()}")
                                    dpapi_secrets.append(secret_name.Name())
                                    
                                    # Try to get the values
                                    try:
                                        cur_val_key = registry.open_key(secret_name, "CurrVal")
                                        if cur_val_key:
                                            val = cur_val_key.get_value("")
                                            print(f"[+] CurrVal for {secret_name.Name()}: {val.hex() if isinstance(val, bytes) else val}")
                                    except Exception as e:
                                        print(f"[-] Failed to get CurrVal for {secret_name.Name()}: {str(e)}")
                            
                            if not dpapi_secrets:
                                print("[-] No DPAPI secrets found")
                                
                        except Exception as e:
                            print("[-] Failed to access DPAPI secrets:", str(e))
                        
                    except Exception as e:
                        print("[-] Failed to open Secrets key:", str(e))
            
            # For NTUSER.DAT hive
            elif "NTUSER.DAT" in os.path.basename(hive_file).upper():
                print("\n[*] Looking for DPAPI keys in NTUSER.DAT hive...")
                try:
                    crypto_key = registry.open_key(root, "Software\\Microsoft\\Crypto")
                    if crypto_key:
                        print("[+] Found Crypto key")
                        
                        # Look for Protect, MasterKeys, etc.
                        for subkey_name in ["Protect", "MasterKeys", "Keys", "SystemCertificates"]:
                            try:
                                subkey = registry.open_key(crypto_key, subkey_name)
                                if subkey:
                                    print(f"[+] Found {subkey_name} key")
                                    
                                    # List subkeys
                                    print(f"[+] {subkey_name} subkeys:")
                                    for sub in subkey.subkeys():
                                        print(f"  - {sub.Name()}")
                            except Exception as e:
                                print(f"[-] Failed to open {subkey_name} key: {str(e)}")
                except Exception as e:
                    print("[-] Failed to open Crypto key:", str(e))
            
            # For SOFTWARE hive
            elif "SOFTWARE" in os.path.basename(hive_file).upper():
                print("\n[*] Looking for DPAPI keys in SOFTWARE hive...")
                try:
                    microsoft_key = registry.open_key(root, "Microsoft")
                    if microsoft_key:
                        print("[+] Found Microsoft key")
                        
                        # Look for Cryptography key
                        try:
                            crypto_key = registry.open_key(microsoft_key, "Cryptography")
                            if crypto_key:
                                print("[+] Found Cryptography key")
                                
                                # Look for Protect and other DPAPI-related keys
                                try:
                                    protect_key = registry.open_key(crypto_key, "Protect")
                                    if protect_key:
                                        print("[+] Found Protect key")
                                        
                                        # List subkeys
                                        print("[+] Protect subkeys:")
                                        for sub in protect_key.subkeys():
                                            print(f"  - {sub.Name()}")
                                except Exception as e:
                                    print("[-] Failed to open Protect key:", str(e))
                        except Exception as e:
                            print("[-] Failed to open Cryptography key:", str(e))
                except Exception as e:
                    print("[-] Failed to open Microsoft key:", str(e))
        
        except Exception as e:
            print(f"[-] Error processing registry for DPAPI keys: {str(e)}")
        
        return True
    
    except Exception as e:
        print(f"[-] Error processing hive file: {str(e)}")
        return False

def main():
    print("DPAPI Registry Hive Scanner")
    print("==========================\n")
    
    if len(sys.argv) < 2:
        print("Usage: python extract_dpapi_from_registry.py <hive_file1> [hive_file2] [hive_file3] ...")
        return
    
    for hive_file in sys.argv[1:]:
        if not os.path.isfile(hive_file):
            print(f"[-] File not found: {hive_file}")
            continue
        
        print(f"\nProcessing hive file: {hive_file}")
        process_hive(hive_file)
    
    print("\nProcessing complete.")

if __name__ == "__main__":
    main()
