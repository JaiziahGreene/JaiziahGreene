#!/usr/bin/env python3
"""
Extract DPAPI keys directly from registry hives
"""

import sys
import os
import json
from impacket.examples import logger
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst
from impacket.registry.regfi import RegistryFile

def extract_keys_from_registry():
    """
    Use the impacket registry parser to extract DPAPI keys
    """
    system_hive = "/workspaces/JaiziahGreene/hives/sy.dat"
    security_hive = "/workspaces/JaiziahGreene/hives/ss.dat"
    
    print(f"[*] Processing SYSTEM hive: {system_hive}")
    print(f"[*] Processing SECURITY hive: {security_hive}")
    
    results = {
        "bootkey": None,
        "dpapi_keys": [],
        "lsa_secrets": []
    }
    
    try:
        # Parse SYSTEM hive
        system_reg = RegistryFile(system_hive)
        system_root = system_reg.get_root_key()
        
        # Get current control set
        select_key = system_root.find_key("Select")
        current = select_key.get_value("Current").get_value()
        current_cs = f"ControlSet{current:03d}"
        print(f"[+] Current Control Set: {current_cs}")
        
        # Get bootkey components
        bootkey_parts = []
        for key_name in ["JD", "Skew1", "GBG", "Data"]:
            key_path = f"{current_cs}\\Control\\Lsa\\{key_name}"
            key = system_root.find_key(key_path)
            
            if key:
                classname = key.get_class_name()
                if classname:
                    bootkey_parts.append(classname.encode())
                    print(f"[+] Found bootkey part from {key_name}: {classname}")
        
        if len(bootkey_parts) == 4:
            # Combine bootkey parts (simplified for demonstration)
            bootkey = b''.join(bootkey_parts)
            print(f"[+] Assembled bootkey: {bootkey.hex()}")
            results["bootkey"] = bootkey.hex()
        else:
            print(f"[-] Failed to get all bootkey parts, found {len(bootkey_parts)}/4")
        
        # Parse SECURITY hive
        security_reg = RegistryFile(security_hive)
        security_root = security_reg.get_root_key()
        
        # Look for DPAPI keys in Policy\Secrets
        try:
            policy_key = security_root.find_key("Policy")
            if policy_key:
                print(f"[+] Found Policy key")
                
                secrets_key = policy_key.find_key("Secrets")
                if secrets_key:
                    print(f"[+] Found Secrets key, enumerating DPAPI secrets")
                    
                    # Enumerate subkeys to find DPAPI secrets
                    for sk in secrets_key.subkeys():
                        if "DPAPI" in sk.get_name():
                            print(f"[+] Found DPAPI secret: {sk.get_name()}")
                            
                            # Get the Value key which contains the secret
                            curval_key = sk.find_key("CurrVal")
                            if curval_key:
                                value = curval_key.get_value("")
                                if value:
                                    dpapi_secret = {
                                        "name": sk.get_name(),
                                        "value_type": value.get_type(),
                                        "value_size": len(value.get_value()),
                                        "value_hex": value.get_value().hex() if isinstance(value.get_value(), bytes) else None
                                    }
                                    results["dpapi_keys"].append(dpapi_secret)
                                    print(f"[+] Extracted {sk.get_name()} value: {len(value.get_value())} bytes")
                else:
                    print(f"[-] Secrets key not found")
        except Exception as e:
            print(f"[-] Error accessing Policy\\Secrets: {str(e)}")
        
        # Save results
        with open("registry_dpapi_extraction.json", "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to registry_dpapi_extraction.json")
        
        return results
    
    except Exception as e:
        print(f"[-] Error during extraction: {str(e)}")
        return None

if __name__ == "__main__":
    print("Registry DPAPI Key Extractor")
    print("=============================\n")
    
    extract_keys_from_registry()
