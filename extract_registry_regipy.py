#!/usr/bin/env python3
"""
Extract DPAPI keys from registry hives using regipy
"""

import os
import sys
import json
from regipy.registry import RegistryHive
from datetime import datetime

def extract_keys_from_registry():
    """
    Use regipy to extract DPAPI keys and registry information
    """
    system_hive = "/workspaces/JaiziahGreene/hives/sy.dat"
    security_hive = "/workspaces/JaiziahGreene/hives/ss.dat"
    
    print(f"[*] Processing SYSTEM hive: {system_hive}")
    print(f"[*] Processing SECURITY hive: {security_hive}")
    
    results = {
        "system_info": {},
        "security_info": {},
        "dpapi_keys": []
    }
    
    try:
        # Parse SYSTEM hive
        system_reg = RegistryHive(system_hive)
        
        # Get current control set
        try:
            select_key = system_reg.get_key("Select")
            current = select_key.get_value("Current")
            current_cs = f"ControlSet{current:03d}"
            print(f"[+] Current Control Set: {current_cs}")
            results["system_info"]["current_control_set"] = current_cs
            
            # Get computer name
            try:
                computer_name_key = system_reg.get_key(f"{current_cs}\\Control\\ComputerName\\ComputerName")
                computer_name = computer_name_key.get_value("ComputerName")
                print(f"[+] Computer Name: {computer_name}")
                results["system_info"]["computer_name"] = computer_name
            except Exception as e:
                print(f"[-] Error getting computer name: {str(e)}")
            
            # Get OS information
            try:
                winnt_key = system_reg.get_key(f"{current_cs}\\Control\\Windows")
                install_date = winnt_key.get_value("InstallDate")
                if install_date:
                    install_date_str = datetime.fromtimestamp(install_date).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"[+] Windows Install Date: {install_date_str}")
                    results["system_info"]["install_date"] = install_date_str
            except Exception as e:
                print(f"[-] Error getting install date: {str(e)}")
            
            # Try to get DPAPI keys from SYSTEM
            try:
                lsa_key = system_reg.get_key(f"{current_cs}\\Control\\Lsa")
                if lsa_key:
                    print(f"[+] Found LSA key, looking for DPAPI keys")
                    
                    # Look for GBG value (can contain DPAPI backup key material)
                    gbg_value = lsa_key.get_value("GBG")
                    if gbg_value:
                        print(f"[+] Found GBG value: {len(gbg_value)} bytes")
                        if isinstance(gbg_value, bytes):
                            results["dpapi_keys"].append({
                                "source": "SYSTEM\\Control\\Lsa\\GBG",
                                "type": "GBG",
                                "value_hex": gbg_value.hex()
                            })
                        else:
                            print(f"[+] GBG value type: {type(gbg_value)}")
                    
                    # Other potential DPAPI-related values
                    for val_name in ["NL$KM", "BackupKeys"]:
                        try:
                            val = lsa_key.get_value(val_name)
                            if val:
                                print(f"[+] Found {val_name} value: {len(val) if isinstance(val, bytes) else val} bytes")
                                if isinstance(val, bytes):
                                    results["dpapi_keys"].append({
                                        "source": f"SYSTEM\\Control\\Lsa\\{val_name}",
                                        "type": val_name,
                                        "value_hex": val.hex()
                                    })
                        except:
                            pass
            except Exception as e:
                print(f"[-] Error accessing LSA key: {str(e)}")
        
        except Exception as e:
            print(f"[-] Error processing SYSTEM hive: {str(e)}")
        
        # Parse SECURITY hive
        try:
            security_reg = RegistryHive(security_hive)
            
            # Examine Policy\Secrets for DPAPI keys
            try:
                policy_key = security_reg.get_key("Policy\\Secrets")
                if policy_key:
                    print(f"[+] Found Policy\\Secrets key, looking for DPAPI keys")
                    
                    # Get subkeys and look for DPAPI secrets
                    subkeys = [x.name for x in policy_key.iter_subkeys()]
                    dpapi_keys = [x for x in subkeys if "DPAPI" in x]
                    
                    print(f"[+] Found {len(dpapi_keys)} DPAPI-related keys: {', '.join(dpapi_keys)}")
                    
                    for key_name in dpapi_keys:
                        try:
                            # Try to get CurrVal subkey and its value
                            currval_key = security_reg.get_key(f"Policy\\Secrets\\{key_name}\\CurrVal")
                            if currval_key:
                                try:
                                    value = currval_key.get_value("")
                                    if value:
                                        print(f"[+] Found {key_name} CurrVal: {len(value) if isinstance(value, bytes) else value} bytes")
                                        if isinstance(value, bytes):
                                            results["dpapi_keys"].append({
                                                "source": f"SECURITY\\Policy\\Secrets\\{key_name}\\CurrVal",
                                                "type": key_name,
                                                "value_hex": value.hex()
                                            })
                                except Exception as e:
                                    print(f"[-] Error getting value for {key_name}: {str(e)}")
                        except Exception as e:
                            print(f"[-] Error accessing {key_name}: {str(e)}")
            except Exception as e:
                print(f"[-] Error accessing Policy\\Secrets: {str(e)}")
        
        except Exception as e:
            print(f"[-] Error processing SECURITY hive: {str(e)}")
        
        # Save results
        with open("regipy_dpapi_extraction.json", "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to regipy_dpapi_extraction.json")
        
        return results
    
    except Exception as e:
        print(f"[-] Global error during extraction: {str(e)}")
        return None

if __name__ == "__main__":
    print("Registry DPAPI Key Extractor (using regipy)")
    print("==========================================\n")
    
    extract_keys_from_registry()
