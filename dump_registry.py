#!/usr/bin/env python3
"""
Dump registry hive structure using regipy
"""

import os
import sys
from regipy.registry import RegistryHive

def dump_registry_structure(hive_path, max_depth=2):
    print(f"Dumping registry hive: {hive_path}")
    
    try:
        reg = RegistryHive(hive_path)
        root_key = reg.root
        
        print(f"Registry Root: {root_key.name}")
        print(f"Last Written: {root_key.last_written_timestamp}")
        print(f"Subkey Count: {root_key.subkey_count}")
        print(f"Value Count: {root_key.values_count}")
        
        def dump_key(key, depth=0, max_depth=max_depth):
            if depth > max_depth:
                print(f"{'  ' * depth}... (max depth reached)")
                return
                
            # Print subkeys
            for subkey in key.iter_subkeys():
                print(f"{'  ' * depth}[KEY] {subkey.name} ({subkey.subkey_count} subkeys, {subkey.values_count} values)")
                dump_key(subkey, depth + 1, max_depth)
            
            # Print values
            for value in key.iter_values():
                val_data = value.value
                if isinstance(val_data, bytes) and len(val_data) > 20:
                    val_data = f"<BINARY {len(val_data)} bytes>"
                print(f"{'  ' * depth}  [VALUE] {value.name}: {val_data}")
        
        print("\nRoot Keys:")
        dump_key(root_key)
    
    except Exception as e:
        print(f"Error dumping registry: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <registry_hive_path> [max_depth]")
        sys.exit(1)
    
    hive_path = sys.argv[1]
    max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    
    dump_registry_structure(hive_path, max_depth)
