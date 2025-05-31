#!/usr/bin/env python3
"""
Extract DPAPI master keys and backup keys from registry hives using pypykatz
"""

import os
import sys
import json
import subprocess

SYSTEM_HIVE = "/workspaces/JaiziahGreene/hives/sy.dat"
SECURITY_HIVE = "/workspaces/JaiziahGreene/hives/ss.dat"
OUTPUT_JSON = "/workspaces/JaiziahGreene/pypykatz_dpapi_masterkeys.json"

# def extract_system_keys():
#     """
#     Use pypykatz's direct CLI command to extract DPAPI info
#     """
#     print("[*] Attempting to extract DPAPI backup keys using pypykatz...")
#     
#     # Check if files exist
#     if not os.path.isfile(SYSTEM_HIVE):
#         print(f"[-] SYSTEM hive file not found: {SYSTEM_HIVE}")
#         return None
#     
#     if not os.path.isfile(SECURITY_HIVE):
#         print(f"[-] SECURITY hive file not found: {SECURITY_HIVE}")
#         return None
#     
#     try:
#         # Create temporary file for command output
#         temp_output = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
#         temp_output.close()
#         
#         # Build the pypykatz command
#         cmd = [
#             "pypykatz", "registry", 
#             SYSTEM_HIVE, 
#             "--security", SECURITY_HIVE,
#             "--json",
#             "-o", temp_output.name
#         ]
#         
#         print(f"[*] Running command: {' '.join(cmd)}")
#         
#         # Execute the command
#         process = subprocess.run(
#             cmd,
#             capture_output=True,
#             text=True
#         )
#         
#         if process.returncode != 0:
#             print(f"[-] Command failed with error:")
#             print(process.stderr)
#             return None
#         
#         print(f"[+] Registry parsing successful!")
#         
#         # Read the JSON results
#         try:
#             with open(temp_output.name, 'r') as f:
#                 results = json.load(f)
#             
#             # Save to a more permanent file
#             output_file = "dpapi_registry_results.json" # This was a different output file
#             with open(output_file, 'w') as f:
#                 json.dump(results, f, indent=4)
#             
#             print(f"[+] Results saved to {output_file}")
#             
#             # Clean up temporary file
#             os.unlink(temp_output.name)
#             
#             return results
#         except Exception as e:
#             print(f"[-] Error processing results: {str(e)}")
#             return None
#         
#     except Exception as e:
#         print(f"[-] Error while parsing registry: {str(e)}")
#         return None

def try_dpapi_masterkey_extractor():
    """
    Try to use pypykatz's dpapi module to extract master keys directly to a JSON file.
    """
    print("[*] Attempting to extract DPAPI master keys using 'pypykatz dpapi masterkey'...")

    if not os.path.isfile(SYSTEM_HIVE):
        print(f"[-] SYSTEM hive file not found: {SYSTEM_HIVE}")
        return False
    
    if not os.path.isfile(SECURITY_HIVE):
        print(f"[-] SECURITY hive file not found: {SECURITY_HIVE}")
        return False

    # Command to run: pypykatz dpapi masterkey --system <SYSTEM> --security <SECURITY> json -o <OUTPUT_JSON>
    command_to_run = [
        "pypykatz",
        "dpapi", "masterkey",
        "--system", SYSTEM_HIVE,
        "--security", SECURITY_HIVE,
        "json", # Specifies JSON output format
        "-o", OUTPUT_JSON # Specifies the output file
    ]

    print(f"[*] Running command: {' '.join(command_to_run)}")

    try:
        process = subprocess.run(
            command_to_run,
            capture_output=True,
            text=True,
            check=False # Set to False to handle non-zero exit codes manually
        )

        if process.returncode == 0:
            print(f"[+] DPAPI master keys extraction command executed successfully.")
            if os.path.isfile(OUTPUT_JSON) and os.path.getsize(OUTPUT_JSON) > 0:
                print(f"[+] Output saved to {OUTPUT_JSON}")
                # Optionally, you can add code here to read and verify the JSON content
                # For example, to confirm it's not empty or has expected keys.
                # For now, just confirming file creation and non-empty status.
            else:
                print(f"[!] Command reported success, but output file {OUTPUT_JSON} is missing or empty.")
                if process.stdout:
                    print("[!] STDOUT:")
                    print(process.stdout)
                if process.stderr:
                    print("[!] STDERR:")
                    print(process.stderr)
                return False
            return True
        else:
            print(f"[-] 'pypykatz dpapi masterkey' command failed with return code {process.returncode}")
            if process.stdout:
                print("[-] STDOUT:")
                print(process.stdout)
            if process.stderr:
                print("[-] STDERR:")
                print(process.stderr)
            return False

    except FileNotFoundError:
        print("[-] Error: pypykatz command not found. Make sure it is installed and in your PATH.")
        return False
    except Exception as e:
        print(f"[-] An unexpected error occurred: {str(e)}")
        return False

if __name__ == "__main__":
    print("[SCRIPT START]")
    success = try_dpapi_masterkey_extractor()
    if success:
        print("[SCRIPT END] DPAPI master key extraction process completed successfully.")
    else:
        print("[SCRIPT END] DPAPI master key extraction process failed.")
