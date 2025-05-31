#!/usr/bin/env python3
import sqlite3
import os
import base64
import shutil
import json
import sys

# Create a copy of the database file to avoid locking issues
original_db = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data/Default/Login Data"
copy_db = "/tmp/login_data_copy.db"

# Make a copy of the database
shutil.copy2(original_db, copy_db)

# Connect to the database
conn = sqlite3.connect(copy_db)
cursor = conn.cursor()

# First, let's get the schema to understand the structure
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table';")
schemas = cursor.fetchall()
print("Database Schema:")
for schema in schemas:
    print(schema[0])
print("\n" + "-"*50 + "\n")

# Try to get data from the logins table
print("Logins Table Data:")
try:
    cursor.execute("SELECT origin_url, username_value, SUBSTR(HEX(password_value), 1, 30) || '...' as password_hex FROM logins;")
    rows = cursor.fetchall()
    if rows:
        print(f"Found {len(rows)} entries:")
        for row in rows:
            print(f"URL: {row[0]}")
            print(f"Username: {row[1]}")
            print(f"Password (hex): {row[2]}")
            print("-" * 30)
    else:
        print("No entries found in logins table.")
except sqlite3.Error as e:
    print(f"Error querying logins table: {e}")

# Check Local State file for encryption key
local_state_path = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data/Local State"
if os.path.exists(local_state_path):
    print("\nLocal State file exists.")
    try:
        with open(local_state_path, 'r') as f:
            local_state = json.load(f)
            if 'os_crypt' in local_state and 'encrypted_key' in local_state['os_crypt']:
                encrypted_key = local_state['os_crypt']['encrypted_key']
                print(f"Encrypted key found: {encrypted_key}")
            else:
                print("No encryption key found in Local State file.")
    except Exception as e:
        print(f"Error reading Local State file: {e}")
else:
    print("\nLocal State file not found.")

conn.close()
