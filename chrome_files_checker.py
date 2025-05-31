#!/usr/bin/env python3
import sqlite3
import os
import shutil
import json
import sys

# Check various Chrome files
chrome_dir = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data/Default"
files_to_check = ['History', 'Web Data', 'Cookies']

for filename in files_to_check:
    full_path = os.path.join(chrome_dir, filename)
    if not os.path.exists(full_path):
        print(f"File {filename} not found!")
        continue
        
    print(f"\n{'=' * 50}")
    print(f"Examining {filename}:")
    print(f"{'=' * 50}")
    
    # Copy to temp to avoid locking
    temp_path = f"/tmp/{filename}_copy.db"
    shutil.copy2(full_path, temp_path)
    
    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in {filename}:")
        for table in tables:
            print(f"  - {table[0]}")
        
        # Check specific tables based on file type
        if filename == 'History':
            print("\nChecking URLs in history:")
            cursor.execute("SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 10;")
            rows = cursor.fetchall()
            for i, row in enumerate(rows, 1):
                print(f"{i}. URL: {row[0]}")
                print(f"   Title: {row[1]}")
                print(f"   Visit count: {row[2]}")
                print()
                
        elif filename == 'Web Data':
            print("\nChecking autofill data:")
            try:
                cursor.execute("SELECT name, value, count FROM autofill ORDER BY count DESC LIMIT 10;")
                rows = cursor.fetchall()
                for i, row in enumerate(rows, 1):
                    print(f"{i}. Name: {row[0]}")
                    print(f"   Value: {row[1]}")
                    print(f"   Count: {row[2]}")
                    print()
            except sqlite3.Error as e:
                print(f"Error querying autofill: {e}")
                
            print("\nChecking autofill profiles:")
            try:
                cursor.execute("SELECT * FROM autofill_profiles LIMIT 5;")
                rows = cursor.fetchall()
                if rows:
                    print(f"Found {len(rows)} profiles")
                    # Just show we found some without revealing all details
                    for i, row in enumerate(rows, 1):
                        print(f"Profile {i}: Found")
                else:
                    print("No profiles found")
            except sqlite3.Error as e:
                print(f"Error querying autofill_profiles: {e}")
                
        elif filename == 'Cookies':
            print("\nChecking cookies:")
            try:
                cursor.execute("SELECT host_key, name, path FROM cookies LIMIT 10;")
                rows = cursor.fetchall()
                for i, row in enumerate(rows, 1):
                    print(f"{i}. Host: {row[0]}")
                    print(f"   Cookie name: {row[1]}")
                    print(f"   Path: {row[2]}")
                    print()
            except sqlite3.Error as e:
                print(f"Error querying cookies: {e}")
        
        conn.close()
    except Exception as e:
        print(f"Error processing {filename}: {e}")
    
print("\nSearch complete!")
