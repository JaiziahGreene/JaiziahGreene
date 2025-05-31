#!/usr/bin/env python3
import os
import sqlite3
import shutil
import binascii
import sys

# Path to Chrome Cookies database
COOKIES_DB = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data/Default/Network/Cookies"

# Target domains
TARGET_DOMAINS = [
    "sishrsb.ednet.ns.ca",
    "gnspes.ca",
    "everyone.ednet.ns.ca", 
    "saml.nspes.ca",
    "ednet.ns.ca",
    "nspes"
]

def main():
    # Create a copy of the database to avoid locks
    temp_db = "/tmp/temp_cookies_direct.db"
    
    if not os.path.exists(COOKIES_DB):
        print(f"Error: Cookies database not found at {COOKIES_DB}")
        return
    
    try:
        # Copy the database
        shutil.copy2(COOKIES_DB, temp_db)
        
        # Connect to the copy
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        print("===== Direct Cookie Database Analysis =====")
        
        # First, let's check the table schema to understand the structure
        cursor.execute("PRAGMA table_info(cookies)")
        columns = cursor.fetchall()
        print("\nCookie table schema:")
        for col in columns:
            print(f"Column {col['cid']}: {col['name']} ({col['type']})")
        
        # Now query for cookies related to our target domains
        print("\nCookies for educational domains (showing raw values):")
        for domain in TARGET_DOMAINS:
            cursor.execute(
                "SELECT host_key, name, value, path, creation_utc, last_access_utc, expires_utc, is_secure, is_httponly "
                "FROM cookies WHERE host_key LIKE ? OR host_key LIKE ?",
                (f'%{domain}%', f'%.{domain}%')
            )
            
            rows = cursor.fetchall()
            if rows:
                print(f"\n--- Found {len(rows)} cookies for domain pattern '{domain}' ---")
                for i, row in enumerate(rows):
                    print(f"Cookie {i+1}:")
                    print(f"  Host: {row['host_key']}")
                    print(f"  Name: {row['name']}")
                    
                    # Try to display the value in different formats in case it helps
                    try:
                        print(f"  Value (text): {row['value']}")
                        
                        # If value is empty or very short, it might be binary/encrypted
                        if not row['value'] or len(row['value']) < 3:
                            value_bytes = row['value'].encode('utf-8') if row['value'] else b''
                            print(f"  Value (hex): {binascii.hexlify(value_bytes).decode('utf-8')}")
                    except:
                        print("  Value: <unable to decode>")
                    
                    print(f"  Path: {row['path']}")
                    print(f"  Secure: {bool(row['is_secure'])}")
                    print(f"  HttpOnly: {bool(row['is_httponly'])}")
                    print(f"  Creation UTC: {row['creation_utc']}")
                    print(f"  Last Access UTC: {row['last_access_utc']}")
                    print(f"  Expires UTC: {row['expires_utc']}")
        
        # Now check if there are any other tables in the database that might be relevant
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print("\nAll tables in the Cookies database:")
        for table in tables:
            print(f"- {table['name']}")
            
            # If there are other tables, let's peek at their schema
            if table['name'] != 'cookies' and table['name'] != 'sqlite_sequence':
                try:
                    cursor.execute(f"PRAGMA table_info({table['name']})")
                    cols = cursor.fetchall()
                    print(f"  Schema of table {table['name']}:")
                    for col in cols:
                        print(f"  Column {col['cid']}: {col['name']} ({col['type']})")
                except:
                    print(f"  Could not retrieve schema for {table['name']}")
        
        conn.close()
        os.remove(temp_db)
        
    except Exception as e:
        print(f"Error examining Cookies database: {e}")
        try:
            conn.close()
        except:
            pass
        try:
            os.remove(temp_db)
        except:
            pass

if __name__ == "__main__":
    main()
