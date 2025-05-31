#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import shutil
import tempfile
import re
from datetime import datetime, timedelta

# Paths to Chrome data files
CHROME_PATH = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
DEFAULT_PROFILE = os.path.join(CHROME_PATH, "Default")
LOGIN_DATA = os.path.join(DEFAULT_PROFILE, "Login Data")
WEB_DATA = os.path.join(DEFAULT_PROFILE, "Web Data")
HISTORY = os.path.join(DEFAULT_PROFILE, "History")
BOOKMARKS = os.path.join(DEFAULT_PROFILE, "Bookmarks")
PREFERENCES = os.path.join(DEFAULT_PROFILE, "Preferences")
COOKIES_DB = os.path.join(DEFAULT_PROFILE, "Network", "Cookies")
LOCAL_STATE = os.path.join(CHROME_PATH, "Local State")

# Target username 
TARGET_USER = "jean-marc.samson"

def copy_db_for_access(db_path):
    """Create a temp copy of a database to avoid locks"""
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        return None, None
        
    try:
        temp_dir = tempfile.mkdtemp()
        temp_db = os.path.join(temp_dir, "temp_db")
        shutil.copy2(db_path, temp_db)
        return temp_db, temp_dir
    except Exception as e:
        print(f"Error copying database {db_path}: {e}")
        return None, None

def cleanup(temp_db, temp_dir):
    """Clean up temporary files"""
    try:
        if temp_db and os.path.exists(temp_db):
            os.remove(temp_db)
        if temp_dir and os.path.exists(temp_dir):
            os.rmdir(temp_dir)
    except Exception as e:
        print(f"Error cleaning up: {e}")

def search_login_data():
    """Search for username in Login Data database"""
    print("\n[1] Searching Login Data for username...")
    results = []
    
    temp_db, temp_dir = copy_db_for_access(LOGIN_DATA)
    if not temp_db:
        return results
    
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Get database structure
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in Login Data: {[t[0] for t in tables]}")
        
        # Search in logins table
        try:
            cursor.execute("SELECT * FROM logins WHERE username_value LIKE ?", (f"%{TARGET_USER}%",))
            login_results = cursor.fetchall()
            
            if login_results:
                print(f"Found {len(login_results)} entries with matching username")
                
                # Get column names
                cursor.execute("PRAGMA table_info(logins)")
                columns = [col[1] for col in cursor.fetchall()]
                
                for row in login_results:
                    entry = {}
                    for i, value in enumerate(row):
                        if i < len(columns):
                            entry[columns[i]] = value
                    results.append({"type": "login", "data": entry})
            else:
                print("No login entries found with matching username")
                
        except sqlite3.OperationalError as e:
            print(f"Error querying logins table: {e}")
        
        conn.close()
    except Exception as e:
        print(f"Error searching Login Data: {e}")
    finally:
        cleanup(temp_db, temp_dir)
    
    return results

def search_web_data():
    """Search for username in Web Data database"""
    print("\n[2] Searching Web Data for username...")
    results = []
    
    temp_db, temp_dir = copy_db_for_access(WEB_DATA)
    if not temp_db:
        return results
    
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Get database structure
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in Web Data: {[t[0] for t in tables]}")
        
        # Search in autofill table
        try:
            cursor.execute("SELECT * FROM autofill WHERE value LIKE ?", (f"%{TARGET_USER}%",))
            autofill_results = cursor.fetchall()
            
            if autofill_results:
                print(f"Found {len(autofill_results)} entries in autofill")
                
                # Get column names
                cursor.execute("PRAGMA table_info(autofill)")
                columns = [col[1] for col in cursor.fetchall()]
                
                for row in autofill_results:
                    entry = {}
                    for i, value in enumerate(row):
                        if i < len(columns):
                            entry[columns[i]] = value
                    results.append({"type": "autofill", "data": entry})
            else:
                print("No autofill entries found with matching username")
                
        except sqlite3.OperationalError as e:
            print(f"Error querying autofill table: {e}")
        
        # Check other potentially relevant tables
        for table in ["addresses", "credit_cards", "payments_customer_data"]:
            try:
                # Get table columns
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Get query for all columns that might contain text
                text_columns = [col for col in columns if "name" in col.lower() or 
                               "value" in col.lower() or 
                               "data" in col.lower() or 
                               "text" in col.lower() or 
                               "email" in col.lower() or
                               col.lower() in ["full_name", "first_name", "last_name", "middle_name"]]
                
                for column in text_columns:
                    cursor.execute(f"SELECT * FROM {table} WHERE {column} LIKE ?", (f"%{TARGET_USER}%",))
                    table_results = cursor.fetchall()
                    
                    if table_results:
                        print(f"Found {len(table_results)} matching entries in {table} column {column}")
                        
                        for row in table_results:
                            entry = {}
                            for i, value in enumerate(row):
                                if i < len(columns):
                                    entry[columns[i]] = value
                            results.append({"type": table, "data": entry})
            except sqlite3.OperationalError as e:
                print(f"Error querying {table} table: {e}")
        
        conn.close()
    except Exception as e:
        print(f"Error searching Web Data: {e}")
    finally:
        cleanup(temp_db, temp_dir)
    
    return results

def search_history():
    """Search for username in History database"""
    print("\n[3] Searching History for username...")
    results = []
    
    temp_db, temp_dir = copy_db_for_access(HISTORY)
    if not temp_db:
        return results
    
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Get database structure
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in History: {[t[0] for t in tables]}")
        
        # Search in urls table
        try:
            cursor.execute("SELECT * FROM urls WHERE url LIKE ? OR title LIKE ?", 
                           (f"%{TARGET_USER}%", f"%{TARGET_USER}%"))
            url_results = cursor.fetchall()
            
            if url_results:
                print(f"Found {len(url_results)} URLs with matching username")
                
                # Get column names
                cursor.execute("PRAGMA table_info(urls)")
                columns = [col[1] for col in cursor.fetchall()]
                
                for row in url_results:
                    entry = {}
                    for i, value in enumerate(row):
                        if i < len(columns):
                            entry[columns[i]] = value
                    results.append({"type": "history_url", "data": entry})
            else:
                print("No history URLs found with matching username")
                
        except sqlite3.OperationalError as e:
            print(f"Error querying urls table: {e}")
        
        conn.close()
    except Exception as e:
        print(f"Error searching History: {e}")
    finally:
        cleanup(temp_db, temp_dir)
    
    return results

def search_bookmarks():
    """Search for username in Bookmarks file"""
    print("\n[4] Searching Bookmarks for username...")
    results = []
    
    if not os.path.exists(BOOKMARKS):
        print(f"Bookmarks file not found: {BOOKMARKS}")
        return results
    
    try:
        with open(BOOKMARKS, 'r', encoding='utf-8') as f:
            bookmarks_data = json.load(f)
        
        # Function to recursively search bookmarks
        def search_bookmark_node(node, path=""):
            found_items = []
            
            # Check name and url if they exist
            name = node.get('name', '')
            url = node.get('url', '')
            
            current_path = f"{path}/{name}" if path else name
            
            # Check if target is in name or url
            if TARGET_USER.lower() in name.lower() or TARGET_USER.lower() in url.lower():
                found_items.append({
                    "type": "bookmark",
                    "path": current_path,
                    "name": name,
                    "url": url
                })
            
            # Recursively check children
            if 'children' in node:
                for child in node['children']:
                    found_items.extend(search_bookmark_node(child, current_path))
            
            return found_items
        
        # Start searching from roots
        if 'roots' in bookmarks_data:
            for root_name, root in bookmarks_data['roots'].items():
                bookmark_results = search_bookmark_node(root, root_name)
                results.extend(bookmark_results)
        
        if results:
            print(f"Found {len(results)} bookmarks with matching username")
        else:
            print("No bookmarks found with matching username")
            
    except Exception as e:
        print(f"Error searching Bookmarks: {e}")
    
    return results

def search_preferences():
    """Search for username in Preferences file"""
    print("\n[5] Searching Preferences for username...")
    results = []
    
    if not os.path.exists(PREFERENCES):
        print(f"Preferences file not found: {PREFERENCES}")
        return results
    
    try:
        with open(PREFERENCES, 'r', encoding='utf-8') as f:
            prefs_data = json.load(f)
        
        # Function to recursively search a JSON structure
        def search_json(obj, path=""):
            found_items = []
            
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check if value is a string and contains target
                    if isinstance(value, str) and TARGET_USER.lower() in value.lower():
                        found_items.append({
                            "type": "preference",
                            "path": current_path,
                            "value": value
                        })
                    
                    # Recursively search nested objects
                    found_items.extend(search_json(value, current_path))
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    found_items.extend(search_json(item, current_path))
            
            return found_items
        
        # Start searching from root
        pref_results = search_json(prefs_data)
        results.extend(pref_results)
        
        if results:
            print(f"Found {len(results)} preferences with matching username")
        else:
            print("No preferences found with matching username")
            
    except Exception as e:
        print(f"Error searching Preferences: {e}")
    
    return results

def search_local_state():
    """Search for username in Local State file"""
    print("\n[6] Searching Local State for username...")
    results = []
    
    if not os.path.exists(LOCAL_STATE):
        print(f"Local State file not found: {LOCAL_STATE}")
        return results
    
    try:
        with open(LOCAL_STATE, 'r', encoding='utf-8') as f:
            local_state_data = json.load(f)
        
        # Use the same recursive search function from search_preferences
        def search_json(obj, path=""):
            found_items = []
            
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check if value is a string and contains target
                    if isinstance(value, str) and TARGET_USER.lower() in value.lower():
                        found_items.append({
                            "type": "local_state",
                            "path": current_path,
                            "value": value
                        })
                    
                    # Recursively search nested objects
                    found_items.extend(search_json(value, current_path))
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    found_items.extend(search_json(item, current_path))
            
            return found_items
        
        # Start searching from root
        local_state_results = search_json(local_state_data)
        results.extend(local_state_results)
        
        if results:
            print(f"Found {len(results)} entries in Local State with matching username")
        else:
            print("No entries found in Local State with matching username")
            
    except Exception as e:
        print(f"Error searching Local State: {e}")
    
    return results

def search_filesystem():
    """Search for username in all files in the Chrome directory"""
    print("\n[7] Searching Chrome filesystem for username...")
    results = []
    
    # Define extensions to search in
    searchable_extensions = ['.txt', '.json', '.log', '.js', '.html', '.htm', '.xml']
    
    for root, dirs, files in os.walk(CHROME_PATH):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip large files and non-text files
            if os.path.getsize(file_path) > 10 * 1024 * 1024:  # Skip files > 10MB
                continue
                
            ext = os.path.splitext(file)[1].lower()
            if ext not in searchable_extensions and not file.lower() in ['cookies', 'history', 'web data', 'login data']:
                continue
            
            try:
                # Try to read file as text
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Try different encodings
                for encoding in ['utf-8', 'latin-1', 'ascii']:
                    try:
                        text_content = content.decode(encoding)
                        
                        # Search for target username
                        if TARGET_USER.lower() in text_content.lower():
                            # Find the line containing the target
                            lines = text_content.split('\n')
                            matching_lines = []
                            
                            for i, line in enumerate(lines):
                                if TARGET_USER.lower() in line.lower():
                                    context_start = max(0, i - 2)
                                    context_end = min(len(lines), i + 3)
                                    context = lines[context_start:context_end]
                                    matching_lines.append({
                                        "line_number": i + 1,
                                        "content": line,
                                        "context": context
                                    })
                            
                            results.append({
                                "type": "file_content",
                                "file_path": os.path.relpath(file_path, CHROME_PATH),
                                "matching_lines": matching_lines
                            })
                            
                            print(f"Found target in file: {os.path.relpath(file_path, CHROME_PATH)}")
                        
                        # We successfully decoded, no need to try other encodings
                        break
                        
                    except UnicodeDecodeError:
                        # Try the next encoding
                        continue
            except Exception as e:
                # Skip files we can't read
                continue
    
    if not results:
        print("No files found containing the target username")
    
    return results

def main():
    print(f"===== Searching Chrome data for '{TARGET_USER}' =====")
    
    all_results = []
    
    # Search in structured data sources
    login_results = search_login_data()
    web_data_results = search_web_data()
    history_results = search_history()
    bookmark_results = search_bookmarks()
    preferences_results = search_preferences()
    local_state_results = search_local_state()
    
    # Search in filesystem
    filesystem_results = search_filesystem()
    
    # Combine all results
    all_results.extend(login_results)
    all_results.extend(web_data_results)
    all_results.extend(history_results)
    all_results.extend(bookmark_results)
    all_results.extend(preferences_results)
    all_results.extend(local_state_results)
    all_results.extend(filesystem_results)
    
    # Write results to a JSON file
    output_file = "jean_marc_samson_search_results.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=4, default=str)
        print(f"\nResults saved to {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")
    
    # Print summary
    print("\n===== Search Results Summary =====")
    print(f"Total matching items found: {len(all_results)}")
    
    type_counts = {}
    for result in all_results:
        result_type = result.get('type', 'unknown')
        type_counts[result_type] = type_counts.get(result_type, 0) + 1
    
    for result_type, count in type_counts.items():
        print(f"- {result_type}: {count} items")

if __name__ == "__main__":
    main()
