#!/usr/bin/env python3
import os
import sqlite3
import json
import base64
import datetime
import sys
from urllib.parse import urlparse, parse_qs
import re

CHROME_PATH = "/workspaces/JaiziahGreene/Lil samson bro/Local/Google/Chrome/User Data"
DEFAULT_PROFILE = os.path.join(CHROME_PATH, "Default")

def print_section(title):
    """Print a section title with separators."""
    print("\n" + "="*80)
    print(f"  {title}  ".center(80, "="))
    print("="*80 + "\n")

def try_connect(db_path):
    """Attempt to connect to a SQLite database, handling locked files."""
    try:
        # Make a copy of the database file to avoid locking issues
        import shutil
        import tempfile
        
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, os.path.basename(db_path))
        shutil.copy2(db_path, temp_file)
        
        conn = sqlite3.connect(temp_file)
        return conn, temp_file, temp_dir
    except Exception as e:
        print(f"Error accessing {db_path}: {e}")
        return None, None, None

def cleanup(temp_file, temp_dir):
    """Clean up temporary files."""
    if temp_file and os.path.exists(temp_file):
        try:
            os.remove(temp_file)
        except:
            pass
    if temp_dir and os.path.exists(temp_dir):
        try:
            os.rmdir(temp_dir)
        except:
            pass

def timestamp_to_datetime(webkit_timestamp):
    """Convert a WebKit timestamp to a readable datetime."""
    if webkit_timestamp:
        # WebKit timestamps are microseconds since 1601-01-01
        epoch_start = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=webkit_timestamp)
        return epoch_start + delta
    return "N/A"

def analyze_history(history_path=os.path.join(DEFAULT_PROFILE, "History")):
    """Analyze the Chrome History database for interesting entries."""
    print_section("CHROME HISTORY ANALYSIS")
    
    conn, temp_file, temp_dir = try_connect(history_path)
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Get the most recent URLs with details
    print("Most Recent URL Visits:")
    print("-" * 100)
    try:
        cursor.execute("""
            SELECT urls.url, urls.title, urls.visit_count, urls.last_visit_time,
                   visits.visit_time, visits.transition, visits.visit_duration
            FROM urls
            JOIN visits ON urls.id = visits.url
            ORDER BY visits.visit_time DESC
            LIMIT 100
        """)
        
        for row in cursor.fetchall():
            url, title, visit_count, last_visit_time, visit_time, transition, duration = row
            
            # Parse and clean the URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Decode URL parameters if present
            params = {}
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
            
            # Check for authentication-related keywords in URL or parameters
            auth_indicators = ['login', 'auth', 'token', 'session', 'signin', 'password', 'credential']
            is_auth_related = any(
                indicator in url.lower() or 
                any(indicator in key.lower() for key in params.keys())
                for indicator in auth_indicators
            )
            
            # Format output
            print(f"URL: {url}")
            print(f"Title: {title}")
            print(f"Domain: {domain}")
            print(f"Visit Count: {visit_count}")
            print(f"Last Visit: {timestamp_to_datetime(last_visit_time)}")
            
            # Flag authentication-related URLs
            if is_auth_related:
                print("⚠️  AUTH-RELATED URL ⚠️")
                # Extract specific parameters that might be interesting, but not showing values
                auth_params = [k for k in params.keys() if any(indicator in k.lower() for indicator in auth_indicators)]
                if auth_params:
                    print(f"Auth-related parameters: {', '.join(auth_params)}")
            
            print("-" * 100)
    except sqlite3.Error as e:
        print(f"Error querying history: {e}")
    
    # Check for form submissions (POST requests)
    print("\nForm Submissions:")
    print("-" * 100)
    try:
        cursor.execute("""
            SELECT urls.url, urls.title, visits.visit_time
            FROM urls
            JOIN visits ON urls.id = visits.url
            WHERE visits.transition & 0xFF = 7  -- 7 is FORM_SUBMIT
            ORDER BY visits.visit_time DESC
            LIMIT 20
        """)
        
        for row in cursor.fetchall():
            url, title, visit_time = row
            print(f"URL: {url}")
            print(f"Title: {title}")
            print(f"Submission Time: {timestamp_to_datetime(visit_time)}")
            print("-" * 100)
    except sqlite3.Error as e:
        print(f"Error querying form submissions: {e}")
    
    # Check for downloads
    print("\nDownloads:")
    print("-" * 100)
    try:
        cursor.execute("""
            SELECT target_path, tab_url, site_url, start_time, received_bytes
            FROM downloads
            ORDER BY start_time DESC
            LIMIT 20
        """)
        
        for row in cursor.fetchall():
            path, tab_url, site_url, start_time, size = row
            print(f"Downloaded: {path}")
            print(f"From: {site_url}")
            print(f"Tab URL: {tab_url}")
            print(f"Time: {timestamp_to_datetime(start_time)}")
            print(f"Size: {size} bytes")
            print("-" * 100)
    except sqlite3.Error as e:
        print(f"Error querying downloads: {e}")
    
    conn.close()
    cleanup(temp_file, temp_dir)

def analyze_cookies(cookies_path=os.path.join(DEFAULT_PROFILE, "Cookies")):
    """Analyze the Chrome Cookies database for authentication-related cookies."""
    print_section("CHROME COOKIES ANALYSIS")
    
    conn, temp_file, temp_dir = try_connect(cookies_path)
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Get auth-related cookies
    print("Authentication-Related Cookies:")
    print("-" * 100)
    
    auth_keywords = ['auth', 'session', 'token', 'login', 'sid', 'user', 'account', 'secure', 'remember']
    
    try:
        cursor.execute("""
            SELECT host_key, name, path, value, creation_utc, last_access_utc, 
                   expires_utc, is_secure, is_httponly, has_expires, is_persistent
            FROM cookies
            ORDER BY last_access_utc DESC
        """)
        
        found_auth_cookies = False
        
        for row in cursor.fetchall():
            host, name, path, value, creation, last_access, expires, secure, httponly, has_expires, persistent = row
            
            # Check if this is likely an auth-related cookie
            if any(keyword in name.lower() for keyword in auth_keywords):
                found_auth_cookies = True
                print(f"Host: {host}")
                print(f"Cookie Name: {name}")
                print(f"Path: {path}")
                print(f"Is Secure: {'Yes' if secure else 'No'}")
                print(f"Is HTTP Only: {'Yes' if httponly else 'No'}")
                print(f"Created: {timestamp_to_datetime(creation)}")
                print(f"Last Accessed: {timestamp_to_datetime(last_access)}")
                print(f"Expires: {timestamp_to_datetime(expires) if has_expires else 'Session Cookie'}")
                
                # Don't print the actual cookie value for security reasons
                print(f"Value: {'*' * min(10, len(value) if value else 0)} [REDACTED]")
                print("-" * 100)
        
        if not found_auth_cookies:
            print("No authentication-related cookies found.")
    except sqlite3.Error as e:
        print(f"Error querying cookies: {e}")
    
    # Get all unique domains with cookies
    print("\nDomains with Cookies:")
    print("-" * 100)
    try:
        cursor.execute("""
            SELECT DISTINCT host_key, COUNT(*) as cookie_count
            FROM cookies
            GROUP BY host_key
            ORDER BY cookie_count DESC
        """)
        
        for row in cursor.fetchall():
            host, count = row
            print(f"Domain: {host} - {count} cookies")
    except sqlite3.Error as e:
        print(f"Error querying cookie domains: {e}")
    
    conn.close()
    cleanup(temp_file, temp_dir)

def analyze_web_data(web_data_path=os.path.join(DEFAULT_PROFILE, "Web Data")):
    """Analyze Web Data for autofill data and saved information."""
    print_section("CHROME WEB DATA ANALYSIS")
    
    conn, temp_file, temp_dir = try_connect(web_data_path)
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Check for autofill data
    print("Autofill Data:")
    print("-" * 100)
    try:
        cursor.execute("SELECT name, value, date_created, date_last_used, count FROM autofill")
        rows = cursor.fetchall()
        
        if rows:
            for row in cursor.fetchall():
                name, value, created, last_used, count = row
                print(f"Field Name: {name}")
                # Carefully handle display of potentially sensitive information
                if name.lower() in ['email', 'username', 'name', 'phone']:
                    print(f"Value: {value}")  # Show these as they're less sensitive
                else:
                    print(f"Value: {'*' * min(10, len(value) if value else 0)} [REDACTED]")  # Redact other values
                print(f"Created: {timestamp_to_datetime(created)}")
                print(f"Last Used: {timestamp_to_datetime(last_used)}")
                print(f"Use Count: {count}")
                print("-" * 100)
        else:
            print("No autofill data found.")
    except sqlite3.Error as e:
        print(f"Error querying autofill data: {e}")
    
    # Check for saved addresses
    print("\nSaved Addresses:")
    print("-" * 100)
    try:
        # This table schema might vary slightly depending on Chrome version
        cursor.execute("""
            SELECT company_name, street_address, city, state, zipcode, 
                   country_code, date_modified, use_count
            FROM autofill_profiles
        """)
        
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                company, street, city, state, zipcode, country, modified, count = row
                if company:
                    print(f"Company: {company}")
                if street:
                    print(f"Street: {street}")
                if city:
                    print(f"City: {city}")
                if state:
                    print(f"State/Province: {state}")
                if zipcode:
                    print(f"ZIP/Postal Code: {zipcode}")
                if country:
                    print(f"Country: {country}")
                print(f"Last Modified: {timestamp_to_datetime(modified)}")
                print(f"Use Count: {count}")
                print("-" * 100)
        else:
            print("No saved addresses found.")
    except sqlite3.Error as e:
        print(f"Error querying address data: {e}")
    
    conn.close()
    cleanup(temp_file, temp_dir)

def analyze_cache_entries():
    """Try to identify and examine cached HTTP requests that might contain auth data."""
    print_section("CHROME CACHE ANALYSIS")
    
    cache_path = os.path.join(DEFAULT_PROFILE, "Cache")
    if not os.path.exists(cache_path):
        print(f"Cache directory not found at: {cache_path}")
        return
    
    print("Cache Directory Structure:")
    for root, dirs, files in os.walk(cache_path, topdown=True):
        print(f"Directory: {root}")
        print(f"  Subdirectories: {len(dirs)}")
        print(f"  Files: {len(files)}")
        # Only process the first level
        if root == cache_path:
            dirs[:] = []  # This prevents walking into subdirectories
    
    print("\nCache analysis is beyond the scope of a simple script.")
    print("Advanced forensic tools like 'Hindsight' would be needed for a full cache analysis.")

def analyze_local_state(local_state_path=os.path.join(CHROME_PATH, "Local State")):
    """Analyze the Local State file for sync data and other account information."""
    print_section("CHROME LOCAL STATE ANALYSIS")
    
    if not os.path.exists(local_state_path):
        print(f"Local State file not found at: {local_state_path}")
        return
    
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Look for profile info
        print("Profile Information:")
        print("-" * 100)
        if 'profile' in data:
            if 'info_cache' in data['profile']:
                for profile_id, profile_info in data['profile']['info_cache'].items():
                    print(f"Profile: {profile_id}")
                    if 'name' in profile_info:
                        print(f"Name: {profile_info['name']}")
                    if 'user_name' in profile_info:
                        print(f"User Name: {profile_info['user_name']}")
                    if 'gaia_id' in profile_info:
                        print(f"GAIA ID: {profile_info['gaia_id']}")
                    if 'email' in profile_info:
                        print(f"Email: {profile_info['email']}")
                    print("-" * 100)
        
        # Look for sync info
        print("\nSync Information:")
        print("-" * 100)
        if 'sync' in data:
            if 'last_signin_username' in data['sync']:
                print(f"Last Signin Username: {data['sync']['last_signin_username']}")
            
            # Check for sync tokens (don't display actual token values)
            if 'signin_scoped_device_id' in data['sync']:
                print(f"Device ID: {data['sync']['signin_scoped_device_id']}")
            
            print("-" * 100)
    
    except Exception as e:
        print(f"Error reading Local State file: {e}")

def check_network_action_predictor(predictor_path=os.path.join(DEFAULT_PROFILE, "Network Action Predictor")):
    """Check Network Action Predictor database for URL predictions related to auth."""
    print_section("NETWORK ACTION PREDICTOR ANALYSIS")
    
    conn, temp_file, temp_dir = try_connect(predictor_path)
    if not conn:
        return
    
    cursor = conn.cursor()
    
    print("URL Predictions (may contain partial form submissions):")
    print("-" * 100)
    
    try:
        cursor.execute("SELECT user_text, url FROM network_action_predictor")
        rows = cursor.fetchall()
        
        auth_keywords = ['login', 'auth', 'signin', 'password', 'email', 'username', 'user', 'account']
        found_auth = False
        
        for row in rows:
            user_text, url = row
            
            # Check if this prediction is related to auth
            if any(keyword in user_text.lower() or keyword in url.lower() for keyword in auth_keywords):
                found_auth = True
                print(f"User Text: {user_text}")
                print(f"URL: {url}")
                print("-" * 100)
        
        if not found_auth:
            print("No authentication-related URL predictions found.")
    
    except sqlite3.Error as e:
        print(f"Error querying Network Action Predictor: {e}")
    
    conn.close()
    cleanup(temp_file, temp_dir)

def main():
    """Main function to execute all analysis."""
    print("Chrome Forensic Analyzer")
    print("=" * 50)
    print(f"Analyzing Chrome data in: {CHROME_PATH}")
    print("=" * 50)
    
    # Run all analysis functions
    analyze_history()
    analyze_cookies()
    analyze_web_data()
    analyze_cache_entries()
    analyze_local_state()
    check_network_action_predictor()
    
    print("\n" + "=" * 80)
    print("  ANALYSIS COMPLETE  ".center(80, "="))
    print("=" * 80)

if __name__ == "__main__":
    main()
