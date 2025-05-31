#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import re
import sys
import json

# Target URLs
GNSPES_URL = "https://gnspes.ca/"
EDNET_URL = "https://everyone.ednet.ns.ca/landing.php"
SAML_URL = "https://saml.nspes.ca/simplesaml/module.php/core/loginuserpass.php"
POWERSCHOOL_URL = "https://sishrsb.ednet.ns.ca/teachers/pw.html"

def analyze_login_form(url):
    """Analyze login form structure on a given URL"""
    print(f"\n=== Analyzing login form at {url} ===")
    
    try:
        # Create a session to maintain cookies
        session = requests.Session()
        
        # Set a realistic user agent
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
        }
        
        # Make the request
        response = session.get(url, headers=headers, timeout=10)
        
        # Check if successful
        if response.status_code == 200:
            print(f"Successfully loaded page (status {response.status_code})")
            
            # Parse the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login forms
            forms = soup.find_all('form')
            
            if forms:
                print(f"Found {len(forms)} form(s)")
                
                for i, form in enumerate(forms):
                    print(f"\nForm #{i+1}:")
                    print(f"  Action: {form.get('action', 'None')}")
                    print(f"  Method: {form.get('method', 'None')}")
                    print(f"  ID: {form.get('id', 'None')}")
                    
                    # Find form fields
                    inputs = form.find_all(['input', 'select', 'textarea'])
                    if inputs:
                        print("  Fields:")
                        for inp in inputs:
                            field_type = inp.get('type', 'text')
                            field_name = inp.get('name', 'Unknown')
                            field_id = inp.get('id', 'None')
                            field_value = inp.get('value', '')
                            
                            print(f"    {field_name} ({field_type}, id={field_id}) = '{field_value}'")
                    
                    # Find submit buttons
                    buttons = form.find_all(['button', 'input[type="submit"]'])
                    if buttons:
                        print("  Buttons:")
                        for button in buttons:
                            button_type = button.get('type', 'button')
                            button_name = button.get('name', 'Unknown')
                            button_id = button.get('id', 'None')
                            button_value = button.get('value', '')
                            
                            print(f"    {button_name} ({button_type}, id={button_id}) = '{button_value}'")
            else:
                print("No forms found on the page")
                
                # Look for JavaScript-based login
                scripts = soup.find_all('script')
                login_related_scripts = []
                
                for script in scripts:
                    script_text = script.string if script.string else ''
                    if any(keyword in script_text.lower() for keyword in ['login', 'auth', 'password', 'credentials']):
                        login_related_scripts.append(script_text)
                
                if login_related_scripts:
                    print(f"Found {len(login_related_scripts)} login-related scripts")
                    for i, script in enumerate(login_related_scripts[:2]):  # Limit to 2 for brevity
                        print(f"\nScript #{i+1} snippet:")
                        print(script[:300] + "..." if len(script) > 300 else script)
            
            # Look for redirects or authentication endpoints
            links = soup.find_all('a', href=True)
            auth_links = []
            
            for link in links:
                href = link['href']
                if any(keyword in href.lower() for keyword in ['login', 'auth', 'signin', 'logon']):
                    auth_links.append(href)
            
            if auth_links:
                print(f"\nFound {len(auth_links)} authentication-related links:")
                for link in auth_links[:5]:  # Limit to 5 for brevity
                    print(f"  {link}")
            
            # Check for redirects in HTTP headers
            if response.history:
                print("\nRedirects occurred:")
                for r in response.history:
                    print(f"  {r.status_code} {r.url} -> {r.headers.get('Location', 'Unknown')}")
                print(f"Final URL: {response.url}")
            
            # Return cookies for inspection
            return {
                "url": response.url,
                "cookies": dict(session.cookies),
                "status_code": response.status_code,
                "redirects": [r.url for r in response.history]
            }
        else:
            print(f"Failed to load page. Status code: {response.status_code}")
            return None
    
    except Exception as e:
        print(f"Error analyzing login form: {e}")
        return None

def follow_auth_flow():
    """Follow the authentication flow from GNSPES to SAML and capture the details"""
    print("\n=== Following Authentication Flow ===")
    
    try:
        # Create a session to maintain cookies
        session = requests.Session()
        
        # Set a realistic user agent
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
        }
        
        # Step 1: Start at GNSPES
        print("\nStep 1: Accessing GNSPES homepage")
        response = session.get(GNSPES_URL, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"Successfully loaded GNSPES (status {response.status_code})")
            
            # Print current cookies
            print("Cookies after GNSPES access:")
            for cookie_name, cookie_value in session.cookies.items():
                print(f"  {cookie_name}: {cookie_value}")
            
            # Check for redirects
            if response.history:
                print("\nRedirects occurred during GNSPES access:")
                for r in response.history:
                    print(f"  {r.status_code} {r.url} -> {r.headers.get('Location', 'Unknown')}")
                print(f"Final URL: {response.url}")
            
            # Step 2: If redirected to EDNET, follow
            if "everyone.ednet.ns.ca" in response.url:
                print("\nStep 2: Redirected to EDNET")
            else:
                print("\nStep 2: Accessing EDNET manually")
                response = session.get(EDNET_URL, headers=headers, timeout=10)
            
            print(f"Current URL: {response.url}")
            
            # Print current cookies
            print("Cookies after EDNET access:")
            for cookie_name, cookie_value in session.cookies.items():
                print(f"  {cookie_name}: {cookie_value}")
            
            # Step 3: Check if redirected to SAML login
            if "saml.nspes.ca" in response.url:
                print("\nStep 3: Redirected to SAML login")
                current_url = response.url
            else:
                # Find SAML links in the page
                soup = BeautifulSoup(response.text, 'html.parser')
                saml_links = []
                
                for a in soup.find_all('a', href=True):
                    if "saml" in a['href'].lower():
                        saml_links.append(a['href'])
                
                if saml_links:
                    print(f"Found {len(saml_links)} SAML-related links")
                    
                    # Try to get the login page URL
                    login_url = saml_links[0]
                    
                    # Make it absolute if it's relative
                    if not login_url.startswith('http'):
                        if login_url.startswith('/'):
                            base_url = response.url.split('//')[0] + '//' + response.url.split('//')[1].split('/')[0]
                            login_url = base_url + login_url
                        else:
                            login_url = response.url.rsplit('/', 1)[0] + '/' + login_url
                    
                    print(f"Following SAML link: {login_url}")
                    
                    response = session.get(login_url, headers=headers, timeout=10)
                    current_url = response.url
                else:
                    print("No SAML links found on the page. Using the known SAML URL.")
                    current_url = SAML_URL
                    response = session.get(current_url, headers=headers, timeout=10)
            
            # Step 4: Analyze the login form
            print("\nStep 4: Analyzing the login form")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login forms
            forms = soup.find_all('form')
            login_form = None
            
            for form in forms:
                # Check if this looks like a login form
                inputs = form.find_all('input')
                input_names = [inp.get('name', '').lower() for inp in inputs]
                
                if any(name in ['username', 'user', 'userid', 'email', 'login'] for name in input_names) and \
                   any(name in ['password', 'passwd', 'pwd'] for name in input_names):
                    login_form = form
                    break
            
            if login_form:
                print("Found login form:")
                print(f"  Action: {login_form.get('action', 'None')}")
                print(f"  Method: {login_form.get('method', 'None')}")
                
                # Get form fields
                inputs = login_form.find_all('input')
                form_data = {}
                
                print("  Fields:")
                for inp in inputs:
                    field_type = inp.get('type', 'text')
                    field_name = inp.get('name', 'Unknown')
                    field_id = inp.get('id', 'None')
                    field_value = inp.get('value', '')
                    
                    print(f"    {field_name} ({field_type}, id={field_id}) = '{field_value}'")
                    
                    # Record field values
                    if field_name:
                        form_data[field_name] = field_value
                
                # Look for password and username fields
                username_field = None
                password_field = None
                
                for inp in inputs:
                    field_name = inp.get('name', '').lower()
                    field_type = inp.get('type', '')
                    
                    if field_type == 'password':
                        password_field = inp.get('name')
                    elif field_type == 'text' or field_type == 'email':
                        if any(n in field_name for n in ['user', 'email', 'login', 'id']):
                            username_field = inp.get('name')
                
                print(f"\nUsername field: {username_field}")
                print(f"Password field: {password_field}")
                
                # Return form information for manual login attempt
                return {
                    "login_url": current_url,
                    "form_action": login_form.get('action', ''),
                    "form_method": login_form.get('method', 'post'),
                    "form_data": form_data,
                    "username_field": username_field,
                    "password_field": password_field,
                    "cookies": dict(session.cookies)
                }
            else:
                print("No login form found on the page")
        else:
            print(f"Failed to access GNSPES. Status code: {response.status_code}")
    
    except Exception as e:
        print(f"Error following authentication flow: {e}")
    
    return None

def main():
    print("===== Nova Scotia Education System Login Analysis =====")
    
    # Analyze each login page
    print("\n[1] Analyzing GNSPES Login")
    gnspes_info = analyze_login_form(GNSPES_URL)
    
    print("\n[2] Analyzing EDNET Login")
    ednet_info = analyze_login_form(EDNET_URL)
    
    print("\n[3] Analyzing SAML Login")
    saml_info = analyze_login_form(SAML_URL)
    
    print("\n[4] Analyzing PowerTeacher Login")
    powerschool_info = analyze_login_form(POWERSCHOOL_URL)
    
    # Follow the authentication flow
    print("\n[5] Following Authentication Flow")
    auth_flow = follow_auth_flow()
    
    # Save the information to a file
    all_info = {
        "gnspes": gnspes_info,
        "ednet": ednet_info,
        "saml": saml_info,
        "powerschool": powerschool_info,
        "auth_flow": auth_flow
    }
    
    with open("/workspaces/JaiziahGreene/auth_analysis.json", "w") as f:
        json.dump(all_info, f, indent=2)
    
    print("\nAnalysis complete. Information saved to auth_analysis.json")
    
    # Print summary of findings
    print("\n===== Summary of Findings =====")
    
    if auth_flow:
        print("\nAuthentication Flow:")
        print(f"Login URL: {auth_flow.get('login_url', 'Unknown')}")
        print(f"Form Action: {auth_flow.get('form_action', 'Unknown')}")
        print(f"Form Method: {auth_flow.get('form_method', 'Unknown')}")
        print(f"Username Field: {auth_flow.get('username_field', 'Unknown')}")
        print(f"Password Field: {auth_flow.get('password_field', 'Unknown')}")
        
        print("\nTo simulate login:")
        print(f"1. Navigate to: {auth_flow.get('login_url', 'Unknown')}")
        print(f"2. Fill in these form fields:")
        for key, value in auth_flow.get('form_data', {}).items():
            print(f"   - {key}: {value}")
        print(f"3. Set {auth_flow.get('username_field', 'Username')} to jean-marc.samson or similar")
        print(f"4. Set {auth_flow.get('password_field', 'Password')} to your target password")
        print("5. Submit the form")
    else:
        print("Could not determine authentication flow")

if __name__ == "__main__":
    main()
