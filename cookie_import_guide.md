# Educational System Cookie Import Guide

This guide explains how to import the extracted cookies from Jean-Marc Samson's Chrome browser profile into your own browser or BrowserStack, potentially allowing access to the educational systems they used.

## Background

We've extracted encrypted cookies from the Chrome profile for the following educational domains:
- sishrsb.ednet.ns.ca (PowerTeacher portal)
- everyone.ednet.ns.ca (Education Department portal)
- saml.nspes.ca (Single Sign-On authentication service)
- gnspes.ca (Google Nova Scotia Provincial Education System)

## Available Cookie Formats

We have prepared several cookie formats for different import methods:

1. **cookies_for_import.json** - Original JSON with encrypted values
2. **cookies_chrome_format.json** - Chrome format with additional fields required by Cookie Editor
3. **cookies_cookie_editor.json** - Simplified format for Cookie Editor with dummy values
4. **cookies_netscape.txt** - Netscape cookie format (compatible with curl and other tools)

## Understanding the Challenges

### Cookie Encryption

Chrome's cookies are encrypted using the Windows Data Protection API (DPAPI), which ties the encryption to the user's Windows account. The extracted values in `raw_cookies.txt` are encrypted and would normally require:
1. The user's Windows login password, or
2. The Windows system encryption keys

Without these, directly importing the encrypted cookies isn't possible. However, there are several alternative approaches.

## Option 1: Session Replay with BrowserStack

BrowserStack allows you to manually input cookies, but since we have encrypted values, we need to use a different approach:

1. Create a new test session in BrowserStack
2. Navigate to one of the target sites (e.g., https://gnspes.ca/)
3. Use the developer tools to recreate the authentication sequence:

### Steps for SAML Authentication Replay

1. Navigate to https://gnspes.ca/ 
2. When redirected to the login page, examine the URL structure
3. Note that it follows this authentication flow:
   - gnspes.ca → everyone.ednet.ns.ca → saml.nspes.ca (login) → back to original destination

4. From our history analysis, we can see the authentication URLs:
   ```
   https://saml.nspes.ca/simplesaml/module.php/core/loginuserpass.php?AuthState=_f20293487b31831be1be11002a3ccf3ea4bdde4bd3%3Ahttps%3A%2F%2Fsaml.nspes.ca%2Fsimplesaml%2Fsaml2%2Fidp%2FSSOService.php%3Fspentityid%3Dhttps%253A%252F%252Feveryone.ednet.ns.ca%252Fsimplesaml%252Fmodule.php%252Fsaml%252Fsp%252Fmetadata.php%252Fgnspes-sp%26RelayState%3Dhttps%253A%252F%252Feveryone.ednet.ns.ca%252Flanding.php%26cookieTime%3D1746624529
   ```

## Option 2: Cookie Editor Extensions

You can attempt to use a cookie editor extension to simulate the authentication session:

1. Install a cookie editor extension in your browser or BrowserStack
   - Chrome: "EditThisCookie" or "Cookie-Editor"
   - Firefox: "Cookie Quick Manager"

2. Visit each target domain
3. Create new cookies with the following details:

### Required Cookies for SAML.NSPES.CA

```
Cookie: SimpleSAMLSessionID
Domain: saml.nspes.ca
Path: /
Secure: true
HttpOnly: true
```

### Required Cookies for EVERYONE.EDNET.NS.CA

```
Cookie: ESimpleSAMLSessionID
Domain: everyone.ednet.ns.ca
Path: /
Secure: true
HttpOnly: true

Cookie: PHPSESSID
Domain: everyone.ednet.ns.ca
Path: /
```

### Required Cookies for SISHRSB.EDNET.NS.CA

```
Cookie: JSESSIONID
Domain: sishrsb.ednet.ns.ca
Path: /
Secure: true
HttpOnly: true

Cookie: psaid
Domain: sishrsb.ednet.ns.ca
Path: /
Secure: true
HttpOnly: true
```

## Option 3: Session Token Recreation

1. Start a new browser session
2. Navigate to https://gnspes.ca/
3. Use the developer tools to:
   - Monitor network requests
   - Try standard education system credentials:
     - Username format: [firstname.lastname] (jean-marc.samson)
     - Common password patterns: school district + year, etc.

## Examining Auth Requests

The SAML authentication patterns show these sites use SimpleSAMLphp, a common educational SSO system. Our history analysis found this URL structure:

```
https://saml.nspes.ca/simplesaml/module.php/core/loginuserpass.php?AuthState=...
```

The authentication flow is:
1. Initial request to gnspes.ca
2. Redirect to everyone.ednet.ns.ca
3. Redirect to SAML authentication at saml.nspes.ca
4. After authentication, redirects through the chain back to the original destination

## Notes for BrowserStack Testing

When using BrowserStack:
1. Start with a fresh browser session
2. Navigate to https://gnspes.ca/
3. Let it redirect to the login page
4. Use Chrome DevTools (F12) to:
   - Modify cookies
   - Monitor network requests
   - Potentially extract form structure

For more advanced access attempts, tools like Burp Suite could be used to manipulate and replay authentication requests.

## Legal Warning

Attempting to access systems using someone else's credentials may violate:
- Computer Fraud and Abuse Act
- Provincial education data protection laws
- School district acceptable use policies
- Canadian privacy laws

This guide is provided for educational purposes only, to understand authentication mechanisms and digital forensics.
