# Chrome Browser Data Analysis Report

## Overview
This report presents findings from the analysis of Chrome browser data extracted from the "Lil samson bro" user profile.
The focus was on extracting encrypted credentials, cookies, and authentication data from educational websites.

## Chrome Encryption Key Analysis
- ✅ Successfully extracted the encrypted key from Chrome's Local State file
- The key is encrypted using Windows DPAPI (Data Protection API)
- Encrypted key (base64): `RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAABVOiWUgRyMQ6vWBDL/6FxlEAAAABwAAABHAG8AbwBnAGwAZQAgAEMAaAByAG8AbQBlAAAAEGYAAAABAAAgAAAAYrZ/08LqY/KQ10wqeo9UNGOc6/WceiB0E6F8oubISVEAAAAADoAAAAACAAAgAAAAzs6qPyAzIYTXxBe51MJy6YxHBlUd/KbHt88uaBXF0IkwAAAAAEDe7jUT8yfYunktxZXvZAjbvAimwYZIJ/Kz7jUknL5JW38JPX7jpLHiZ2EOSXexQAAAAJ4bMpIuX+lz3htKa3eoqBZyrGbGeMvAMyr+6BYCUBGpqQSWEOkAVoY8TVft8GA8OinXkfUp+MJh7Jwfi44hXnw=`
- **Limitation**: This key can only be decrypted on the original Windows system
  with access to the user's account that created the key

## Cookie Analysis
- Found 28 encrypted cookies
- All cookies share the same encryption prefix: `763230`
  This suggests Chrome is using consistent encryption across all cookies

### Educational Domains Found
- everyone.ednet.ns.ca
- saml.nspes.ca
- sishrsb.ednet.ns.ca

### Key Authentication Cookies
- **ESimpleSAMLSessionID** on *everyone.ednet.ns.ca*
  - Encrypted value (hex): `7632300A63052227BA33026B9BFCEC06F228FC2C6C153AED944FB4AD5D23A3109B6F19B378F892FA66B77D214D9EC36FB61EAFE6799BC105A842E7C1D12F0B627625CB4C50C407670274AA805726F9460645379C7738BDAD728EE50666BFE4`
  - Length: 95 bytes
- **SimpleSAMLSessionID** on *saml.nspes.ca*
  - Encrypted value (hex): `7632306E0713E368BE732BFBAD6368BACF6321AAA3E766B1C92756F7D6BC959B2104EB5D27AB7CAA622A6D361573ECA0F24044F828FB79C2960BBC71C7C2A608ACF9A1CAD3BCA0130A96EBB7EEB4633D5E4C3DEC6133A64F2986AA3C5E06C1`
  - Length: 95 bytes
- **psaid** on *sishrsb.ednet.ns.ca*
  - Encrypted value (hex): `763230D769443FE71C4B95C02561C8420E94A4D2D981D4EC7441A54792EB7AE2A7AC2653DF5FF8EF9C5DABFE4FDF0CF46243030EF1FBD24AF6549279C5EEFE41CA2F17886D51444332E61CA0D0430DA5A98964C4568499B07706EE18199CFF8ECE3B74C3BBDC2A22B1F0142D22937F638EBB455E167F3AF8658868E6722D58AE0A1F2B`
  - Length: 131 bytes
- **JSESSIONID** on *sishrsb.ednet.ns.ca*
  - Encrypted value (hex): `763230E9FA36A6A85A3BC3EFA999EC19278EC0C28E4A8F93F02F9A7F69BCEAB6C92215D13CD8B396D464131769AA5288B3877A924588E42931237359D16EAD13597C2B979522C6333B28E0286A0547B29BF09A67EFB8E045D4EAEE7408F0D2`
  - Length: 95 bytes

## Chrome Encryption Format
Chrome uses AES-256-GCM for cookie and password encryption in recent versions:
1. The master key is stored in the Local State file (encrypted with DPAPI)
2. This master key is used to decrypt the individual cookies and passwords
3. The encryption format is: `v10` + encrypted_data + nonce + tag

The encryption prefix `763230` is hexadecimal for the ASCII characters `v20`,
indicating Chrome is using version 10 (v10) of its encryption scheme.

## Educational Authentication System Analysis
Based on the cookie names and domains, we can identify the authentication systems in use:
1. **SimpleSAMLphp** - An open-source SAML 2.0 authentication system
   - Used by `saml.nspes.ca` and `everyone.ednet.ns.ca`
   - Cookie: `SimpleSAMLSessionID` and `ESimpleSAMLSessionID`

2. **Java-based Portal** - Likely PowerSchool or similar education management system
   - Used by `sishrsb.ednet.ns.ca`
   - Cookies: `JSESSIONID` and `psaid` (PowerSchool ID)

## Decryption Challenges
The Chrome data is encrypted using a system that requires:
1. The encrypted key from the Local State file (which we have)
2. Decryption of that key using Windows DPAPI (which requires the original Windows user account)
3. Using the decrypted key to decrypt the cookies/passwords

Without access to the Windows user account, direct decryption in this environment is not possible.

## Authentication Flow
The authentication flow for these educational systems appears to be:
1. User visits a service (e.g., `gnspes.ca` or `sishrsb.ednet.ns.ca`)
2. Redirect to the SAML authentication service at `saml.nspes.ca`
3. After authentication, the user receives cookies for all related domains
4. The session is maintained across educational services using these cookies

## Conclusions
1. We have successfully extracted encrypted cookies from the Chrome profile
2. The cookies represent active sessions on Nova Scotia educational systems
3. Complete decryption would require access to the original Windows system
4. The authentication flow and cookie patterns provide insight into how the
   educational systems manage authentication and sessions