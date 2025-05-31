#!/usr/bin/env python3
# mkkrb5pw.py - Generate Kerberos string-to-key values for various algorithms
# Updated for modern impacket API

import sys
import binascii
from impacket.krb5.crypto import _enctype_table

def main():
    if len(sys.argv) < 3:
        print("Usage: %s <password> <salt> [etype]" % sys.argv[0])
        print("Example: %s 'azerty123' SVH-0236-S-17jean-marc.samson 3" % sys.argv[0])
        print("Etypes: 1=des-cbc-crc, 3=des-cbc-md5, 17=aes128-cts-hmac-sha1-96, 18=aes256-cts-hmac-sha1-96, 23=rc4-hmac")
        sys.exit(1)
    password = sys.argv[1]
    salt = sys.argv[2]
    etype = int(sys.argv[3]) if len(sys.argv) > 3 else 3  # Default to des-cbc-md5
    key = _enctype_table[etype].string_to_key(password, salt, None)
    # Modern impacket returns a Key object, get the raw key bytes
    if hasattr(key, 'contents'):
        key_bytes = key.contents
    else:
        key_bytes = key
    print("etype %d: %s" % (etype, binascii.hexlify(key_bytes).decode()))

if __name__ == '__main__':
    main()
