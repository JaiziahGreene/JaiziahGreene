# Kerberos des_cbc_md5 (DES) string-to-key implementation using pyDes
# This version closely follows the MIT/Heimdal C reference and community scripts
# Reference: https://github.com/ra5k/kerberos-string2key/blob/master/kerberos_string2key.py

import hashlib
import pyDes

# --- NTLM hash check ---
def ntlm_hash(password):
    pw = password.encode('utf-16le')
    return hashlib.new('md4', pw).hexdigest()

def str2key_des(password, salt):
    # Step 1: Concatenate password and salt, encode as UTF-8
    data = (password + salt).encode('utf-8')
    # Step 2: Pad to multiple of 8 bytes with nulls
    if len(data) % 8 != 0:
        data += b'\x00' * (8 - (len(data) % 8))
    # Step 3: DES-CBC encrypt with zero IV, key is all zeroes
    key = b'\x00' * 8
    iv = b'\x00' * 8
    cipher = pyDes.des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_NORMAL)
    out = cipher.encrypt(data)
    # Step 4: The last 8 bytes are the key, but must be fixed for parity
    keybytes = out[-8:]
    keybytes = fix_parity(keybytes)
    # Step 5: If weak key, XOR with 0xF0 and fix parity again
    if is_weak_des_key(keybytes):
        keybytes = bytes([b ^ 0xF0 for b in keybytes])
        keybytes = fix_parity(keybytes)
    return keybytes.hex()

def fix_parity(keybytes):
    # Set odd parity for each byte
    fixed = bytearray()
    for b in keybytes:
        b &= 0xFE
        ones = bin(b).count('1')
        if ones % 2 == 0:
            b |= 1
        fixed.append(b)
    return bytes(fixed)

def is_weak_des_key(key):
    weak_keys = [
        b"\x01\x01\x01\x01\x01\x01\x01\x01",
        b"\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
        b"\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E",
        b"\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
        b"\x01\xFE\x01\xFE\x01\xFE\x01\xFE",
        b"\xFE\x01\xFE\x01\xFE\x01\xFE\x01",
        b"\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1",
        b"\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E",
    ]
    return key in weak_keys

if __name__ == "__main__":
    password = "Passw0rd!"
    salt = "SVH-0236-S-17admin"
    print("NTLM hash:", ntlm_hash(password))
    print("Kerberos des_cbc_md5 key:", str2key_des(password, salt))
    print("Expected Kerberos des_cbc_md5: 4f923207310e79a4")
    print("Expected NTLM: fc525c9683e8fe067095ba2ddc971889")
