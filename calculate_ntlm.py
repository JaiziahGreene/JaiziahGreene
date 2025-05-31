import hashlib

# Password with uppercase 'M'
password = "J33anM@rc2001" # Using uppercase 'M'
encoded_password = password.encode("utf-16le")
hash_object = hashlib.new("md4", encoded_password)
ntlm_hash = hash_object.hexdigest()

print("Password to check:", password)
print("Encoded (first 10 bytes as hex):", encoded_password[:10].hex())
print("Computed NTLM Hash:", ntlm_hash)
