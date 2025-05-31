from passlib.hash import krb5des

# Known values
salt = "SVH-0236-S-17admin"
password = "Passw0rd!"
target_des_hash = "4f923207310e79a4"

# Generate the DES hash
generated_hash = krb5des.hash(password, salt=salt, checksum=0)
generated_hash_part = generated_hash.split("$")[-1]

# Compare
if generated_hash_part == target_des_hash:
    print(f"✅ Success! DES hash matches for password '{password}'.")
else:
    print(f"❌ Mismatch. Generated DES hash: {generated_hash_part}")
