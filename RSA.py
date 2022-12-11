
import rsa
"""
public_key, private_key = rsa.newkeys(2048)

with open("public.pem", "wb") as f:
   f.write(public_key.save_pkcs1("PEM"))


with open("private.pem", "wb") as f:
    f.write(private_key.save_pkcs1("PEM"))

"""


with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

# Encrypting the AES with RSA public Key

#encrypted_message = open("encrypted_message", "rb").read()
#print(encrypted_message)

#decrypt_message = rsa.decrypt(encrypted_message, private_key)
#print(decrypt_message.decode())

# Authentication and verification


message = "Authentication between sender and receiver"

signature = rsa.sign(message.encode(), private_key, "SHA-256")

with open("Signature", "wb") as f:
     f.write(signature)

with open("Signature", "rb") as f:
    signature = f.read()

print(rsa.verify(message.encode(), signature, public_key))



