import base64

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15

message = "signature message"
secret_code = "secret code"

public_key = 'rsa_public_key.bin'
private_key = 'rsa_private_key.bin'


def generate_private_key():
    key = RSA.generate(2018)
    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8, protection='scryptAndAES128-CBC')
    file_out = open(private_key, "wb")
    file_out.write(encrypted_key)
    file_out.close()
    print(key.publickey().exportKey())


def generate_public_key():
    encoded_key = open(private_key, "rb").read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)
    file_out = open(public_key, "wb")
    file_out.write(key.publickey().exportKey())
    file_out.close()
    print(key.publickey().exportKey())


def sign_message():
    key = RSA.import_key(open(private_key, "rb").read(), passphrase=secret_code)
    hash_message = SHA256.new(str.encode(message))
    signature = pkcs1_15.new(key).sign(hash_message)
    print(signature)
    file_out = open("signature.txt", "w")
    signature_str = base64.b64encode(signature)
    print(signature_str)
    signature_byte = bytes.decode(signature_str)
    file_out.write(signature_byte)
    file_out.close()


def verify_signature():
    key = RSA.import_key(open(public_key, "rb").read())
    hash_message = SHA256.new(str.encode(message))
    try:
        signature_str = open("signature.txt", "r").read()
        signature_byte = str.encode(signature_str)
        signature = base64.b64decode(signature_byte)
        pkcs1_15.new(key).verify(hash_message, signature)
        print(True)
    except (ValueError, TypeError) as e:
        print(e)
        print(False)


if __name__ == "__main__":
    generate_private_key()
    generate_public_key()
    sign_message()
    verify_signature()

# https://www.pycryptodome.org/en/latest/index.html
# pip install pycryptodomex==3.4.7
# python 3.5.x 3.6.x
