from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def generate_aes() -> object:
    return AES.new(get_random_bytes(16), AES.MODE_CBC)


def encrypt_aes(aes_key: bytes, rsa_data: bytes) -> bytes:
    rsa_wrapper = RSA.importKey(rsa_data)
    cipher = PKCS1_OAEP.new(rsa_wrapper)
    return cipher.encrypt(aes_key)


def decrypt(data: bytearray, aes_key: bytes):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=bytes(16))
    return depad_pkcs7(cipher.decrypt(data))


def depad_pkcs7(data):
    padding_length = data[-1]
    if padding_length > len(data):
        raise ValueError("Invalid PKCS7 padding")

    for i in range(len(data) - padding_length, len(data)):
        if data[i] != padding_length:
            raise ValueError("Invalid PKCS7 padding")

    return data[:-padding_length]