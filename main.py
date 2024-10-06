# main.py

import random
import secrets
from encrypt import DESEncryptor

def text_to_bits(text):
    return [int(bit) for bit in ''.join(format(ord(c), '08b') for c in text)]

def bits_to_text(bits):
    return ''.join(chr(int(''.join(str(bit) for bit in bits[i:i+8]), 2)) for i in range(0, len(bits), 8))

def generate_random_key():
    # Generate a random 64-bit key (8 bytes)
    return secrets.token_bytes(8)

def key_to_bits(key):
    # Convert the random key (bytes) into a bit array
    return [int(bit) for byte in key for bit in format(byte, '08b')]

if __name__ == "__main__":
    plaintext = "HelloWorld"
    
    # Generate a random 64-bit key
    random_key = generate_random_key()
    print("Generated Key (Hex):", random_key.hex())
    
    # Convert plaintext and key to bits
    plaintext_bits = text_to_bits(plaintext)
    key_bits = key_to_bits(random_key)

    # Ensure both are 64 bits (padding if necessary)
    plaintext_bits = plaintext_bits[:64] + [0] * (64 - len(plaintext_bits[:64]))
    key_bits = key_bits[:64] + [0] * (64 - len(key_bits[:64]))

    des = DESEncryptor()

    # Encrypt
    ciphertext_bits = des.des_encrypt(plaintext_bits, key_bits)
    print("Ciphertext:", ''.join(map(str, ciphertext_bits)))

    # Decrypt
    decrypted_bits = des.des_decrypt(ciphertext_bits, key_bits)
    decrypted_text = bits_to_text(decrypted_bits)
    print("Decrypted Text:", decrypted_text)
