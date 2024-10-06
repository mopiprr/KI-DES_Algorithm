# main.py

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

def pad_plaintext(plaintext):
    padding_len = 8 - (len(plaintext) % 8)
    padding = chr(padding_len) * padding_len
    return plaintext + padding

def unpad_plaintext(padded_text):
    padding_len = ord(padded_text[-1])
    return padded_text[:-padding_len]

def split_into_blocks(data, block_size=8):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

if __name__ == "__main__":
    des = DESEncryptor()

    # Ask the user whether they want to encrypt or decrypt
    choice = input("Would you like to (e)ncrypt or (d)ecrypt?: ").lower()

    # For encryption
    if choice == 'e':
        plaintext = input("Enter the plaintext to encrypt: ")

        # Apply padding to plaintext
        padded_plaintext = pad_plaintext(plaintext)

        # Generate a random 64-bit key
        random_key = generate_random_key()
        print("Generated Key (Hex):", random_key.hex())

        # Convert padded plaintext and key to bits
        plaintext_blocks = split_into_blocks(padded_plaintext, 8)  # Split into 8-byte blocks
        key_bits = key_to_bits(random_key)

        # Encrypt each block
        ciphertext_bits = []
        for block in plaintext_blocks:
            block_bits = text_to_bits(block)
            ciphertext_bits.extend(des.des_encrypt(block_bits, key_bits))

        print("Ciphertext (Binary):", ''.join(map(str, ciphertext_bits)))

    # For decryption
    elif choice == 'd':
        ciphertext_input = input("Enter the ciphertext (binary string) to decrypt: ")
        key_input = input("Enter the key used for encryption (hexadecimal format): ")

        # Convert ciphertext and key to bits
        ciphertext_bits = [int(bit) for bit in ciphertext_input]
        key_bits = key_to_bits(bytes.fromhex(key_input))

        # Decrypt in 64-bit (8-byte) blocks
        decrypted_text = ""
        ciphertext_blocks = split_into_blocks(ciphertext_bits, 64)  # Split into 64-bit blocks
        for block_bits in ciphertext_blocks:
            decrypted_bits = des.des_decrypt(block_bits, key_bits)
            decrypted_text += bits_to_text(decrypted_bits)

        # Remove padding from decrypted text
        unpadded_text = unpad_plaintext(decrypted_text)
        print("Decrypted Text:", unpadded_text)

    else:
        print("Invalid choice! Please choose either 'e' for encryption or 'd' for decryption.")
