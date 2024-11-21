import socket
import secrets
from encrypt import DESEncryptor
from main import text_to_bits, bits_to_text, pad_plaintext, unpad_plaintext, key_to_bits
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# RSA Functions
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key, prefix):
    with open(f"{prefix}_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"password")
        ))
    with open(f"{prefix}_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_key(filename, is_private=False):
    with open(filename, "rb") as key_file:
        if is_private:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=b"password"
            )
        else:
            return serialization.load_pem_public_key(
                key_file.read()
            )

# Initialize DES Encryptor
des_encryptor = DESEncryptor()

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12346))

role = client_socket.recv(1024).decode()
print(f"You are Client {role}.")

# Generate RSA keys or load from file
private_key, public_key = generate_rsa_keys()
save_keys(private_key, public_key, role)

# Send public key to server
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client_socket.sendall(public_pem)

if role == 'A':
    other_client = 'B'
else:
    other_client = 'A'

while True:
    if role == "A":
        # Sender: Send a message first
        message = input("Enter the message to send to Client B (or 'quit' to exit): ")
        if message.lower() == 'quit':
            client_socket.sendall(b'quit')
            print("Connection closed.")
            break

        # Encrypt the message and generate a random DES key using `secrets`
        des_key = secrets.token_bytes(8)  # 64-bit DES key
        print(f"Generated DES key (hex): {des_key.hex()}")  # Display for debugging

        key_bits = key_to_bits(des_key)
        padded_message = pad_plaintext(message)
        message_bits = text_to_bits(padded_message)

        encrypted_bits = []
        for i in range(0, len(message_bits), 64):
            block = message_bits[i:i+64]
            encrypted_bits.extend(des_encryptor.des_encrypt(block, key_bits))

        encrypted_message = ''.join(map(str, encrypted_bits))

        # Encrypt DES key with Client B's public key
        public_key_b = load_key("B_public_key.pem", is_private=False)
        encrypted_key = public_key_b.encrypt(
            des_key.hex().encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send encrypted message and encrypted DES key
        data_to_send = encrypted_message + '|' + encrypted_key.hex()
        client_socket.sendall(data_to_send.encode())

        # Wait to receive a message
        response = client_socket.recv(4096).decode()
        if response == 'quit':
            print("Client B has disconnected.")
            break

        # Process received message
        encrypted_message_part, encrypted_key_hex = response.split('|')
        print("Encrypted message from Client B:", encrypted_message_part)

        # Input private key to decrypt DES key
        private_key_password = input("Enter your private key password to decrypt the DES key: ")
        des_key_hex = private_key.decrypt(
            bytes.fromhex(encrypted_key_hex),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        print(f"DES Key (hex): {des_key_hex}")

        # Decrypt the message using the DES key
        encrypted_bits_b = [int(bit) for bit in encrypted_message_part]
        key_bits_b = key_to_bits(bytes.fromhex(des_key_hex))

        decrypted_bits_b = []
        for i in range(0, len(encrypted_bits_b), 64):
            block = encrypted_bits_b[i:i+64]
            decrypted_bits_b.extend(des_encryptor.des_decrypt(block, key_bits_b))

        decrypted_message_b = bits_to_text(decrypted_bits_b)
        unpadded_message_b = unpad_plaintext(decrypted_message_b)
        print("Decrypted message from Client B:", unpadded_message_b)

    elif role == "B":
        # Receiver: Receive first
        response = client_socket.recv(4096).decode()
        if response == 'quit':
            print("Client A has disconnected.")
            break

        # Process received message
        encrypted_message_part, encrypted_key_hex = response.split('|')
        print("Encrypted message from Client A:", encrypted_message_part)

        # Input private key to decrypt DES key
        private_key_password = input("Enter your private key password to decrypt the DES key: ")
        des_key_hex = private_key.decrypt(
            bytes.fromhex(encrypted_key_hex),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        print(f"DES Key (hex): {des_key_hex}")

        # Decrypt the message using the DES key
        encrypted_bits_a = [int(bit) for bit in encrypted_message_part]
        key_bits_a = key_to_bits(bytes.fromhex(des_key_hex))

        decrypted_bits_a = []
        for i in range(0, len(encrypted_bits_a), 64):
            block = encrypted_bits_a[i:i+64]
            decrypted_bits_a.extend(des_encryptor.des_decrypt(block, key_bits_a))

        decrypted_message_a = bits_to_text(decrypted_bits_a)
        unpadded_message_a = unpad_plaintext(decrypted_message_a)
        print("Decrypted message from Client A:", unpadded_message_a)

        # Respond to Client A
        message = input("Enter the message to send to Client A (or 'quit' to exit): ")
        if message.lower() == 'quit':
            client_socket.sendall(b'quit')
            print("Connection closed.")
            break

        # Encrypt the message and generate a random DES key
        des_key = secrets.token_bytes(8)  # 64-bit DES key
        print(f"Generated DES key (hex): {des_key.hex()}")  # Display for debugging

        key_bits = key_to_bits(des_key)
        padded_message = pad_plaintext(message)
        message_bits = text_to_bits(padded_message)

        encrypted_bits = []
        for i in range(0, len(message_bits), 64):
            block = message_bits[i:i+64]
            encrypted_bits.extend(des_encryptor.des_encrypt(block, key_bits))

        encrypted_message = ''.join(map(str, encrypted_bits))

        # Encrypt DES key with Client A's public key
        public_key_a = load_key("A_public_key.pem", is_private=False)
        encrypted_key = public_key_a.encrypt(
            des_key.hex().encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send encrypted message and encrypted DES key
        data_to_send = encrypted_message + '|' + encrypted_key.hex()
        client_socket.sendall(data_to_send.encode())

client_socket.close()
