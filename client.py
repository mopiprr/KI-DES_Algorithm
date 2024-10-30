import socket
from encrypt import DESEncryptor
from main import text_to_bits, bits_to_text, pad_plaintext, unpad_plaintext, key_to_bits

# Initialize DES Encryptor
des_encryptor = DESEncryptor()

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Giving role, first connect is A, second connected is B
role = client_socket.recv(1024).decode()
print(f"You are Client {role}.")

if role == "A":
    # Client A: Send message to Client B
    message = input("Enter the message to send to Client B: ")
    client_socket.sendall(message.encode())

    # Receive randomly generated encryption key usede
    encryption_key = client_socket.recv(1024).decode()
    print("Encryption key received:", encryption_key)

    # Recive message from B
    encrypted_message = client_socket.recv(4096).decode()
    print("Encrypted message from Client B:", encrypted_message)

    # Input new key
    key_guess = input("Enter the key to decrypt Client B's message: ")
    client_socket.sendall(key_guess.encode())

    # Receive final decrypted message or disconnection 
    response = client_socket.recv(4096).decode()
    print(response)

elif role == "B":
    # Client B: Receive encrypted message from Client A
    encrypted_message = client_socket.recv(4096).decode()
    print("Encrypted message from Client A:", encrypted_message)

    key_guess = input("Enter the key to decrypt Client A's message: ")
    client_socket.sendall(key_guess.encode())

    response = client_socket.recv(4096).decode()
    print("Decrypted message:", response)

    # Send a response back to Client A
    message = input("Enter the message to send back to Client A: ")
    client_socket.sendall(message.encode())

    encryption_key = client_socket.recv(1024).decode()
    print("Encryption key for response:", encryption_key)

    final_response = client_socket.recv(4096).decode()
    print(final_response)

client_socket.close()
