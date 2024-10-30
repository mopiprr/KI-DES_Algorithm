import socket
from encrypt import DESEncryptor
from main import text_to_bits, pad_plaintext, unpad_plaintext, generate_random_key, key_to_bits
from main import bits_to_text

# Initialize DES Encryptor
des_encryptor = DESEncryptor()

# Setup server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(2)  # Listen for 2 clients

print("Server waiting for two clients to connect...")

# Accept connections from 2 client
client_a, addr_a = server_socket.accept()
print("Client A connected from:", addr_a)
client_a.sendall(b"A")  

client_b, addr_b = server_socket.accept()
print("Client B connected from:", addr_b)
client_b.sendall(b"B") 

# Communication loop between Client A and Client B
while True:
    # Receive message from Client A
    message_a = client_a.recv(4096).decode()
    if not message_a:
        print("Client A disconnected.")
        break

    # Encrypt the message and generate a random key for encryption
    padded_message_a = pad_plaintext(message_a)
    message_bits = text_to_bits(padded_message_a)
    random_key = generate_random_key()
    key_bits = key_to_bits(random_key)

    encrypted_bits = []
    for i in range(0, len(message_bits), 64):
        block = message_bits[i:i+64]
        encrypted_bits.extend(des_encryptor.des_encrypt(block, key_bits))

    # Return key toA
    client_a.sendall(random_key.hex().encode())

    # Send the encrypted message to Client B
    encrypted_message = ''.join(map(str, encrypted_bits))
    client_b.sendall(encrypted_message.encode())

    # Ask Client B for the key
    key_guess_hex = client_b.recv(1024).decode()
    if key_guess_hex != random_key.hex():
        print("Client B provided incorrect key. Disconnecting.")
        client_b.sendall(b"Incorrect key. Disconnecting.")
        client_b.close()
        client_a.close()
        break
    else:
        encrypted_bits = [int(bit) for bit in encrypted_message]
        decrypted_bits = []
        for i in range(0, len(encrypted_bits), 64):
            block = encrypted_bits[i:i+64]
            decrypted_bits.extend(des_encryptor.des_decrypt(block, key_bits))

        decrypted_message = bits_to_text(decrypted_bits)
        unpadded_message = unpad_plaintext(decrypted_message)
        print("Message from Client A to Client B:", unpadded_message)
        client_b.sendall(unpadded_message.encode()) 

    # Client B responds back to Client A following similar process
    message_b = client_b.recv(4096).decode()
    if not message_b:
        print("Client B disconnected.")
        break

    padded_message_b = pad_plaintext(message_b)
    message_bits_b = text_to_bits(padded_message_b)
    random_key_b = generate_random_key()
    key_bits_b = key_to_bits(random_key_b)

    encrypted_bits_b = []
    for i in range(0, len(message_bits_b), 64):
        block = message_bits_b[i:i+64]
        encrypted_bits_b.extend(des_encryptor.des_encrypt(block, key_bits_b))

    client_b.sendall(random_key_b.hex().encode())
    
    encrypted_message_b = ''.join(map(str, encrypted_bits_b))
    client_a.sendall(encrypted_message_b.encode())

    key_guess_hex_a = client_a.recv(1024).decode()
    if key_guess_hex_a != random_key_b.hex():
        print("Client A provided incorrect key. Disconnecting.")
        client_a.sendall(b"Incorrect key. Disconnecting.")
        client_a.close()
        client_b.close()
        break
    else:
        encrypted_bits_b = [int(bit) for bit in encrypted_message_b]
        decrypted_bits_b = []
        for i in range(0, len(encrypted_bits_b), 64):
            block = encrypted_bits_b[i:i+64]
            decrypted_bits_b.extend(des_encryptor.des_decrypt(block, key_bits_b))

        decrypted_message_b = bits_to_text(decrypted_bits_b)
        unpadded_message_b = unpad_plaintext(decrypted_message_b)
        print("Message from Client B to Client A:", unpadded_message_b)
        client_a.sendall(unpadded_message_b.encode()) 

client_a.close()
client_b.close()
server_socket.close()
