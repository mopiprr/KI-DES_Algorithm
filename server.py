import socket
from cryptography.hazmat.primitives import serialization

# Setup server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12346))
server_socket.listen(2)  # Listen for 2 clients

print("Server waiting for two clients to connect...")

# Accept connections and store public keys
public_keys = {}

client_a, addr_a = server_socket.accept()
print("Client A connected from:", addr_a)
client_a.sendall(b"A")

# Receive Client A's public key
public_key_a_pem = client_a.recv(4096)
public_keys["A"] = serialization.load_pem_public_key(public_key_a_pem)
with open("A_public_key.pem", "wb") as f:
    f.write(public_key_a_pem)

client_b, addr_b = server_socket.accept()
print("Client B connected from:", addr_b)
client_b.sendall(b"B")

# Receive Client B's public key
public_key_b_pem = client_b.recv(4096)
public_keys["B"] = serialization.load_pem_public_key(public_key_b_pem)
with open("B_public_key.pem", "wb") as f:
    f.write(public_key_b_pem)

while True:
    # Forward data between clients
    data = client_a.recv(4096).decode()
    if data == 'quit':
        print("Client A disconnected.")
        client_b.sendall(b'quit')
        break
    client_b.sendall(data.encode())

    data = client_b.recv(4096).decode()
    if data == 'quit':
        print("Client B disconnected.")
        client_a.sendall(b'quit')
        break
    client_a.sendall(data.encode())

client_a.close()
client_b.close()
server_socket.close()
