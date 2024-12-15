import socket
import json
from RSA import RSA 

PKA_HOST = 'localhost'
PKA_PORT = 12345

def register_public_key(client_id, public_key):
    """Registers this client's public key with the PKA server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as pka_socket:
        pka_socket.connect((PKA_HOST, PKA_PORT))
        request = {
            'action': 'register',
            'client_id': client_id,
            'public_key': public_key
        }
        pka_socket.sendall(json.dumps(request).encode())
        response = pka_socket.recv(1024).decode()
        print(f"PKA Server Response: {response}")

def get_public_key(target_id):
    """Fetches the public key of the target client from the PKA server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as pka_socket:
        pka_socket.connect((PKA_HOST, PKA_PORT))
        request = {
            'action': 'get_key',
            'target_id': target_id
        }
        pka_socket.sendall(json.dumps(request).encode())
        response = json.loads(pka_socket.recv(1024).decode())
        if response['status'] == 'success':
            return tuple(response['public_key'])  # Return as (n, e)
        else:
            print(f"Error: {response['message']}")
            return None

if __name__ == "__main__":
    # Generate RSA keys for this client
    rsa_instance = RSA(1024)
    client_id = input("Enter your client ID (e.g., A or B): ")
    print(f"Generated RSA keys for Client {client_id}")

    # Register the public key with the PKA server
    register_public_key(client_id, rsa_instance.public_key())

    # Fetch the public key of the other client
    target_id = "B" if client_id == "A" else "A"
    target_public_key = get_public_key(target_id)
    if target_public_key:
        print(f"Public key for Client {target_id}: {target_public_key}")
