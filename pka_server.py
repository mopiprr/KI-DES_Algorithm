import socket
import threading
import json
from RSA import RSA  

class PublicKeyAuthority:
    def __init__(self, host='localhost', port=12345):
        """Initialize the PKA server with host and port."""
        self.host = host
        self.port = port
        self.public_keys = {}  # Store public keys as {"client_id": public_key}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Maximum number of queued connections
        print(f"PKA Server started on {self.host}:{self.port}")

    def generate_rsa_keys(self, client_id):
        """Generate RSA keys using custom implementation and save them as .pem files."""
        rsa_instance = RSA(1024)
        public_key = rsa_instance.public_key()
        private_key = rsa_instance.private_key()

        # Save private key
        private_key_str = f"{private_key[0]},{private_key[1]}"
        with open(f"{client_id}_private_key.pem", "w") as private_file:
            private_file.write(private_key_str)

        # Save public key
        public_key_str = f"{public_key[0]},{public_key[1]}"
        with open(f"{client_id}_public_key.pem", "w") as public_file:
            public_file.write(public_key_str)

        print(f"Generated and saved RSA keys for Client {client_id}.")
        return public_key_str

    def handle_client(self, client_socket):
        """Handle incoming client requests."""
        try:
            request = client_socket.recv(1024).decode()
            request = json.loads(request)

            if request['action'] == 'register':
                # Generate and register RSA keys
                client_id = request['client_id']
                public_key_str = self.generate_rsa_keys(client_id)
                self.public_keys[client_id] = public_key_str
                client_socket.sendall(b"Public key registered successfully.")

            elif request['action'] == 'get_key':
                # Retrieve a public key for a specific client
                target_id = request['target_id']
                if target_id in self.public_keys:
                    response = {
                        'status': 'success',
                        'public_key': self.public_keys[target_id]
                    }
                else:
                    response = {
                        'status': 'error',
                        'message': 'Public key not found for the specified client.'
                    }
                client_socket.sendall(json.dumps(response).encode())

            else:
                # Invalid action
                response = {
                    'status': 'error',
                    'message': 'Invalid action specified.'
                }
                client_socket.sendall(json.dumps(response).encode())

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def start(self):
        """Start the PKA server."""
        print("PKA Server is running and waiting for connections...")
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection received from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

if __name__ == "__main__":
    # Create and start the PKA server
    pka_server = PublicKeyAuthority()
    pka_server.start()