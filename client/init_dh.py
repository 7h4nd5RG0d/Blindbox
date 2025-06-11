import socket
import random
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Diffie-Hellman parameters
p = 23
g = 5

# --- Phase 1: Key exchange with server ---
client_private = random.randint(1, p - 2)
client_public = pow(g, client_private, p)

s = socket.socket()
s.connect(('server', 5002))  # Connect to server for DH key exchange
s.send(str(client_public).encode())
server_public = int(s.recv(1024).decode())
shared_secret = pow(server_public, client_private, p)
print("[Client] Shared secret with server:", shared_secret)
key = hashlib.sha512(str(shared_secret).encode()).digest() 

s.close()

with open("key.bin", "wb") as f:
    f.write(key)