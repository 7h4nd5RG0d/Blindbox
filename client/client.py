import socket
import random
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_message(k_ssl, plaintext):
    aesgcm = AESGCM(k_ssl)
    nonce = os.urandom(12)  # 96-bit nonce recommended
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext  # send nonce with ciphertext

with open("key.bin", "rb") as f:
    key = f.read()
k_ssl=key[:32]
k_o=key[32:48]
k_rand=key[48:64]

# --- Phase 2: Send encrypted messages to middlebox ---
while True:
    msg = input("Enter message to send: ")
    if not msg:
        break

    enc_msg=encrypt_message(k_ssl,msg)
    m = socket.socket()
    m.connect(('middlebox', 5001))  
    m.send(enc_msg)
    response = m.recv(1024)
    print("Received from middlebox:", response.decode())
    m.close()
