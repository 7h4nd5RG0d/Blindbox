import socket
import random
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def decrypt_message(k_ssl, encrypted_data):
    aesgcm = AESGCM(k_ssl)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


# Diffie-Hellman params
p = 23
g = 5

k_ssl=0
k_o=0
k_rand=0

def handle_key_exchange(server_socket):
    global k_ssl, k_o, k_rand
    conn, addr = server_socket.accept()
    print("[Server] DH connection from", addr)

    client_public = int(conn.recv(1024).decode())
    server_private = random.randint(1, p - 2)
    server_public = pow(g, server_private, p)
    conn.send(str(server_public).encode())

    shared_secret = pow(client_public, server_private, p)
    print("[Server] Shared secret with client:", shared_secret)
    key = hashlib.sha512(str(shared_secret).encode()).digest() 
    k_ssl=key[:32]
    k_o=key[32:48]
    k_rand=key[48:64]
    conn.close()
    

def handle_middlebox_messages(server_socket):
    print("[Server] Ready to receive from middlebox...")
    while True:
        try:
            conn, addr = server_socket.accept()
            print("[Server] Message from", addr)

            data = conn.recv(1024)
            if not data:
                print("[Server] Empty message, closing.")
                conn.close()
                continue
            dec_data=decrypt_message(k_ssl,data)
            print("[Server] Received:", dec_data.decode())
            conn.send(dec_data) 
            conn.close()

        except Exception as e:
            print("[Server] Error:", str(e))

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 5002))
    s.listen(5)
    print("[Server] Server listening on port 5002...")

    handle_key_exchange(s)
    handle_middlebox_messages(s)



if __name__ == "__main__":
    main()
