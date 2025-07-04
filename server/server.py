# DEPENDENCIES:
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socket
import random
import hashlib
import re

#####################################################################################################
# GLOBAL PARAMS
# Diffie-Hellman params
p = 23
g = 5
# Keys
k_ssl=0
k=0
k_rand=0

RS=2**40
salt_int=0

#####################################################################################################
# Key exchange with client
def handle_key_exchange(server_socket):
    global k_ssl, k, k_rand, salt_int

    conn, addr = server_socket.accept()
    print("[Server] DH connection from", addr)

    client_public = int(conn.recv(1024).decode())
    server_private = random.randint(1, p - 2)
    server_public = pow(g, server_private, p)
    conn.send(str(server_public).encode())
    salt_bytes =conn.recv(1024)
    salt_int = int.from_bytes(salt_bytes, 'big')

    print("[Server] salt recieved:",salt_int)
    shared_secret = pow(client_public, server_private, p)
    print("[Server] Shared secret with client:", shared_secret)

    key = hashlib.sha512(str(shared_secret).encode()).digest() 
    k_ssl=key[:32]
    k=key[32:48]
    k_rand=key[48:64]
    conn.close()
    
#####################################################################################################
def handle_middlebox_messages(server_socket):
    print("[Server] Ready to receive from middlebox...")
    while True:
        try:
            conn, addr = server_socket.accept()
            print("[Server] Message from", addr)
            encrypted_msg,token_stream,tokenisation_type,token_length= receive_payload(conn)
            dec_data=decrypt_message(k_ssl,encrypted_msg)
            encrypted_tokens=parse_token_data(token_stream)

            salts=[]
            server_tokens=[]
            server_pre_enc_tokens=[]
            server_enc_tokens=[]

            if tokenisation_type==1: # For checking if tokens are correctly created in client side
                server_tokens,salts=window_tokenisation(dec_data.decode(),token_length)
            else:
                server_tokens,salts=delimiter_tokenisation(dec_data.decode())
            
            cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=default_backend())
            for token in server_tokens:
                padder = padding.PKCS7(128).padder() 
                padded = padder.update(token) + padder.finalize()
                encryptor = cipher.encryptor()
                ct = encryptor.update(padded) + encryptor.finalize()
                server_pre_enc_tokens.append(ct)
            
            idx=0
            for token in server_pre_enc_tokens:
                cipher = Cipher(algorithms.AES(token), modes.ECB(), backend=default_backend())
                padder = padding.PKCS7(128).padder() 
                salt_bytes = salts[idx].to_bytes(16, byteorder='big')
                padded = padder.update(salt_bytes) + padder.finalize()
                encryptor = cipher.encryptor()
                ct = encryptor.update(padded) + encryptor.finalize()
                ct_int=int.from_bytes(ct, byteorder='big')
                ct_int=ct_int%RS
                ct_bytes = ct_int.to_bytes(5, byteorder='big')
                server_enc_tokens.append(ct_bytes)

            print("[Server] Received:", dec_data.decode())
            if encrypted_tokens==server_enc_tokens:
                conn.send(dec_data) 
                conn.close()
            else:
                warning="Hacking attempt detected at [Server]"
                conn.send(warning.encode())
        except Exception as e:
            print("[Server] Error:", str(e))

#####################################################################################################
# TOKENISATION
# Window Tokenisation
def window_tokenisation(plaintext, window_size):
    tokens = []
    salts=[]
    counts={}
    message_bytes = plaintext.encode('utf-8')
    length = len(message_bytes)
    for i in range(length):
        token = bytes([message_bytes[(i + j) % length] for j in range(window_size)])
        tokens.append(token)
        counts[token]=counts.get(token,0)+1
        salts.append(salt_int+counts[token])
    return tokens,salts

# Partial Window Tokenisation
def window_tokenisation_partial(plaintext, window_size):
    tokens = []
    message_bytes = plaintext.encode('utf-8')
    length = len(message_bytes)
    for i in range(length-window_size+1):
        token = message_bytes[i:i+window_size]
        tokens.append(token)
    return tokens

# Delimiter Tokenisation
def delimiter_tokenisation(plaintext):
    delimiters = ['=', ';', ':', ',', ' ']
    salts=[]
    counts={}
    pattern = '|'.join(map(re.escape, delimiters))
    raw_tokens = re.split(pattern, plaintext)
    tokens=[]
    for token in raw_tokens:
        if not token:
            continue
        if len(token) > 8:
            # Replace long token with 8-byte windows
            broken_tokens = window_tokenisation_partial(token, 8)
            for t in broken_tokens:
                counts[t] = counts.get(t, 0) + 1
                tokens.append(t)
                salts.append(salt_int + counts[t])
        else:
            token_byte = token.encode()
            counts[token_byte] = counts.get(token_byte, 0) + 1
            tokens.append(token_byte)
            salts.append(salt_int + counts[token_byte])
    return tokens, salts

#####################################################################################################
# Decryption
def decrypt_message(k_ssl, encrypted_data):
    aesgcm = AESGCM(k_ssl)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

#####################################################################################################
# Decryption for tokens
def decrypt_tokens(encrypted_tokens, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decrypted_tokens = []
    for ct in encrypted_tokens:
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        token = unpadder.update(padded) + unpadder.finalize()
        decrypted_tokens.append(token)
    return decrypted_tokens

#####################################################################################################
def receive_full(conn, n):
    #Read exactly n bytes from the socket
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        data += chunk
    return data

def receive_payload(conn):
    token_length=0
    # Read length of enc_msg (4 bytes)
    enc_len_bytes = receive_full(conn, 4)
    enc_len = int.from_bytes(enc_len_bytes, 'big')
    # Read enc_msg
    enc_msg = receive_full(conn, enc_len)
    # Tokenisation type:
    tokenisation_type_bytes=receive_full(conn,1)
    tokenisation_type = int.from_bytes(tokenisation_type_bytes, 'big')
    if tokenisation_type==1:
        token_length_bytes=receive_full(conn,4)
        token_length = int.from_bytes(token_length_bytes, 'big')
    # Read length of token data (4 bytes)
    token_len_bytes = receive_full(conn, 4)
    token_len = int.from_bytes(token_len_bytes, 'big')
    # Read encrypted tokens
    token_data = receive_full(conn, token_len)
    return enc_msg, token_data,tokenisation_type,token_length 

#####################################################################################################
def parse_token_data(token_data):
    i = 0
    tokens = []
    while i < len(token_data):
        length = int.from_bytes(token_data[i:i+2], 'big')
        i += 2
        token = token_data[i:i+length]
        tokens.append(token)
        i += length
    return tokens

#####################################################################################################
def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 5002))
    s.listen(5)
    print("[Server] Server up...")

#####################################################################################################
    handle_key_exchange(s)
    handle_middlebox_messages(s)

#####################################################################################################

if __name__ == "__main__":
    main()