# DEPENDENCIES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import socket
import random
import hashlib
import os
import re

RS=2**40
salt=os.urandom(8)
salt_int = int.from_bytes(salt, byteorder='big')
# Diffie Helman Key Exchange
def perform_dh_key_exchange():
    # Diffie-Hellman parameters
    p = 23
    g = 5
    client_private = random.randint(1, p - 2) # private key
    client_public = pow(g, client_private, p) # public key

    # Initiate connection with server
    s = socket.socket()
    s.connect(('server', 5002))
    s.send(str(client_public).encode())
    server_public = int(s.recv(1024).decode()) # Server's public key
    s.send(salt) # Send the salt
    # Derive keys
    shared_secret = pow(server_public, client_private, p)  # Shared secret using DH
    print("[Client] Shared secret with server:", shared_secret)
    s.close()
    key = hashlib.sha512(str(shared_secret).encode()).digest()
    return key[:32], key[32:48], key[48:64]  # SSL, ENC, RAND

# Tokenisation
def tokenisation_selection():
    # Initiate connection with middlebox
    s = socket.socket()
    s.connect(('middlebox', 5001))
    option = s.recv(1024).decode()
    print("Salt:",salt_int)
    s.send(salt)
    s.close()
    if ',' in option:
        option_str, min_len_str = option.split(',')
        return int(option_str), int(min_len_str) # Window based with window-size
    else:
        return int(option), None # Delimiter based

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

# Encryption
def encrypt_message(k_ssl, plaintext):
    aesgcm = AESGCM(k_ssl)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext

def main():
    k_ssl, k, k_rand = perform_dh_key_exchange()
    option, min_length = tokenisation_selection()
    while True:
        msg = input("Enter message to send: ")
        if not msg:
            break
        tokens = []
        salts=[]
        if option == 1:
            print("Window-based tokenisation selected with window-size=",min_length)
            tokens,salts = window_tokenisation(msg,min_length)
        elif option == 2:
            print("Delimiter-based tokenisation selected")
            tokens,salts = delimiter_tokenisation(msg)

        print("Tokens:",tokens)
        pre_encrypted_tokens = []
        encrypted_tokens = []
        cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=default_backend())
        for token in tokens:
            padder = padding.PKCS7(128).padder() 
            padded = padder.update(token) + padder.finalize()
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded) + encryptor.finalize()
            pre_encrypted_tokens.append(ct)

        idx=0
        for token in pre_encrypted_tokens:
            cipher = Cipher(algorithms.AES(token), modes.ECB(), backend=default_backend())
            padder = padding.PKCS7(128).padder() 
            salt_bytes = salts[idx].to_bytes(16, byteorder='big')
            padded = padder.update(salt_bytes) + padder.finalize()
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded) + encryptor.finalize()
            ct_int=int.from_bytes(ct, byteorder='big')
            ct_int=ct_int%RS
            ct_bytes = ct_int.to_bytes(5, byteorder='big')
            encrypted_tokens.append(ct_bytes)
            idx=idx+1

        enc_msg = encrypt_message(k_ssl, msg)
        #Send to middlebox
        m = socket.socket()
        m.connect(('middlebox', 5001))

        token_data = b''.join(len(t).to_bytes(2, 'big') + t for t in encrypted_tokens)

        if option==1:
            payload= len(enc_msg).to_bytes(4, 'big')+enc_msg + option.to_bytes(1, 'big')+ (min_length).to_bytes(4, 'big')+len(token_data).to_bytes(4, 'big')+token_data
        else:
            payload= len(enc_msg).to_bytes(4, 'big')+enc_msg + option.to_bytes(1, 'big')+len(token_data).to_bytes(4, 'big')+token_data

        print('')
        print("PAYLOAD:",payload)
        m.sendall(payload)
        #Recieve from middlebox
        response = m.recv(1024)
        print("Received from middlebox:", response.decode())
        m.close()

if __name__ == "__main__":
    main()