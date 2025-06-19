from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socket
import random

class Node:
    def __init__(self,key,ctr):
        self.key=key
        self.ctr=ctr
        self.left=None
        self.right=None
        self.height=1

# Ruleset
ruleset = ['hack', 'malware', 'attack', 'exploit']
min_length = min(len(word) for word in ruleset)
window_length=min(min_length,8)
RS=2**40
salt_0=0

def rebalance(node):
    balance=get_balance(node)

    if balance>1:
        if get_balance(node.left)>=0:
            return right_rotate(node)
        else:
            node.left=left_rotate(node.left)
            return right_rotate(node)
    
    if balance <-1:
        if get_balance(node.right)<=0:
            return left_rotate(node)
        else:
            node.right=right_rotate(node.right)
            return left_rotate(node)
        
    return node


def get_height(node):
    return node.height if node else 0

def get_balance(node):
    return get_height(node.left) - get_height(node.right) if node else 0

def right_rotate(z):
    y = z.left
    T3 = y.right

    # Perform rotation
    y.right = z
    z.left = T3

    # Update heights
    z.height = 1 + max(get_height(z.left), get_height(z.right))
    y.height = 1 + max(get_height(y.left), get_height(y.right))

    return y

def left_rotate(z):
    y = z.right
    T2 = y.left

    # Perform rotation
    y.left = z
    z.right = T2

    # Update heights
    z.height = 1 + max(get_height(z.left), get_height(z.right))
    y.height = 1 + max(get_height(y.left), get_height(y.right))

    return y

def get_min_value(node):
    current=node
    while current.left:
        current=current.left
    return current

def AVL_creation(root,encrypted_rules):
    for enc_rule in encrypted_rules:
        enc_rule_int=int.from_bytes(enc_rule, 'big')
        root=AVL_insertion(root,enc_rule_int,1)
    return root
    
def AVL_search(root,token,enc_rule): # First search, then deletion, then insertion
        current=root
        found=False

        while current:
            if token==current.key:
                found=True
                break
            elif token<current.key:
                current=current.left
            else:
                current=current.right

        if found:
            root,ctr=AVL_deletion(root,token)
            cipher = Cipher(algorithms.AES(enc_rule), modes.ECB(), backend=default_backend())
            padder = padding.PKCS7(128).padder() 
            salt_final = (salt_0 + ctr + 1).to_bytes(16, byteorder='big')
            padded = padder.update(salt_final) + padder.finalize()
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded) + encryptor.finalize()            
            root=AVL_insertion(root,ct,ctr+1)
        return None

def AVL_insertion(root,token,ctr):
    if not root:
        return Node(token,ctr)
    elif token<root.key:
        root.left=AVL_insertion(root.left,token,ctr)
    else:
        root.right=AVL_insertion(root.right,token,ctr)
    
    root.height=1+max(get_height(root.left),get_height(root.right))
    balance=get_balance(root)

    if balance>1 and token<root.left.key:
        return right_rotate(root)
    
    if balance < -1 and token>root.right.key:
        return left_rotate(root)

    if balance > 1 and token > root.left.key:
        root.left = left_rotate(root.left)
        return right_rotate(root)

    if balance < -1 and token < root.right.key:
        root.right = right_rotate(root.right)
        return left_rotate(root)

    return root

def AVL_deletion(root,token): 
    if not root:
        return root,None
    deleted_ctr=None
    if token<root.key:
        root.left, deleted_ctr=AVL_deletion(root.left,token)
    elif token>root.key:
        root.right, deleted_ctr=AVL_deletion(root.right,token)
    else:
        deleted_ctr=root.ctr
        if not root.left:
            return root.right,deleted_ctr
        elif not root.right:
            return root.left,deleted_ctr
        temp=get_min_value(root.right)
        root.key=temp.key
        root.ctr=temp.ctr
        root.right,_=AVL_deletion(root.right,temp.key)
    
    root.height=1+max(get_height(root.left),get_height(root.right))
    return rebalance(root),deleted_ctr

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

# Select tokenisation scheme
def handle_tokenisation(middlebox_socket):
    global salt_0
    conn, addr = middlebox_socket.accept()
    print("[Middlebox] Tokenisation connection from", addr)
    s=random.randint(1,2)
    if s==2:
        conn.send(str(s).encode())
    else:
        msg = f"{s},{window_length}"
        conn.send(msg.encode())
    
    print("[Middlebox] Tokenisation method:", s)
    salt_0_bytes=conn.recv(1024)
    salt_0 = int.from_bytes(salt_0_bytes, 'big')
    print("[Middlebox] Initial salt decided is",salt_0)
    conn.close()

def forward_to_server(message):
    try:
        with socket.socket() as to_server:
            to_server.connect(('server', 5002))
            to_server.send(message)
            return to_server.recv(1024)
    except Exception as e:
        return f"❌ Error: {e}".encode()

def main():
    # Setup middlebox
    mb = socket.socket()
    mb.bind(('0.0.0.0', 5001))
    mb.listen(5)
    print("[Middlebox] Middlebox up...")
    global window_length
    handle_tokenisation(mb) 

    while True:
        try:
            # Connection with client
            conn, addr = mb.accept()
            print(f"[Middlebox] Connection from {addr}")
            encrypted_msg,token_stream,tokenisation_type,token_length= receive_payload(conn)
            print("[Middlebox] Encrypted message:", encrypted_msg.hex())
            print("[Middlebox] Encrypted tokens:", token_stream.hex())
            parsed_tokens=parse_token_data(token_stream)
            
            encrypted_ruleset=[]
            root=AVL_creation(None,encrypted_ruleset)

            # Forward as-is to the server
            if tokenisation_type==1:
                if token_length==window_length:
                    payload=len(encrypted_msg).to_bytes(4, 'big')+encrypted_msg + tokenisation_type.to_bytes(1, 'big')+ token_length.to_bytes(4, 'big')+len(token_stream).to_bytes(4, 'big')+token_stream
                    server_response = forward_to_server(payload)
                    conn.send(server_response)
                else:
                    warning="Hacking attempt detected at [Middlebox]"
                    conn.send(warning.encode())
            else:
                payload=len(encrypted_msg).to_bytes(4, 'big')+encrypted_msg + tokenisation_type.to_bytes(1, 'big')+ len(token_stream).to_bytes(4, 'big')+token_stream
                server_response = forward_to_server(payload)
                conn.send(server_response)
        except Exception as e:
            print("[Middlebox] Error:", str(e))
        finally:
            conn.close()


if __name__ == "__main__":
    main()