from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socket
import pickle
import socket
import random
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import zmq
import time

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

def handle_evaluation(middlebox_socket):
    conn, addr = middlebox_socket.accept()
    print("[Middlebox] Evaluation connection from", addr)
    with conn:
        length_bytes = conn.recv(4)
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            data += chunk
        print("[Bob] Received evaluator package.")
    return pickle.loads(data)

WIRE_LABEL_SIZE=16
def evaluate_gate(gate, wire_values):
    if gate['type'] == 'AND':
        A, B = gate['in']
        a_label, a_sel = wire_values[A]
        b_label, b_sel = wire_values[B]

        index = (a_sel << 1) | b_sel
        encrypted, out_sel = gate['table'][index]

        h = hashlib.sha256(a_label + b_label).digest()[:WIRE_LABEL_SIZE]
        out_label = bytes(x ^ y for x, y in zip(encrypted, h))
        wire_values[gate['out'][0]] = (out_label, out_sel)

    elif gate['type'] == 'XOR':
        A, B = gate['in']
        C = gate['out'][0]
        a_label, a_sel = wire_values[A]
        b_label, b_sel = wire_values[B]
        label = bytes(x ^ y for x, y in zip(a_label, b_label))
        sel = a_sel ^ b_sel
        wire_values[C] = (label, sel)

    elif gate['type'] == 'INV':
        A = gate['in'][0]
        C = gate['out'][0]
        a_label, a_sel = wire_values[A]
        wire_values[C] = (a_label, a_sel^1)

    else:
        raise NotImplementedError(f"Unsupported gate type: {gate['type']}")
          
def evaluate_circuit(package):
    wire_values = {}

    bob_wires = package['middlebox_inputs']
    bob_indices = package['middlebox_input_wires']
    alice_wires = package['alice_inputs']
    alice_indices = package['alice_input_wires']
    for idx, (label, sel_bit) in zip(bob_indices, bob_wires):
        wire_values[idx] = (label, sel_bit)

    for idx, (label, sel_bit) in zip(alice_indices, alice_wires):
        wire_values[idx] = (label, sel_bit)
    
    and_index = 0
    for gate in package['gates']:
        
        if gate['type'] == 'AND':
            gate['table'] = package['garbled_tables'][and_index]['table']
            and_index += 1

    for gate in package['gates']:
        evaluate_gate(gate, wire_values)

    return wire_values

def decode_outputs(wire_values, output_map):
    results = []
    for idx, mapping in output_map.items():
        if idx not in wire_values:
            results.append(None)
            continue
        
        value = wire_values[idx]  # value = (label, sel_bit)
        
        if value == mapping['0']:
            results.append(0)
        elif value == mapping['1']:
            results.append(1)
        else:
            results.append(None)
    return results

def forward_to_server(message):
    try:
        with socket.socket() as to_server:
            to_server.connect(('server', 5002))
            to_server.send(message)
            return to_server.recv(1024)
    except Exception as e:
        return f"❌ Error: {e}".encode()

def bits_to_bytes(bits):
    # Pad bits to a multiple of 8
    if len(bits) % 8 != 0:
        bits += [0] * (8 - len(bits) % 8)

    byte_arr = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        byte_arr.append(byte)
    return bytes(byte_arr)

def main():
    # Setup middlebox
    mb = socket.socket()
    mb.bind(('0.0.0.0', 5001))
    mb.listen(5)
    print("[Middlebox] Middlebox up...")
    global window_length
    handle_tokenisation(mb) 

    package=handle_evaluation(mb)
    wire_values = evaluate_circuit(package)
    print("PART 2a:",wire_values[16316])
    print("PART 2b:",wire_values[36492])
    print("PART 2a:",wire_values[16317])
    print("PART 2b:",wire_values[36493])
        # Sorted check
    wire_items = sorted(wire_values.items(), key=lambda x: x[0])

    first_mismatch = None
    mismatch_count = 0

    for idx, (label, _) in wire_items:
        if idx in package['wire_labels']:
            label0 = package['wire_labels'][idx][0][0]
            label1 = package['wire_labels'][idx][1][0]
            if label != label0 and label != label1:
                if first_mismatch is None:
                    first_mismatch = idx
                mismatch_count += 1

    print("First Mismatched Label Index:", first_mismatch)
    print("Total Mismatched Labels:", mismatch_count)
    print("Total Wires:", len(wire_values))
    print("INPUT CHECK",decode_outputs(wire_values, package['bob_map']))
    print("INPUT KEY CHECK",decode_outputs(wire_values, package['key_map']))
    output_bits = decode_outputs(wire_values, package['output_map'])
    print("[Bob] Output bits:", output_bits)
    output_bytes = bits_to_bytes(output_bits)
    print("[Bob] Output (hex):", output_bytes.hex())

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