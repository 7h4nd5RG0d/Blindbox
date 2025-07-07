# DEPENDENCIES:
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import pickle
import socket
import random
import hashlib
import os
import re
import sys

#####################################################################################################
# GLOBAL PARAMS:
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# Ruleset
ruleset = ['hack', 'malware', 'attack', 'exploit']
min_length = min(len(word) for word in ruleset)
window_length=min(min_length,8) # Window length for tokenisation
RS=2**40
salt_0=0 # Initial salt
WIRE_LABEL_SIZE=16

#####################################################################################################
# AVL Tree class and functions:
class Node:
    def __init__(self,key,ctr):
        self.key=key
        self.ctr=ctr
        self.left=None
        self.right=None
        self.height=1

# Rebalance after deletion and insertion
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

# Get height
def get_height(node):
    return node.height if node else 0

# Get balance
def get_balance(node):
    return get_height(node.left) - get_height(node.right) if node else 0

# Rotate the tree to right
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

# Rotate to left
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

# Get the min value in the AVL
def get_min_value(node):
    current=node
    while current.left:
        current=current.left
    return current

# Creating the AVL
def AVL_creation(root,encrypted_rules):
    for enc_rule in encrypted_rules:
        enc_rule_int=int.from_bytes(enc_rule, 'big')
        root=AVL_insertion(root,enc_rule_int,1)
    return root

# Search in the AVL tree
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

# Insertion
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

# Deletion
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

#####################################################################################################
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
    return s

#####################################################################################################
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
        salts.append(salt_0+counts[token])
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
                salts.append(salt_0 + counts[t])
        else:
            token_byte = token.encode()
            counts[token_byte] = counts.get(token_byte, 0) + 1
            tokens.append(token_byte)
            salts.append(salt_0 + counts[token_byte])
    return tokens, salts

#####################################################################################################
# SAMPLE:
# Handle the sample evaluation from client
def sample_handle_evaluation(middlebox_socket):
    conn, addr = middlebox_socket.accept()
    print("[Middlebox] Sample Evaluation connection from", addr)
    with conn:
        length_bytes = conn.recv(4)
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("[Middlebox] Connection closed unexpectedly")
            data += chunk
        print("[Middlebox] Received evaluator package.")
        conn.close()
    return pickle.loads(data)

#####################################################################################################
# Sample evaluation:
def sample_evaluate_circuit(package):
    wire_values = {}

    middlebox_wires = package['middlebox_inputs']
    middlebox_indices = package['middlebox_input_wires']

    client_wires = package['client_inputs']
    client_indices = package['client_input_wires']

    for idx, (label, sel_bit) in zip(middlebox_indices, middlebox_wires): # Stores the middlebox wire labels
        wire_values[idx] = (label, sel_bit)

    for idx, (label, sel_bit) in zip(client_indices, client_wires): # Stores the client wire labels
        wire_values[idx] = (label, sel_bit)
    
    and_index = 0 # Evaluation for only gates using the encrypted tables
    for gate in package['gates']: 
        if gate['type'] == 'AND':
            gate['table'] = package['garbled_tables'][and_index]['table']
            and_index += 1

    for gate in package['gates']:
        evaluate_gate(gate, wire_values)

    return wire_values

#####################################################################################################
# prepare the ruleset, where each rule is of 128 bits..
def prepare(ruleset,tokenisation_type,window_length):
    prepared_rules=[]
    for rule in ruleset:
        if tokenisation_type==1:
            broken_rules,_=window_tokenisation(rule,window_length)
        else:
            broken_rules,_=delimiter_tokenisation(rule)

        for rules in broken_rules:
            padder = padding.PKCS7(128).padder() 
            padded = padder.update(rules) + padder.finalize()

            for i in range(0,len(padded),16):
                prepared_rules.append((padded[i:i+16]))

    print("[Middlebox] Ruleset prepared for OT")
    return prepared_rules

#####################################################################################################
# Evaluation of Yao garbled circuit:
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

#####################################################################################################
# Decoding outputs labels using output map:
def decode_outputs(wire_values, output_map):
    results = []
    for idx, mapping in output_map.items():
        if idx not in wire_values:
            results.append(None)
            continue
        
        value = wire_values[idx]  
        
        if value == mapping['0']:
            results.append(0)
        elif value == mapping['1']:
            results.append(1)
        else:
            results.append(None)
    return results

#####################################################################################################
# Evaluate the circuit
def evaluate_circuit(package,labels):
    
    middlebox_indices = package['middlebox_input_wires']
    client_wires = package['client_inputs']
    client_indices = package['client_input_wires']

    and_index = 0
    for gate in package['gates']:
        if gate['type'] == 'AND':
            gate['table'] = package['garbled_tables'][and_index]['table']
            and_index += 1

    final_wires_list=[]
    for i in range(0,len(labels)):
        pre_label=labels[i]
        wire_values = {}
        for idx, (label,sel_bit) in zip(middlebox_indices, pre_label):
            wire_values[idx] = (label, sel_bit)

        for idx, (label, sel_bit) in zip(client_indices, client_wires):
            wire_values[idx] = (label, sel_bit)

        for gate in package['gates']:
            evaluate_gate(gate, wire_values)
        
        final_wires_list.append(wire_values)

    return final_wires_list

#####################################################################################################
# Recieve the labels corresponding to the plaintext ruleset for yao garbled circuits 
def receive_labels_client(plaintext_rules, s):
    conn, addr = s.accept()
    print(f"[Middlebox] Evaluation Connected to {addr}")

    try:
        # Step 1: Receive evaluator package
        length_bytes = conn.recv(4)
        if len(length_bytes) < 4:
            raise RuntimeError("[Middlebox] Did not receive full length prefix")

        length = int.from_bytes(length_bytes, 'big')        
        received = b''
        while len(received) < length:
            chunk = conn.recv(min(4096, length - len(received)))
            if not chunk:
                raise RuntimeError("[Middlebox] Connection closed while receiving circuit")
            received += chunk

        evaluator_package = pickle.loads(received)
        print("[Middlebox] Received evaluator package.")

        num_blocks = len(plaintext_rules)
        conn.sendall(num_blocks.to_bytes(4, 'big'))

        for block in plaintext_rules:
            assert len(block) == 16
            conn.sendall(block)

        expected_total = num_blocks * 128 * 17
        labels_raw = b''
        while len(labels_raw) < expected_total:
            chunk = conn.recv(expected_total - len(labels_raw))
            if not chunk:
                raise RuntimeError("[Middlebox] Connection closed while receiving labels")
            labels_raw += chunk

        if len(labels_raw) != expected_total:
            raise RuntimeError("[Middlebox] Did not receive full label+selbit data")

        all_input_labels = []
        for i in range(num_blocks):
            block_raw = labels_raw[i*128*17 : (i+1)*128*17]
            input_labels = [
                (block_raw[j:j+16], block_raw[j+16])
                for j in range(0, 128*17, 17)
            ]
            all_input_labels.append(input_labels)

        return evaluator_package, all_input_labels

    except Exception as e:
        print("[Middlebox] ",f"[!] Error: {e}")
        return None, []
    finally:
        conn.close()

# Recieve the labels corresponding to the plaintext ruleset for yao garbled circuits  from server
def receive_labels_server(plaintext_rules):
    try:
        # Step 1: Connect to the server
        with socket.socket() as conn:
            conn.connect(('server', 5002))
            print("[Middlebox] Connected to Server for Garbling and Eval.")

            # Step 2: Receive evaluator package
            length_bytes = conn.recv(4)
            if len(length_bytes) < 4:
                raise RuntimeError("[Middlebox] Did not receive full length prefix")

            length = int.from_bytes(length_bytes, 'big')        
            received = b''
            while len(received) < length:
                chunk = conn.recv(min(4096, length - len(received)))
                if not chunk:
                    raise RuntimeError("[Middlebox] Connection closed while receiving circuit")
                received += chunk

            evaluator_package = pickle.loads(received)
            print("[Middlebox] Received evaluator package.")

            # Step 3: Send number of plaintext blocks
            num_blocks = len(plaintext_rules)
            conn.sendall(num_blocks.to_bytes(4, 'big'))

            # Step 4: Send all 16-byte plaintext blocks
            for block in plaintext_rules:
                assert len(block) == 16
                conn.sendall(block)

            # Step 5: Receive all labels in one go
            expected_total = num_blocks * 128 * 17
            labels_raw = b''
            while len(labels_raw) < expected_total:
                chunk = conn.recv(expected_total - len(labels_raw))
                if not chunk:
                    raise RuntimeError("[Middlebox] Connection closed while receiving labels")
                labels_raw += chunk

            if len(labels_raw) != expected_total:
                raise RuntimeError("[Middlebox] Did not receive full label+selbit data")

            # Step 6: Parse all labels
            all_input_labels = []
            for i in range(num_blocks):
                block_raw = labels_raw[i * 128 * 17 : (i + 1) * 128 * 17]
                input_labels = [
                    (block_raw[j:j + 16], block_raw[j + 16])
                    for j in range(0, 128 * 17, 17)
                ]
                all_input_labels.append(input_labels)

            return evaluator_package, all_input_labels

    except Exception as e:
        print("[Middlebox] ", f"[!] Error: {e}")
        return None, []

#####################################################################################################
# Parse the encrypted token data:
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
def receive_full(conn, n):
    #Read exactly n bytes from the socket
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("[Middlebox] Socket closed prematurely")
        data += chunk
    return data

# Recieve payload from client
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
# Connection with server
def forward_to_server(message):
    try:
        with socket.socket() as to_server:
            to_server.connect(('server', 5002))
            to_server.send(message)
            return to_server.recv(1024)
    except Exception as e:
        return f"❌ Error: {e}".encode()

# Mathemtical functions################################################################################
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

def bytes_to_bits(byte_data):
    return [int(bit) for byte in byte_data for bit in f'{byte:08b}'] 

#####################################################################################################
def main():
    # Setup middlebox
    mb = socket.socket()
    mb.bind(('0.0.0.0', 5001))
    mb.listen(15)
    print("[Middlebox] Middlebox up...")

#####################################################################################################   
    tokenisation_type=handle_tokenisation(mb) 

#####################################################################################################
# Sample part:
    sample_package=sample_handle_evaluation(mb)
    sample_wire_values = sample_evaluate_circuit(sample_package)
    sample_output_bits = decode_outputs(sample_wire_values, sample_package['output_map'])
    sample_output_bytes = bits_to_bytes(sample_output_bits)
    print("[Middlebox] Sample Output (hex):", sample_output_bytes.hex())

#####################################################################################################
    prepared_ruleset=prepare(ruleset,tokenisation_type,window_length)

#####################################################################################################
    print("[Middlebox] Evaluating the circuit ...")
    package_client,labels_client=receive_labels_client(prepared_ruleset,mb)
    package_server,labels_server=receive_labels_server(prepared_ruleset)

    if  (labels_server!=labels_client) : # Checks if garbled circuit/tables and labels are same.....
        warning="Hacking attempt detected at [Middlebox]"
        print("[Middlebox] Hacking attempt detected here...")
        conn, addr = mb.accept()
        conn.send(warning.encode())
        conn.close()
        mb.close()
        return
    print("[Middlebox] Garbled tables/circuit of client and sevrer match, moving forward...")
    wire_values = evaluate_circuit(package_client,labels_client)
    encrypted_ruleset=[]
    for i in range(0,len(wire_values)):
        output_bits = decode_outputs(wire_values[i], package_client['output_map'])
        encrypted_ruleset.append(bits_to_bytes(output_bits))
    print("[Middlebox] Encryption of ruleset done..!")
#####################################################################################################
# AVL Root for faster searching and updation
    root=AVL_creation(None,encrypted_ruleset)
    print("[Middlebox] AVL Tree created")
#####################################################################################################
    while True:
        try:
            conn = None  
            # Connection with client
            conn, addr = mb.accept()
            print(f"[Middlebox] Connection from {addr}")
            encrypted_msg,token_stream,tokenisation_type,token_length= receive_payload(conn)
            print("[Middlebox] Encrypted message:", encrypted_msg.hex())
            print("[Middlebox] Encrypted tokens:", token_stream.hex())

            parsed_tokens=parse_token_data(token_stream) # parse the token data
            # Forward as-is to the server
            if (tokenisation_type==1):
                if token_length==window_length:
                    payload=len(encrypted_msg).to_bytes(4, 'big')+encrypted_msg + tokenisation_type.to_bytes(1, 'big')+ token_length.to_bytes(4, 'big')+len(token_stream).to_bytes(4, 'big')+token_stream
                    server_response = forward_to_server(payload)
                    conn.send(server_response)
                else: # Check if tokenisation length is changed by client in order to avoid detection
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

#####################################################################################################
if __name__ == "__main__":
    main()

#####################################################################################################