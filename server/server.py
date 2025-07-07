# DEPENDENCIES:
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from collections import defaultdict 
import socket
import random
import hashlib
import re
import hmac
import os
import pickle
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
WIRE_LABEL_SIZE = 16  # 128-bit wire labels (AES block size)

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
# Parse Bristol circuit file
def parse_bristol_circuit(filepath):
    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    _, num_wires = map(int, lines[0].split()) # 1st line stores number of gates and number of wires
    inputs_info = list(map(int, lines[1].split()))

    if len(inputs_info) == 3:
        input1, input2, num_outputs = inputs_info # 2nd line stores the number of inputs of server, middlebox and number of outputs in bits
    else:
        raise ValueError("[Server] Unexpected header in Bristol file: expected 3 values on line 2.")

    gates = [] # Stores the gates
    input_counts = defaultdict(int)
    output_candidates = set()

    for line in lines[2:]:
        tokens = line.strip().split()
        n_in, n_out = int(tokens[0]), int(tokens[1])
        inputs = list(map(int, tokens[2:2 + n_in]))
        outputs = list(map(int, tokens[2 + n_in:2 + n_in + n_out]))
        gate_type = tokens[-1]
        # Track inputs count
        for i in inputs:
            input_counts[i] += 1
        # Mark outputs as candidates
        for o in outputs:
            output_candidates.add(o)
        gates.append({"type": gate_type, "in": inputs, "out": outputs})
    # Final outputs are candidates that never appeared as inputs
    real_outputs = [w for w in output_candidates if input_counts[w] == 0] # Stores the output wires..Since they wont be used as input wires....
    return {
        "num_wires": num_wires,
        "inputs_garbler": input1,
        "inputs_middlebox": input2,
        "num_outputs": num_outputs,
        "output_wires": real_outputs,
        "gates": gates
    }

# Generate a global delta for Free XOR
def generate_delta(seed: bytes, counter: int = 0) -> bytes:
    assert len(seed) >= 16, "[Server] Seed (k_rand) must be at least 128 bits"

    # Use HMAC to derive 128-bit pseudorandom value from k_rand and counter
    h = hmac.new(seed, f'delta-{counter}'.encode(), hashlib.sha256).digest()
    delta = bytearray(h[:WIRE_LABEL_SIZE])
    delta[-1] |= 1  
    return bytes(delta)

def prf(seed: bytes, label: str) -> bytes:
    return hmac.new(seed, label.encode(), hashlib.sha256).digest()[:16]  # 128-bit

# Generation of wire labels
def generate_wire_labels(num_wires, delta,k_rand):
    wire_labels = {}
    for i in range(num_wires):
        label_material = prf(k_rand, f'label-{i}')
        base_label = label_material[:16]
        sel_bit = label_material[0] & 1 # select bit
        label_0 = base_label if sel_bit == 0 else bytes(a ^ b for a, b in zip(base_label, delta)) # Label for 0 bit
        label_1 = bytes(a ^ b for a, b in zip(label_0, delta)) # Label for 1 bit
        wire_labels[i] = ((label_0, 0 if sel_bit == 0 else 1), (label_1, 1 if sel_bit == 0 else 0))
    return wire_labels

# Garbling of AND gate
def garble_and_gate(A, B, C, wire_labels):
    table = [None] * 4
    for a in (0, 1):
        for b in (0, 1):
            inA, selA = wire_labels[A][a]
            inB, selB = wire_labels[B][b]
            out_label, out_sel = wire_labels[C][a & b]
            index = (selA << 1) | selB
            h = hashlib.sha256(inA + inB).digest()[:WIRE_LABEL_SIZE]
            encrypted = bytes(x ^ y for x, y in zip(out_label, h))
            table[index] = (encrypted, out_sel)
    return {
        "type": "AND",
        "in": (A, B),
        "out": C,
        "table": table
    }

# Garble the circuit using Free XOR and basic AND gate garbling
def garble_circuit(circuit, wire_labels, delta):
    garbled_tables = []
    for gate in circuit["gates"]:
        gtype = gate["type"]
        in_wires = gate["in"]
        out_wires = gate["out"]

        if gtype == "XOR": # Simple free XOR
            A, B = in_wires
            C = out_wires[0]
            (a0, sa0), _ = wire_labels[A]
            (b0, sb0), _ = wire_labels[B]
            c0 = bytes(x ^ y for x, y in zip(a0, b0))
            c1 = bytes(x ^ y for x, y in zip(c0, delta))
            wire_labels[C] = ((c0, sa0 ^ sb0), (c1, 1 ^ (sa0 ^ sb0)))

        elif gtype == "INV":
            A = in_wires[0]
            (a0,sa0)=wire_labels[A][0]
            (a1,sa1)=wire_labels[A][1]
            C = out_wires[0]
            wire_labels[C] = ((a1,sa0), (a0,sa1))

        elif gtype == "AND": # Can be optimised using garbled gate reduction(GRR)
            A, B = in_wires
            C = out_wires[0]
            garbled_tables.append(garble_and_gate(A, B, C, wire_labels))

        else:
            raise NotImplementedError("[Client] ",f"Gate {gtype} not supported.")
    return garbled_tables

# Function for generating labels for inputs in garbler side
def encode_inputs(bits, wire_labels, offset):
    return [wire_labels[offset + i][bit] for i, bit in enumerate(bits)]

# Package to be sent ot middlebox
def prepare_evaluator_package(circuit, wire_labels, garbled_tables, k_bits):
    inputs_offset = circuit["inputs_garbler"]

    middlebox_input_indices = list(range(inputs_offset, inputs_offset + 128))
    output_indices = circuit["output_wires"]

    client_input_indices = list(range(0, inputs_offset))
    client_input_labels = encode_inputs(k_bits, wire_labels, 0)  # <- Garbled input: evaluator doesn't know the bit
    # Output wire indices
    output_map = {
        idx: {
            "0": wire_labels[idx][0],
            "1": wire_labels[idx][1]
        } for idx in output_indices
    }
    return {
        "garbled_tables": garbled_tables,
        "middlebox_input_wires": middlebox_input_indices,
        "output_map": output_map,
        "client_inputs": client_input_labels,
        "client_input_wires": client_input_indices,
        "output_wires": output_indices,
        "gates": circuit["gates"],
    }

def send_garbled_output(s,evaluator_package, wire_labels, offset):
    serialized = pickle.dumps(evaluator_package)
    length = len(serialized).to_bytes(4, 'big')

    conn, addr = s.accept()
    print("[Server] Garbling connection from", addr)
   
    conn.sendall(length + serialized)

    try:
        # Receive number of blocks (4 bytes)
        num_blocks_bytes = conn.recv(4)
        if len(num_blocks_bytes) < 4:
            raise RuntimeError("[Server] Failed to receive number of plaintext blocks")
        num_blocks = int.from_bytes(num_blocks_bytes, 'big')

        # Receive all plaintext blocks
        total_plaintext_len = num_blocks * 16
        received = b''
        while len(received) < total_plaintext_len:
            chunk = conn.recv(total_plaintext_len - len(received))
            if not chunk:
                raise RuntimeError("[Server] Connection closed while receiving plaintext blocks")
            received += chunk

        # Prepare and send all labels
        payload = b''
        for i in range(num_blocks):
            block = received[i*16:(i+1)*16]
            bits = []
            for byte in block:
                bits.extend([(byte >> j) & 1 for j in reversed(range(8))])
            assert len(bits) == 128

            for j, bit in enumerate(bits):
                label, sel_bit = wire_labels[offset + j][bit]
                payload += label + bytes([sel_bit])  # 17 bytes per input bit

        assert len(payload) == num_blocks * 128 * 17
        conn.sendall(payload)
    except Exception as e:
        print(f"[!] Error in send_garbled_output: {e}")
    finally:
        conn.close()
        print("[Server] garbled tables and labels sent to middlebox")

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

#Mathematical functions##############################################################################
def bytes_to_bits(byte_data):
    return [int(bit) for byte in byte_data for bit in f'{byte:08b}'] 

#####################################################################################################
def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 5002))
    s.listen(5)
    print("[Server] Server up...")

#####################################################################################################
    handle_key_exchange(s)

#####################################################################################################
    circuit_path = "aes_128.bristol" 
    circuit = parse_bristol_circuit(circuit_path)
    print("[Server] AES circuit ready..!")

#####################################################################################################

    k_bits = bytes_to_bits(k) 
    delta = generate_delta(k_rand)   # will be generate based on k_rand
    wire_labels = generate_wire_labels(circuit["num_wires"], delta, k_rand)
    garbled_tables = garble_circuit(circuit, wire_labels, delta)
    evaluator_package = prepare_evaluator_package(circuit, wire_labels, garbled_tables,k_bits)

    # Need to use OT
    send_garbled_output(s,evaluator_package,wire_labels,circuit['inputs_garbler'])

#####################################################################################################
    handle_middlebox_messages(s)

#####################################################################################################

if __name__ == "__main__":
    main()