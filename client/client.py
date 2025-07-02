# DEPENDENCIES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import socket
import pickle
import socket
import random
import hashlib
import os
import re
import sys
import zmq
from collections import defaultdict 

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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

WIRE_LABEL_SIZE = 16  # 128-bit labels (AES block size)

# Parse Bristol circuit file

def parse_bristol_circuit(filepath):
    with open(filepath, 'r') as f:
        lines = f.read().strip().splitlines()

    num_gates, num_wires = map(int, lines[0].split())
    inputs_info = list(map(int, lines[1].split()))
    num_outputs_line = list(map(int, lines[2].split()))

    num_parties, num_inputs_1, num_inputs_2 = inputs_info
    num_output_blocks, output_block_size = num_outputs_line
    num_outputs = num_output_blocks * output_block_size

    gates = []
    input_counts = defaultdict(int)
    output_candidates = set()

    for line in lines[4:]:
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
    real_outputs = [w for w in output_candidates if input_counts[w] == 0]
    print(real_outputs)

    return {
        "num_gates": num_gates,
        "num_wires": num_wires,
        "inputs_garbler": num_inputs_1,
        "inputs_middlebox": num_inputs_2,
        "num_outputs": num_outputs,
        "output_wires": real_outputs,
        "gates": gates
    }

def bytes_to_bits(byte_data):
    return [int(bit) for byte in byte_data for bit in f'{byte:08b}']  # ✅ list of integers

# Generate a global delta for Free XOR
def generate_delta():
    delta = bytearray(os.urandom(WIRE_LABEL_SIZE))
    delta[-1] |= 1  # Ensure the last bit is 1 (non-zero LSB)
    return bytes(delta)

def generate_wire_labels(num_wires, delta):
    wire_labels = {}
    for i in range(num_wires):
        base_label = os.urandom(WIRE_LABEL_SIZE)
        sel_bit = random.randint(0, 1)
        label_0 = base_label if sel_bit == 0 else bytes(a ^ b for a, b in zip(base_label, delta))
        label_1 = bytes(a ^ b for a, b in zip(label_0, delta))
        wire_labels[i] = ((label_0, 0 if sel_bit == 0 else 1), (label_1, 1 if sel_bit == 0 else 0))
    return wire_labels

def encode_inputs(bits, wire_labels, offset):
    return [wire_labels[offset + i][bit] for i, bit in enumerate(bits)]

def garble_and_gate(A, B, C, wire_labels, delta):
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

        if gtype == "XOR":
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
        elif gtype == "AND":
            A, B = in_wires
            C = out_wires[0]
            garbled_tables.append(garble_and_gate(A, B, C, wire_labels, delta))
        else:
            raise NotImplementedError(f"Gate {gtype} not supported.")
    return garbled_tables

def prepare_evaluator_package(circuit, wire_labels, bob_input_bits, garbled_tables, k_rand_bits, delta):
    inputs_offset = circuit["inputs_garbler"]
    bob_input_labels = encode_inputs(bob_input_bits, wire_labels, inputs_offset)
    bob_input_indices = list(range(inputs_offset, inputs_offset + len(bob_input_bits)))
    output_indices = circuit["output_wires"]
    alice_input_indices = list(range(0, inputs_offset))
    alice_input_labels = encode_inputs(k_rand_bits, wire_labels, 0)  # <- Garbled input: evaluator doesn't know the bit
    # Output wire indices
    output_map = {
        idx: {
            "0": wire_labels[idx][0],
            "1": wire_labels[idx][1]
        } for idx in output_indices
    }

    bob_map = {
        idx: {
            "0": wire_labels[idx][0],
            "1": wire_labels[idx][1]
        } for idx in bob_input_indices
    }

    key_map = {
        idx: {
            "0": wire_labels[idx][0],
            "1": wire_labels[idx][1]
        } for idx in alice_input_indices
    }

    return {
        "middlebox_inputs": bob_input_labels,
        "middlebox_input_wires": bob_input_indices,
        "garbled_tables": garbled_tables,
        "output_map": output_map,
        "alice_inputs": alice_input_labels,
        "alice_input_wires": alice_input_indices,
        "output_wires": output_indices,
        "delta":delta,
        "gates": circuit["gates"],
        "wire_labels": wire_labels,
        "bob_map": bob_map,
        "key_map":key_map
    }

def send_garbled_output(evaluator_package):
    # Serialize the evaluator package
    serialized = pickle.dumps(evaluator_package)
    length = len(serialized).to_bytes(4, 'big')

    # Connect to middlebox and send length + data
    s = socket.socket()
    s.connect(('middlebox', 5001))
    s.sendall(length + serialized)
    s.close()

def bits_to_bytes(bits):
    # Pad to full bytes (if necessary)
    if len(bits) % 8 != 0:
        bits += [0] * (8 - (len(bits) % 8))

    byte_arr = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        byte_arr.append(byte)
    return bytes(byte_arr)

def main():
    k_ssl, k, k_rand = perform_dh_key_exchange()
    circuit_path = "aes_128.bristol" 
    circuit = parse_bristol_circuit(circuit_path)

    delta = generate_delta()   #will be generate based on k_rand
    wire_labels = generate_wire_labels(circuit["num_wires"], delta)

    k_rand_bits = bytes_to_bits(k_rand) # need to correct , use k
    print("KEY:",k_rand_bits)
    bob_input_bits = [random.randint(0, 1) for _ in range(circuit["inputs_middlebox"])]
    bob_input_bytes = bits_to_bytes(bob_input_bits)
    cipher = Cipher(algorithms.AES(k_rand), modes.ECB(), backend=default_backend())
    padder = padding.PKCS7(128).padder()
    padded = padder.update(bob_input_bytes) + padder.finalize()
    encryptor = cipher.encryptor()
    print("INPUT",bytes_to_bits(padded[:16]))
    ct = encryptor.update(padded[:16]) + encryptor.finalize()
    print("[Client] ciphertext:", ct.hex())
    garbled_tables = garble_circuit(circuit, wire_labels, delta)
    print("PART 1a:",wire_labels[16316])
    print("PART 1b:",wire_labels[36492])
    print("PART 1a:",wire_labels[16317])
    print("PART 1b:",wire_labels[36493])
    print("CHECK:",bytes_to_bits(padded))
    evaluator_package = prepare_evaluator_package(circuit, wire_labels, bytes_to_bits(padded)[:128], garbled_tables,k_rand_bits,delta)

    option, min_length = tokenisation_selection()

    send_garbled_output(evaluator_package)

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