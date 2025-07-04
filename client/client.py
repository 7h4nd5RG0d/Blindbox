# DEPENDENCIES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from collections import defaultdict 
import hmac
import socket
import pickle
import socket
import random
import hashlib
import os
import re
import sys
import zmq

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

WIRE_LABEL_SIZE = 16  # 128-bit wire labels (AES block size)

# Parse Bristol circuit file
def parse_bristol_circuit(filepath):
    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    _, num_wires = map(int, lines[0].split())
    inputs_info = list(map(int, lines[1].split()))

    if len(inputs_info) == 3:
        input1, input2, num_outputs = inputs_info
    else:
        raise ValueError("Unexpected header in Bristol file: expected 3 values on line 2.")

    gates = []
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
    print(gates[0])
    # Final outputs are candidates that never appeared as inputs
    real_outputs = [w for w in output_candidates if input_counts[w] == 0]
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
    assert len(seed) >= 16, "Seed (k_rand) must be at least 128 bits"

    # Use HMAC to derive 128-bit pseudorandom value from k_rand and counter
    h = hmac.new(seed, f'delta-{counter}'.encode(), hashlib.sha256).digest()
    delta = bytearray(h[:WIRE_LABEL_SIZE])
    delta[-1] |= 1  
    return bytes(delta)

# Generation of wire labels
def generate_wire_labels(num_wires, delta):
    wire_labels = {}
    for i in range(num_wires):
        base_label = os.urandom(WIRE_LABEL_SIZE)
        sel_bit = random.randint(0, 1)
        label_0 = base_label if sel_bit == 0 else bytes(a ^ b for a, b in zip(base_label, delta))
        label_1 = bytes(a ^ b for a, b in zip(label_0, delta))
        wire_labels[i] = ((label_0, 0 if sel_bit == 0 else 1), (label_1, 1 if sel_bit == 0 else 0))
    return wire_labels

# Function for generating labels for inputs in garbler side
def encode_inputs(bits, wire_labels, offset):
    return [wire_labels[offset + i][bit] for i, bit in enumerate(bits)]

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
            garbled_tables.append(garble_and_gate(A, B, C, wire_labels))

        else:
            raise NotImplementedError(f"Gate {gtype} not supported.")
    return garbled_tables

######################################################################################################
# Package to be sent ot middlebox
def prepare_sample_evaluator_package(circuit, wire_labels, bob_input_bits, garbled_tables, k_rand_bits):
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

    return {
        "middlebox_inputs": bob_input_labels,
        "middlebox_input_wires": bob_input_indices,
        "garbled_tables": garbled_tables,
        "output_map": output_map,
        "alice_inputs": alice_input_labels,
        "alice_input_wires": alice_input_indices,
        "output_wires": output_indices,
        "gates": circuit["gates"],
        "wire_labels": wire_labels
    }

######################################################################################################
# Package to be sent ot middlebox
def prepare_evaluator_package(circuit, wire_labels, garbled_tables, k_rand_bits):
    inputs_offset = circuit["inputs_garbler"]
    bob_input_indices = list(range(inputs_offset, inputs_offset + 128))
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

    return {
        "garbled_tables": garbled_tables,
        "middlebox_input_wires": bob_input_indices,
        "output_map": output_map,
        "alice_inputs": alice_input_labels,
        "alice_input_wires": alice_input_indices,
        "output_wires": output_indices,
        "gates": circuit["gates"],
        "wire_labels": wire_labels
    }

######################################################################################################
# Sending the garbled evaluator
def send_sample_garbled_output(evaluator_package):
    # Serialize the evaluator package
    serialized = pickle.dumps(evaluator_package)
    length = len(serialized).to_bytes(4, 'big')
    # Connect to middlebox and send length + data
    s = socket.socket()
    s.connect(('middlebox', 5001))
    s.sendall(length + serialized)
    s.close()

######################################################################################################

def send_garbled_output(evaluator_package, wire_labels, offset):
    serialized = pickle.dumps(evaluator_package)
    length = len(serialized).to_bytes(4, 'big')

    s = socket.socket()
    s.connect(('middlebox', 5001))
    s.sendall(length + serialized)

    try:
        # Receive number of blocks (4 bytes)
        num_blocks_bytes = s.recv(4)
        if len(num_blocks_bytes) < 4:
            raise RuntimeError("Failed to receive number of plaintext blocks")
        num_blocks = int.from_bytes(num_blocks_bytes, 'big')

        # Receive all plaintext blocks
        total_plaintext_len = num_blocks * 16
        received = b''
        while len(received) < total_plaintext_len:
            chunk = s.recv(total_plaintext_len - len(received))
            if not chunk:
                raise RuntimeError("Connection closed while receiving plaintext blocks")
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
                payload += label + bytes([sel_bit])  # 17 bytes per bit

        assert len(payload) == num_blocks * 128 * 17
        s.sendall(payload)

    except Exception as e:
        print(f"[!] Error in send_garbled_output: {e}")
    finally:
        s.close()


######################################################################################################
# Evaluating circuit /// Trivial just for CHECKING
def evaluate_circuit(circuit, input_bits):
    total_wires = circuit["num_wires"]
    wire_values = [0] * total_wires 

    for i, bit in enumerate(input_bits):
        wire_values[i] = bit

    for gate in circuit["gates"]:
        typ = gate["type"]
        a = gate["in"]
        out = gate["out"][0]
        if typ == "XOR":
            wire_values[out] = wire_values[a[0]] ^ wire_values[a[1]]
        elif typ == "AND":
            wire_values[out] = wire_values[a[0]] & wire_values[a[1]]
        elif typ == "INV":
            wire_values[out] = 1 - wire_values[a[0]]
    return wire_values[-circuit["num_outputs"]:]

# Mathematical functions ############################################################################

def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        bits += [0] * (8 - (len(bits) % 8))

    byte_arr = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        byte_arr.append(byte)
    return bytes(byte_arr)

def bytes_to_bits(byte_data):
    return [int(bit) for byte in byte_data for bit in f'{byte:08b}'] 

def hex_to_bits(hex_string):
    return [int(bit) for byte in bytes.fromhex(hex_string) for bit in f'{byte:08b}']

def bits_to_hex(bits):
    bytes_out = [int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)]
    return ''.join(f'{b:02x}' for b in bytes_out)

#####################################################################################################

def main():

#####################################################################################################
    k_ssl, k, k_rand = perform_dh_key_exchange()
    option, min_length = tokenisation_selection()
#####################################################################################################

    circuit_path = "AES1-128.bristol" 
    circuit = parse_bristol_circuit(circuit_path)

#####################################################################################################

    # Sample check, for is the circuit working correctly #############################################
    sample_key_hex = '2b7e151628aed2a6abf7158809cf4f3c'
    sample_pt_hex  = '6bc1bee22e409f96e93d7e117393172a'
    sample_expected_ct_hex = '3ad77bb40d7a3660a89ecaf32466ef97'

    sample_key_bits = hex_to_bits(sample_key_hex)
    sample_pt_bits = hex_to_bits(sample_pt_hex)
    sample_input_bits = sample_key_bits + sample_pt_bits  # Key first, then plaintext

    sample_out_bits = evaluate_circuit(circuit, sample_input_bits)
    sample_output_hex = bits_to_hex(sample_out_bits)

    print("Circuit Output:  ", sample_output_hex)
    print("Expected Output: ", sample_expected_ct_hex)
    print("Match:           ", sample_output_hex == sample_expected_ct_hex)

    sample_delta = generate_delta(k_rand)
    sample_wire_labels = generate_wire_labels(circuit["num_wires"], sample_delta)
    sample_garbled_tables = garble_circuit(circuit, sample_wire_labels, sample_delta)
    sample_evaluator_package = prepare_sample_evaluator_package(circuit, sample_wire_labels, sample_pt_bits, sample_garbled_tables,sample_key_bits)
    send_sample_garbled_output(sample_evaluator_package)

######################################################################################################

    k_bits = bytes_to_bits(k) 
    delta = generate_delta(k_rand)   # will be generate based on k_rand
    wire_labels = generate_wire_labels(circuit["num_wires"], delta)
    garbled_tables = garble_circuit(circuit, wire_labels, delta)
    evaluator_package = prepare_evaluator_package(circuit, wire_labels, garbled_tables,k_bits)

    # Need to use OT
    send_garbled_output(evaluator_package,wire_labels,circuit['inputs_garbler'])

######################################################################################################
    # Sending the enc_data and tokens
    while True:
        m = socket.socket()
        m.connect(('middlebox', 5001))
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

######################################################################################################

if __name__ == "__main__":
    main()

######################################################################################################