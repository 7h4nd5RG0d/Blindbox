# DEPENDENCIES:
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.mceliece8192128 import encrypt
from collections import defaultdict 
from tinyec import registry,ec
from tinyec.ec import Point
import secrets
import hashlib
import re
import hmac
import pickle
import socket

#####################################################################################################
# GLOBAL PARAMS
# Keys
k_ssl=0
k=0

k_rand=0

RS=2**64
salt_int=0
WIRE_LABEL_SIZE = 16  # 128-bit wire labels (AES block size)
# Using a standard curve for OT
curve = registry.get_curve('secp256r1')  # prime-order group
G = curve.g  # Generator point
p = curve.field.p  # Prime field order

#Mathematical functions##############################################################################
def bytes_to_bits(byte_data):
    return [int(bit) for byte in byte_data for bit in f'{byte:08b}'] 

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

#####################################################################################################
# Key exchange with client
def handle_key_exchange(server_socket):
    global k_ssl, k, k_rand, salt_int

    conn, addr = server_socket.accept()
    print("[Server] Key exchange connection from", addr)

    pk_len_bytes = conn.recv(4)
    pk_len = int.from_bytes(pk_len_bytes, 'big')
    pk = b''
    while len(pk) < pk_len:
        pk += conn.recv(pk_len - len(pk))
    ct,ss=encrypt(pk)
    conn.sendall(len(ct).to_bytes(4, 'big')+ct)
    salt_bytes =conn.recv(1024)
    salt_int = int.from_bytes(salt_bytes, 'big')

    print("[Server] salt recieved:",salt_int)
    shared_secret = ss
    print("[Server] Shared secret with client:", shared_secret.hex())

    key = hashlib.sha512(shared_secret).digest() 
    k_ssl=key[:32]
    k=key[32:48]
    k_rand=key[48:64]
    conn.close()

#####################################################################################################
def point_to_bytes(P):
    return int.to_bytes(P.x, 32, 'big') + int.to_bytes(P.y, 32, 'big')

def bytes_to_point(b):
    x = int.from_bytes(b[:32], 'big')
    y = int.from_bytes(b[32:], 'big')
    return ec.Point(curve,x, y)

def Hash(S: Point, R: Point, P: Point) -> bytes:
    data = (
        S.x.to_bytes(32, 'big') + S.y.to_bytes(32, 'big') +
        R.x.to_bytes(32, 'big') + R.y.to_bytes(32, 'big') +
        P.x.to_bytes(32, 'big') + P.y.to_bytes(32, 'big')
    )
    return hashlib.sha256(data).digest()

# Oblivious Transfer:
def handle_oblivious_transfer(conn,num,wire_label,offset):
    y = secrets.randbelow(curve.field.n - 1)+1 # y ← F_p
    S = y * G
    T = y * S
    conn.send(point_to_bytes(S))
    for i in range(num):
        for j in range(128):
            R_i_j=bytes_to_point(conn.recv(64))
            k_i0_j = Hash(S, R_i_j, y * R_i_j)
            k_i1_j = Hash(S, R_i_j, (y * R_i_j) - T)
            ci_0=xor_bytes(k_i0_j,wire_label[offset+j][0])
            ci_1=xor_bytes(k_i1_j,wire_label[offset+j][1])
            conn.send(ci_0)
            conn.send(ci_1)

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
def generate_wire_labels(num_wires, delta, k_rand):
    wire_labels = {}
    for i in range(num_wires):
        label_material = prf(k_rand, f'label-{i}')
        base_label = label_material[:16]
        label_0 = base_label
        label_1 = bytes(a ^ b for a, b in zip(label_0, delta)) # Label for 1 bit
        wire_labels[i] = (label_0, label_1)
    return wire_labels

# Hash function for Half-gates optimisation:
def H(counter: int, label: bytes) -> bytes:
    counter_bytes = counter.to_bytes(4, byteorder='big')
    data = counter_bytes + label
    # Apply SHA256 hash
    return hashlib.sha256(data).digest()

# Helper functions
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def mul_bit_bytes(bit: int, b: bytes) -> bytes:
    return b if bit else bytes(len(b))

# Garbling of AND gate using Half-Gate optimisation
def garble_and_gate(A, B, C, wire_labels,counter,delta):
    X_a0 = wire_labels[A][0]
    X_a1 = wire_labels[A][1]
    X_b0 = wire_labels[B][0]
    X_b1 = wire_labels[B][1]

    p_a = X_a0[-1] & 1
    p_b = X_b0[-1] & 1

    # First half-gate
    Ha0 = H(counter, X_a0)
    Ha1 = H(counter, X_a1)
    T_G  = xor_bytes(xor_bytes(Ha0, Ha1), mul_bit_bytes(p_b, delta))
    X_G  = xor_bytes(Ha0, mul_bit_bytes(p_a, T_G))

    # Second half-gate
    Hb0 = H(counter + 1, X_b0)
    Hb1 = H(counter + 1, X_b1)
    T_E  = xor_bytes(xor_bytes(Hb0, Hb1), X_a0)
    temp = xor_bytes(T_E, X_a0)
    X_E  = xor_bytes(Hb0, mul_bit_bytes(p_b, temp))

    # Output labels
    X_c0 = xor_bytes(X_G, X_E)
    X_c1 = xor_bytes(X_c0, delta)

    wire_labels[C] = (X_c0, X_c1)

    return {
        "type": "AND",
        "in": (A, B),
        "out": C,
        "table": [T_G, T_E]
    }

# Garble the circuit using Free XOR and basic AND gate garbling
def garble_circuit(circuit, wire_labels, delta, g_P):
    garbled_tables = []
    counter=0
    for gate in circuit["gates"]:
        gtype = gate["type"]
        in_wires = gate["in"]
        out_wires = gate["out"]

        if gtype == "XOR": # Simple free XOR
            A, B = in_wires
            C = out_wires[0]
            (a0), _ = wire_labels[A]
            (b0), _ = wire_labels[B]
            c0 = bytes(x ^ y for x, y in zip(a0, b0))
            c1 = bytes(x ^ y for x, y in zip(c0, delta))
            wire_labels[C] = ((c0), (c1))

        elif gtype == "INV":
            A = in_wires[0]
            (a0)=wire_labels[A][0]
            C = out_wires[0]
            c0=bytes(x ^ y for x, y in zip(a0, g_P))
            wire_labels[C] = ((bytes(x ^ y for x, y in zip(c0, delta))),(c0))

        elif gtype == "AND": # Can be optimised using garbled gate reduction(GRR)
            A, B = in_wires
            C = out_wires[0]
            garbled_tables.append(garble_and_gate(A, B, C, wire_labels,counter,delta))
            counter=counter+2

        else:
            raise NotImplementedError("[Client] ",f"Gate {gtype} not supported.")
    return garbled_tables


# Function for generating labels for inputs in garbler side
def encode_inputs(bits, wire_labels, offset):
    return [wire_labels[offset + i][bit] for i, bit in enumerate(bits)]

# Package to be sent ot middlebox
def prepare_evaluator_package(circuit, wire_labels, garbled_tables, k_bits,g_P):
    inputs_offset = circuit["inputs_garbler"]

    middlebox_input_indices = list(range(inputs_offset, inputs_offset + 128))
    output_indices = circuit["output_wires"]

    client_input_indices = list(range(0, inputs_offset))
    client_input_labels = encode_inputs(k_bits, wire_labels, 0)  # <- Garbled input: evaluator doesn't know the bit
    # Output wire indices
    output_map = {
    idx: wire_labels[idx][0][-1] & 1  # LSB of last byte of label for bit 0
    for idx in output_indices
    }
    return {
        "garbled_tables": garbled_tables,
        "middlebox_input_wires": middlebox_input_indices,
        "output_map": output_map,
        "client_inputs": client_input_labels,
        "client_input_wires": client_input_indices,
        "output_wires": output_indices,
        "gates": circuit["gates"],
        "g_P": g_P
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

        handle_oblivious_transfer(conn,num_blocks,wire_labels,offset)
    except Exception as e:
        print(f"[!] Error in send_garbled_output: {e}")
    finally:
        conn.close()
        print("[Server] garbled tables and labels sent to middlebox")

# Evaluating circuit /// Trivial just for CHECKING
def evaluate_circuit(circuit, input_bits):
    total_wires = circuit["num_wires"]
    wire_values = [0] * total_wires 

    for idx, bit in enumerate(input_bits):
        wire_values[idx] = bit

    for gate in circuit["gates"]:
        typ = gate["type"]
        ins = gate["in"]
        out = gate["out"][0]
        if typ == "XOR":
            wire_values[out] = wire_values[ins[0]] ^ wire_values[ins[1]]
        elif typ == "AND":
            wire_values[out] = wire_values[ins[0]] & wire_values[ins[1]]
        elif typ == "INV":
            wire_values[out] = 1 - wire_values[ins[0]]
    return wire_values[-circuit["num_outputs"]:]
#####################################################################################################
def handle_middlebox_messages(server_socket,circuit):
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
                server_tokens,salts=delimiter_tokenisation(dec_data.decode(),token_length)
            
            cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=default_backend())
            k_bits=bytes_to_bits(k)
            for token in server_tokens:
                padder = padding.PKCS7(128).padder() 
                padded = padder.update(token) + padder.finalize()
                padded_bits=bytes_to_bits(padded)
                out_bits=evaluate_circuit(circuit,k_bits+padded_bits)
                server_pre_enc_tokens.append(bits_to_bytes(out_bits))
            
            idx=0
            for token in server_pre_enc_tokens:
                cipher = Cipher(algorithms.AES(token), modes.ECB(), backend=default_backend())
                padder = padding.PKCS7(128).padder() 
                salt_bytes = salts[idx].to_bytes(8, byteorder='big')
                padded = padder.update(salt_bytes) + padder.finalize()
                encryptor = cipher.encryptor()
                ct = encryptor.update(padded) + encryptor.finalize()
                ct_int=int.from_bytes(ct, byteorder='big')
                ct_int=ct_int%RS
                ct_bytes = ct_int.to_bytes(8, byteorder='big')
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
def delimiter_tokenisation(plaintext,window_size):
    delimiters = ['=', ';', ':', ',', ' ']
    salts=[]
    counts={}
    pattern = '|'.join(map(re.escape, delimiters))
    raw_tokens = re.split(pattern, plaintext)
    tokens=[]
    for token in raw_tokens:
        if not token:
            continue
        if len(token) > window_size:
            # Replace long token with 8-byte windows
            broken_tokens = window_tokenisation_partial(token, window_size)
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

#####################################################################################################
    circuit_path = "aes_128.bristol" 
    circuit = parse_bristol_circuit(circuit_path)
    print("[Server] AES circuit ready..!")

#####################################################################################################

    k_bits = bytes_to_bits(k) 
    delta = generate_delta(k_rand)   # will be generate based on k_rand
    X= generate_delta(k_rand) # will be used for INV gates
    g_P=bytes(x ^ y for x, y in zip(X, delta))
    wire_labels = generate_wire_labels(circuit["num_wires"], delta, k_rand)
    garbled_tables = garble_circuit(circuit, wire_labels, delta,g_P)
    evaluator_package = prepare_evaluator_package(circuit, wire_labels, garbled_tables,k_bits,g_P)

    # Need to use OT
    send_garbled_output(s,evaluator_package,wire_labels,circuit['inputs_garbler'])

#####################################################################################################
    handle_middlebox_messages(s,circuit)

#####################################################################################################

if __name__ == "__main__":
    main()