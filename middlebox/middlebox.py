import socket
import random

# Ruleset
ruleset = ['hack', 'malware', 'attack', 'exploit']
min_length = min(len(word) for word in ruleset)

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
    # Read length of enc_msg (4 bytes)
    enc_len_bytes = receive_full(conn, 4)
    enc_len = int.from_bytes(enc_len_bytes, 'big')
    # Read enc_msg
    enc_msg = receive_full(conn, enc_len)
    # Read length of token data (4 bytes)
    token_len_bytes = receive_full(conn, 4)
    token_len = int.from_bytes(token_len_bytes, 'big')
    # Read encrypted tokens
    token_data = receive_full(conn, token_len)
    return enc_msg, token_data

# Select tokenisation scheme
def handle_tokenisation(middlebox_socket):
    conn, addr = middlebox_socket.accept()
    print("[Middlebox] Tokenisation connection from", addr)
    s=random.randint(1,2)
    if s==2:
        conn.send(str(s).encode())
    else:
        msg = f"{s},{min_length}"
        conn.send(msg.encode())
    
    print("[Middlebox] Tokenisation method:", s)
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

    handle_tokenisation(mb) 

    while True:
        try:
            # Connection with client
            conn, addr = mb.accept()
            print(f"[Middlebox] Connection from {addr}")
            encrypted_msg,token_stream= receive_payload(conn)
            print("[Middlebox] Encrypted message:", encrypted_msg.hex())
            print("[Middlebox] Encrypted tokens:", token_stream.hex())
            parsed_tokens=parse_token_data(token_stream)
            # Forward as-is to the server
            payload=len(encrypted_msg).to_bytes(4, 'big')+encrypted_msg + len(token_stream).to_bytes(4, 'big')+token_stream
            server_response = forward_to_server(payload)
            conn.send(server_response)
        except Exception as e:
            print("[Middlebox] Error:", str(e))
        finally:
            conn.close()


if __name__ == "__main__":
    main()