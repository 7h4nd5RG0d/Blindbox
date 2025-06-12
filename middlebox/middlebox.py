import socket
import random

# Ruleset
ruleset = ['hack', 'malware', 'attack', 'exploit']
min_length = min(len(word) for word in ruleset)


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
    mb = socket.socket()
    mb.bind(('0.0.0.0', 5001))
    mb.listen(5)
    print("[Middlebox] Middlebox up...")

    handle_tokenisation(mb) 
    while True:
        try:
            conn, addr = mb.accept()
            print(f"[Middlebox] Connection from {addr}")
            data = conn.recv(1024)
            print("[Middlebox] Received (encrypted):", data.hex())

            # Forward as-is to the server
            server_response = forward_to_server(data)
            conn.send(server_response)
        except Exception as e:
            print("[Middlebox] Error:", str(e))
        finally:
            conn.close()


if __name__ == "__main__":
    main()
