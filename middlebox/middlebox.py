import socket

# Ruleset
ruleset = ['hack', 'malware', 'attack', 'exploit']

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
