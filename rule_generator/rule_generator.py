from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import socket
import pickle

key = RSA.generate(2048)
privkey = key
pubkey = key.publickey()
ruleset = ['hack','malware']
ruleset_bytes = pickle.dumps(ruleset)
ruleset_digest = SHA256.new(ruleset_bytes).digest()
digest_hash = SHA256.new(ruleset_digest)
signature = pkcs1_15.new(privkey).sign(digest_hash)


def send_public_key(generator_socket):
    conn, addr = generator_socket.accept()
    print("[Rule-generator] 🚀 Verification connection from", addr)
    pubkey_bytes = pubkey.export_key()
    conn.send(len(pubkey_bytes).to_bytes(4, 'big'))
    conn.send(pubkey_bytes)
    conn.send(signature)

def send_ruleset():
    try:
        with socket.socket() as conn:
            conn.connect(('middlebox', 5001))
            print("[Rule-generator] 🚀 Connected to Middlebox for sending ruleset")

            conn.send(pickle.dumps(ruleset))

    except Exception as e:
        print("[Rule-generator] ❌", f"[!] Error: {e}")
        return None, []

    
#####################################################################################################
def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 5003))
    s.listen(5)
    print("[Server] 🟢 Rule-Generator up...")

    send_public_key(s)
    send_ruleset()

#####################################################################################################
if __name__ == "__main__":
    main()

#####################################################################################################