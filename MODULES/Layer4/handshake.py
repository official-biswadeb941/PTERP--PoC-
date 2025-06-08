import socket
import threading
import time
import hashlib
import secrets
import base64
from typing import Optional 
from nacl.public import PrivateKey, PublicKey, Box

MAGIC: str = "GET / HTTP/3.0\r\nHost: google.com\r\nUser-Agent: curl/8.1.0\r\n\r\n"

# === UTILS ===
def generate_nonce() -> str:
    return secrets.token_hex(8)

def generate_hash(timestamp: str, nonce: str) -> str:
    return hashlib.sha256((timestamp + nonce).encode()).hexdigest()

# === HANDSHAKE FUNCTION ===
def perform_handshake(conn: socket.socket, addr: str, initiator: bool = False) -> Optional[bytes]:
    try:
        # Generate ephemeral key pair
        sk = PrivateKey.generate()
        pk = sk.public_key
        pk_b64 = base64.b64encode(bytes(pk)).decode()

        if initiator:
            # Send: MAGIC | timestamp | nonce | base64(pubkey)
            timestamp = str(int(time.time()))
            nonce = generate_nonce()
            message = f"{MAGIC}|{timestamp}|{nonce}|{pk_b64}"
            conn.sendall(message.encode())

            # Receive: digest | base64(pubkey)
            data = conn.recv(1024)
            if not data:
                return None

            response = data.decode()
            try:
                expected_hash, peer_pk_b64 = response.split("|")
            except ValueError:
                print(f"❌ Invalid response format from {addr}")
                return None

            if expected_hash != generate_hash(timestamp, nonce)[:16]:
                print(f"❌ Hash mismatch from {addr}")
                return None

            peer_pk = PublicKey(base64.b64decode(peer_pk_b64))
            box = Box(sk, peer_pk)
            shared_session_key = box.shared_key()

            # Final ACK
            conn.sendall(b"ACK::OK")
            print(f"🤝 Handshake completed with {addr}")
            return shared_session_key

        else:
            # Receive: MAGIC | timestamp | nonce | base64(pubkey)
            data = conn.recv(1024)
            if not data:
                return None

            try:
                magic, timestamp, nonce, peer_pk_b64 = data.decode().split("|")
            except ValueError:
                print(f"❌ Malformed handshake from {addr}")
                return None

            if magic != MAGIC:
                conn.sendall(b"REJECT::MAGIC")
                return None

            # Derive digest and send back
            digest = generate_hash(timestamp, nonce)[:16]
            peer_pk = PublicKey(base64.b64decode(peer_pk_b64))
            reply = f"{digest}|{pk_b64}"
            conn.sendall(reply.encode())

            # Wait for ACK
            ack = conn.recv(1024)
            if ack and ack.decode() == "ACK::OK":
                box = Box(sk, peer_pk)
                shared_session_key = box.shared_key()
                print(f"🤝 Handshake completed with {addr}")
                return shared_session_key
            else:
                print(f"❌ No ACK from {addr}")
                return None

    except Exception as e:
        print(f"⚠️ Handshake error with {addr}: {e}")
        return None


# === SERVER ROLE ===
def server_mode(LISTEN_PORT: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", LISTEN_PORT))
        s.listen()
        print(f"[🔉] Listening on port {LISTEN_PORT}...")

        while True:
            conn, addr = s.accept()
            client_addr = f"{addr[0]}:{addr[1]}"
            threading.Thread(
                target=handle_connection,
                args=(conn, client_addr, False),
                daemon=True
            ).start()

# === CLIENT ROLE ===
def client_mode(PEER_IP: str, PEER_PORT: int):
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((PEER_IP, PEER_PORT))
                print(f"[📡] Connected to peer {PEER_IP}:{PEER_PORT}")
                handle_connection(s, f"{PEER_IP}:{PEER_PORT}", initiator=True)
        except Exception as e:
            print(f"[🔁] Retrying peer connection: {e}")
        time.sleep(10)

# === COMMON CONNECTION HANDLER ===
def handle_connection(conn: socket.socket, addr: str, initiator: bool) -> None:
    session_key = perform_handshake(conn, addr, initiator)
    if session_key:
        # You should now pass session_key to your SecurePacket handler
        print(f"[🔑] Session key established with {addr}: {session_key.hex()}")
    else:
        print(f"[❌] Handshake failed with {addr}")

# === MAIN ===
def main() -> None:
    threading.Thread(target=server_mode, daemon=True).start()
    threading.Thread(target=client_mode).start()

if __name__ == "__main__":
    main()
