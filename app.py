import socket
import threading
import time
from packet import SecurePacket, PacketType
from handshake import perform_handshake

# === CONFIG ===
PEER_IP: str = "192.168.1.9"   # 🔧 Update to match peer IP
PEER_PORT: int = 6500
LISTEN_PORT: int = 6501

MESSAGE = "⚡️ This is a Message from PTER Protocol ⚡️".encode('utf-8')  # ✅ Valid UTF-8


# === SENDER FUNCTION ===
def send_packet(ip: str, port: int, message: bytes) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            print(f"[>] Connected to peer {ip}:{port}")

            # Perform secure handshake to derive session key
            session_key = perform_handshake(s, f"{ip}:{port}", initiator=True)
            if not session_key:
                print("[x] Handshake failed.")
                return

            # Create encrypted and compressed packet using derived session key
            packet = SecurePacket(PacketType.MESSAGE, message, session_key, compress=True)
            s.sendall(packet.to_bytes())
            print(f"[✔] Sent secure packet to {ip}:{port}")
    except Exception as e:
        print(f"[!] Error sending packet to {ip}:{port} - {e}")


# === RECEIVER FUNCTION ===
def receive_packet(conn: socket.socket, addr: str) -> None:
    try:
        # Perform secure handshake to derive session key
        session_key = perform_handshake(conn, addr)
        if not session_key:
            print(f"[x] Handshake failed with {addr}")
            return

        data = conn.recv(4096)
        if not data:
            print(f"[x] No data received from {addr}")
            return

        # Decrypt packet using the negotiated session key
        packet = SecurePacket.from_bytes(data, session_key)
        print(f"[📥] Received from {addr}: {packet.get_payload().decode()}")

    except Exception as e:
        print(f"[!] Packet processing error from {addr}: {e}")
    finally:
        conn.close()


# === SERVER MODE ===
def server_mode(listen_port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", listen_port))
        s.listen()
        print(f"[🔉] Listening for packets on port {listen_port}...")

        while True:
            conn, addr = s.accept()
            client_addr = f"{addr[0]}:{addr[1]}"
            threading.Thread(target=receive_packet, args=(conn, client_addr), daemon=True).start()


# === CLIENT MODE ===
def client_mode(peer_ip: str, peer_port: int) -> None:
    while True:
        send_packet(peer_ip, peer_port, MESSAGE)
        time.sleep(10)  # Adjustable retry/send interval


# === MAIN ===
def main() -> None:
    threading.Thread(target=server_mode, args=(LISTEN_PORT,), daemon=True).start()
    threading.Thread(target=client_mode, args=(PEER_IP, PEER_PORT)).start()

if __name__ == "__main__":
    main()
