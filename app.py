import socket
import threading
import time
import signal
import sys
import types
from typing import Optional

from MODULES.packet import SecurePacket, PacketType
from MODULES.handshake import perform_handshake

# === CONFIGURATION ===
PEER_IP: str = "192.168.1.9"  # 🔧 Set to your peer's IP
PEER_PORT: int = 6500
LISTEN_PORT: int = 6501
MESSAGE = ("⚡️ This is a Message from PTER Protocol ⚡️ " * 16384).encode('utf-8')  # ≈ 1MB

# === GLOBAL STATE ===
running = True
server_socket: Optional[socket.socket] = None


# === SIGNAL HANDLER ===
def signal_handler(sig: int, _: Optional[types.FrameType]) -> None:
    global running, server_socket
    print(f"\n[🔻] Caught termination signal ({sig}). Cleaning up...")

    running = False

    if server_socket:
        try:
            server_socket.close()
            print("[🧹] Server socket closed.")
        except Exception as e:
            print(f"[!] Error closing server socket: {e}")

    sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # kill
if sys.platform == "win32":
    signal.signal(signal.SIGBREAK, signal_handler)  # Ctrl+Break (Windows only)


# === SENDER FUNCTION ===
def send_packet(ip: str, port: int, message: bytes) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            print(f"[>] Connected to peer {ip}:{port}")

            session_key = perform_handshake(s, f"{ip}:{port}", initiator=True)
            if not session_key:
                print("[x] Handshake failed.")
                return

            packet = SecurePacket(PacketType.MESSAGE, message, session_key, compress=True)
            s.sendall(packet.to_bytes())
            print(f"[✔] Sent secure packet to {ip}:{port}")
    except Exception as e:
        print(f"[🚨] Error sending packet to {ip}:{port} - {e}")


# === RECEIVER FUNCTION ===
def receive_packet(conn: socket.socket, addr: str) -> None:
    try:
        session_key = perform_handshake(conn, addr)
        if not session_key:
            print(f"[x] Handshake failed with {addr}")
            return

        data = conn.recv(4096)
        if not data:
            print(f"[x] No data received from {addr}")
            return

        packet = SecurePacket.from_bytes(data, session_key)
        print(f"[📥] Received from {addr}: {packet.get_payload().decode()}")

    except Exception as e:
        print(f"[🚨] Packet processing error from {addr}: {e}")
    finally:
        conn.close()


# === SERVER MODE ===
def server_mode(listen_port: int) -> None:
    global server_socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        server_socket = s
        s.bind(("", listen_port))
        s.listen()
        print(f"[🔉] Listening for packets on port {listen_port}...")

        s.settimeout(1.0)  # Let accept() check for shutdown periodically
        while running:
            try:
                conn, addr = s.accept()
                client_addr = f"{addr[0]}:{addr[1]}"
                threading.Thread(target=receive_packet, args=(conn, client_addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if running:
                    print(f"[⚠️] Server socket error: {e}")
                break


# === CLIENT MODE ===
def client_mode(peer_ip: str, peer_port: int) -> None:
    while running:
        send_packet(peer_ip, peer_port, MESSAGE)
        time.sleep(10)  # Adjustable send interval


# === MAIN ===
def main() -> None:
    threading.Thread(target=server_mode, args=(LISTEN_PORT,), daemon=True).start()
    threading.Thread(target=client_mode, args=(PEER_IP, PEER_PORT)).start()


if __name__ == "__main__":
    main()
