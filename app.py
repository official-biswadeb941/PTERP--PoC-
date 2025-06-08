import socket
import threading
import time
import signal
import sys
import types
import struct
from typing import Optional

from MODULES.Layer4.packet import SecurePacket, PacketType
from MODULES.Layer4.handshake import perform_handshake

# === CONFIGURATION ===
PEER_IP: str = "192.168.1.9"  # 🔧 Set to your peer's IP
PEER_PORT: int = 6500
LISTEN_PORT: int = 6501
MESSAGE = ("⚡️ This is a Message from PTER Protocol ⚡️ " * 10000).encode('utf-8')  # ≈ 1MB

# === GLOBAL STATE ===
running = True
server_socket: Optional[socket.socket] = None
VERBOSE = True
total_received_bytes = 0


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
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
if sys.platform == "win32":
    signal.signal(signal.SIGBREAK, signal_handler)


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
            packet_data = packet.to_bytes()

            # Prefix with 4-byte big-endian length
            length_prefix = struct.pack(">I", len(packet_data))
            s.sendall(length_prefix + packet_data)

            print(f"[✔] Sent secure packet to {ip}:{port} ({len(packet_data)} bytes)")

    except Exception as e:
        print(f"[🚨] Error sending packet to {ip}:{port} - {e}")


# === RECEIVER FUNCTION ===
def receive_packet(conn: socket.socket, addr: str) -> None:
    global total_received_bytes

    try:
        session_key = perform_handshake(conn, addr)
        if not session_key:
            print(f"[x] Handshake failed with {addr}")
            return

        # Read the 4-byte length prefix
        header = conn.recv(4)
        if len(header) < 4:
            print(f"[x] Incomplete header from {addr}")
            return

        packet_length = struct.unpack(">I", header)[0]
        if VERBOSE:
            print(f"[🔍] Expecting packet of size {packet_length} bytes from {addr}")

        # Read full packet data based on the length
        data = b""
        while len(data) < packet_length:
            chunk = conn.recv(min(4096, packet_length - len(data)))
            if not chunk:
                break
            data += chunk

        if len(data) != packet_length:
            print(f"[x] Incomplete packet from {addr}: expected {packet_length}, got {len(data)}")
            return

        # Process the secure packet
        packet = SecurePacket.from_bytes(data, session_key)
        payload = packet.get_payload()
        payload_size = len(payload)
        total_received_bytes += payload_size

        if VERBOSE:
            print(f"[📦] Packet Size from {addr}: {payload_size} bytes ({payload_size / (1024 * 1024):.2f} MB)")
            print(f"[📊] Total Received: {total_received_bytes} bytes ({total_received_bytes / (1024 * 1024):.2f} MB)")

        print(f"[📥] Received from {addr}: {payload.decode(errors='ignore')}")

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

        s.settimeout(1.0)
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
        time.sleep(10)


# === MAIN ===
def main() -> None:
    threading.Thread(target=server_mode, args=(LISTEN_PORT,), daemon=True).start()
    threading.Thread(target=client_mode, args=(PEER_IP, PEER_PORT)).start()


if __name__ == "__main__":
    main()
