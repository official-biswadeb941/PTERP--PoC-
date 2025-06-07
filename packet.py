"""
Post-Trust Ephemeral Relay Protocol (PTER) – Secure Packet Module
Includes secure packet handling, encryption, decryption, compression, and integrity validation via HMAC.

# Updated PTER Packet Structure (with HMAC):
#
# +----------------+----------------+----------------+----------------+
# | Magic (1 byte) | Version (1)    | Type (1)       | Flags (1)      |
# +----------------+----------------+----------------+----------------+
# |                Nonce (24 bytes)                                 |
# +---------------------------------------------------------------+
# |        Timestamp (8 bytes)         | Payload Length (4 bytes)  |
# +------------------------------------+--------------------------+
# |                Ciphertext (variable, encrypted payload)        |
# +---------------------------------------------------------------+
# |               HMAC (32 bytes, SHA-256 of ciphertext)           |
# +---------------------------------------------------------------+
"""

import zlib
import struct
import time
import hmac
import hashlib
from enum import IntEnum, unique
from nacl.secret import SecretBox
from nacl.utils import random as random_bytes
from nacl.exceptions import CryptoError
from validate_header import HeaderSkeptic  # anti-forensic validator
from typing import Optional, Any, Dict


@unique
class PacketType(IntEnum):
    # Core
    MESSAGE = 0x01
    HANDSHAKE = 0x02
    HEARTBEAT = 0x03
    ACK = 0x04
    ERROR = 0x05
    CLOSE = 0x06

    # Control
    PING = 0x20
    PONG = 0x21
    AUTH_REQUEST = 0x22
    AUTH_RESPONSE = 0x23
    SESSION_REKEY = 0x24

    # System/Internal
    METADATA = 0x40
    INTERNAL_COMMAND = 0x41
    LOG = 0x42

    # Custom
    CUSTOM_RESERVED_1 = 0x60
    CUSTOM_RESERVED_2 = 0x61

    # Extensions
    COMPRESSED_MESSAGE = 0x81
    MULTIPLEXED_STREAM = 0x82
    PRIORITY_HIGH = 0x83
    STREAM_FRAGMENT = 0x84

    @classmethod
    def is_control(cls, value: int) -> bool:
        return 0x20 <= value <= 0x3F

    @classmethod
    def is_system(cls, value: int) -> bool:
        return 0x40 <= value <= 0x5F

    @classmethod
    def is_custom(cls, value: int) -> bool:
        return 0x60 <= value <= 0x7F

    @classmethod
    def is_flagged(cls, value: int) -> bool:
        return value >= 0x80

    @classmethod
    def name_from_value(cls, value: int) -> str:
        member = cls._value2member_map_.get(value)
        return member.name if member else f"UNKNOWN_0x{value:02X}"

    @classmethod
    def has_value(cls, value: int) -> bool:
        return value in cls._value2member_map_


def compute_hmac(ciphertext: bytes, key: bytes) -> bytes:
    return hmac.new(key, ciphertext, hashlib.sha256).digest()


def verify_hmac(ciphertext: bytes, key: bytes, received_hmac: bytes) -> bool:
    expected = compute_hmac(ciphertext, key)
    return hmac.compare_digest(expected, received_hmac)


class SecurePacket:
    MAGIC_BYTE = 0xAB
    VERSION = 1
    HEADER_FORMAT = "!BBBB24sQI"  # magic, version, type, flags, nonce, timestamp, payload_len
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    HMAC_SIZE = 32  # SHA-256 digest

    def __init__(
        self,
        packet_type: int | PacketType,
        payload: bytes,
        session_key: bytes,
        nonce: Optional[bytes] = None,
        compress: bool = False,
        skip_compress: bool = False,
        timestamp: Optional[int] = None
    ) -> None:
        if not isinstance(payload, bytes):
            raise TypeError("Payload must be bytes.")
        if len(session_key) != SecretBox.KEY_SIZE:
            raise ValueError("Session key must be 32 bytes.")

        self.original_packet_type = int(packet_type)
        self.is_compressed = compress
        self.timestamp = timestamp or int(time.time())
        self.version = self.VERSION
        self.flags = 0x00

        if compress and not skip_compress:
            payload = zlib.compress(payload)
            self.packet_type = PacketType.COMPRESSED_MESSAGE
        else:
            self.packet_type = int(packet_type)

        self.nonce = nonce or random_bytes(24)
        self.session_key = session_key
        self.box = SecretBox(session_key)

        self.ciphertext = self.box.encrypt(payload, self.nonce).ciphertext
        self.hmac = compute_hmac(self.ciphertext, self.session_key)
        self.payload = payload

    def to_bytes(self) -> bytes:
        header = struct.pack(
            self.HEADER_FORMAT,
            self.MAGIC_BYTE,
            self.version,
            self.packet_type,
            self.flags,
            self.nonce,
            self.timestamp,
            len(self.ciphertext)
        )
        return header + self.ciphertext + self.hmac

    def hex_dump(self) -> str:
        return self.to_bytes().hex()

    @classmethod
    def from_bytes(cls, data: bytes, session_key: bytes) -> 'SecurePacket':
        if len(data) < cls.HEADER_SIZE + cls.HMAC_SIZE:
            raise ValueError("Invalid packet: too short.")

        # 🎭 Anti-forensic inspection (raises no exception — just asks questions)
        _, validation_notes = HeaderSkeptic.question_header(data)
        if "✅" not in validation_notes:
            print(f"[🧠 Header Anomaly Detected]\n{validation_notes}\n")  # Optional: log it for your internal ops

        header = data[:cls.HEADER_SIZE]
        magic, version, packet_type, flags, nonce, timestamp, payload_len = struct.unpack(cls.HEADER_FORMAT, header)

        if magic != cls.MAGIC_BYTE:
            raise ValueError(f"Invalid magic byte: {hex(magic)}")
        if version != cls.VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")
        if flags != 0x00:
            raise ValueError(f"Unexpected flags set: 0x{flags:02X}")

        ciphertext_start = cls.HEADER_SIZE
        ciphertext_end = ciphertext_start + payload_len
        hmac_start = ciphertext_end
        hmac_end = hmac_start + cls.HMAC_SIZE

        if len(data) < hmac_end:
            raise ValueError("Truncated packet or missing HMAC.")

        ciphertext = data[ciphertext_start:ciphertext_end]
        received_hmac = data[hmac_start:hmac_end]

        if not verify_hmac(ciphertext, session_key, received_hmac):
            raise ValueError("HMAC verification failed. Packet integrity compromised.")

        box = SecretBox(session_key)
        try:
            payload = box.decrypt(ciphertext, nonce)
        except CryptoError as e:
            raise ValueError("Decryption failed.") from e

        is_compressed = packet_type == PacketType.COMPRESSED_MESSAGE
        if is_compressed:
            try:
                payload = zlib.decompress(payload)
            except zlib.error:
                raise ValueError("Decompression failed.")

        return cls(
            packet_type=packet_type,
            payload=payload,
            session_key=session_key,
            nonce=nonce,
            compress=is_compressed,
            skip_compress=True,
            timestamp=timestamp
        )
    
    def get_payload(self) -> bytes:
        return self.payload

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "type": PacketType.name_from_value(self.packet_type),
            "timestamp": self.timestamp,
            "time_human": time.ctime(self.timestamp),
            "version": self.version,
            "compressed": self.is_compressed,
            "length": len(self.payload),
            "nonce": self.nonce.hex(),
            "hmac": self.hmac.hex(),
        }