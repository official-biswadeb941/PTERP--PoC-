"""
This is the structure of Post-Trust Ephemeral Relay Protocol PTER Packet Module.
It Includes secure packet handling, encryption, decryption and compression.
"""

import zlib
import struct
import time
from enum import IntEnum, unique
from nacl.secret import SecretBox
from nacl.utils import random as random_bytes
from nacl.exceptions import CryptoError
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
        if member is not None:
            return member.name
        return f"UNKNOWN_0x{value:02X}"


    @classmethod
    def has_value(cls, value: int) -> bool:
        return value in cls._value2member_map_


class SecurePacket:
    MAGIC_BYTE = 0xAB
    VERSION = 1
    HEADER_FORMAT = "!BBBB24sQI"  # magic, version, type, flags, nonce, timestamp, payload_len
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

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
        self.flags = 0x00  # Reserved for future use

        if compress and not skip_compress:
            payload = zlib.compress(payload)
            self.packet_type = PacketType.COMPRESSED_MESSAGE
        else:
            self.packet_type = int(packet_type)

        self.nonce = nonce or random_bytes(24)
        self.session_key = session_key
        self.box = SecretBox(session_key)

        self.ciphertext = self.box.encrypt(payload, self.nonce).ciphertext
        self.payload = payload  # Save raw or compressed data

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
        return header + self.ciphertext

    def hex_dump(self) -> str:
        return self.to_bytes().hex()

    @classmethod
    def from_bytes(cls, data: bytes, session_key: bytes) -> 'SecurePacket':
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Invalid packet: too short.")

        header = data[:cls.HEADER_SIZE]
        magic, version, packet_type, flags, nonce, timestamp, payload_len = struct.unpack(cls.HEADER_FORMAT, header)

        if magic != cls.MAGIC_BYTE:
            raise ValueError(f"Invalid magic byte: {hex(magic)}")

        if version != cls.VERSION:
            raise ValueError(f"Unsupported protocol version: {version}, expected: {cls.VERSION}")

        if flags != 0x00:
            raise ValueError(f"Unexpected flags set: 0x{flags:02X} — flags are currently reserved and must be zero.")

        if len(session_key) != SecretBox.KEY_SIZE:
            raise ValueError("Session key must be 32 bytes.")

        ciphertext = data[cls.HEADER_SIZE:cls.HEADER_SIZE + payload_len]
        if len(ciphertext) != payload_len:
            raise ValueError("Payload length mismatch.")

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
            "nonce": self.nonce.hex()
        }
