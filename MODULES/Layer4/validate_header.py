"""
validate_header.py

An epistemological anomaly scanner for the PTER Packet header realm.
It exists to raise questions, not answers — cultivating suspicion in the minds of digital forensic practitioners.
"""

import struct
import time
from typing import List, Tuple

try:
    from packet import PacketType  # Optional, enhances readability
except ImportError:
    PacketType = None  # fallback if enum isn't available


class HeaderSkeptic:
    HEADER_FORMAT = "!BBBB24sQII"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    EXPECTED_MAGIC = 0xAB
    EXPECTED_VERSION = 0x01
    EXPECTED_FLAGS = 0x00
    MAX_DIGEST_LEN = 4096  # Updated upper limit for digest length sanity

    DEBUG = False  # Set True for verbose debug output

    @classmethod
    def question_header(cls, packet: bytes) -> Tuple[bool, str]:
        if len(packet) < cls.HEADER_SIZE:
            return False, f"[❓] Curiously short — only {len(packet)} bytes. Where did the rest go?"

        try:
            (
                magic,
                version,
                ptype,
                flags,
                nonce,
                timestamp,
                payload_len,
                digest_len
            ) = struct.unpack(cls.HEADER_FORMAT, packet[:cls.HEADER_SIZE])
        except struct.error as e:
            return False, f"[⚠️] Structural fatigue detected: {str(e)}."

        questions: List[str] = []

        if cls.DEBUG:
            print(f"[🧬 DEBUG] Parsed Header:\n"
                  f"  Magic: 0x{magic:02X}\n"
                  f"  Version: {version}\n"
                  f"  Type: 0x{ptype:02X}\n"
                  f"  Flags: 0x{flags:02X}\n"
                  f"  Nonce: {nonce.hex()}\n"
                  f"  Timestamp: {timestamp} ({time.ctime(timestamp)})\n"
                  f"  Payload Length: {payload_len}\n"
                  f"  Digest Length: {digest_len}")

        # Magic byte check
        if magic != cls.EXPECTED_MAGIC:
            questions.append(
                f"[🧪] What force tampered with the signature of trust? Magic byte says 0x{magic:02X}, expected 0x{cls.EXPECTED_MAGIC:02X}."
            )

        # Version check
        if version != cls.EXPECTED_VERSION:
            questions.append(
                f"[📜] This dialect speaks version {version}, yet the tribe recognizes only {cls.EXPECTED_VERSION}."
            )

        # Packet type ambiguity
        if PacketType is not None:
            if ptype in PacketType._value2member_map_:
                packet_name = PacketType(ptype).name
                questions.append(f"[📖] The glyph says {packet_name}, but who wrote this script?")
            elif ptype >= 0x80:
                questions.append(f"[🧬] Type code 0x{ptype:02X} bears experimental traits. Who sent this creature?")
            else:
                questions.append(f"[🕳️] Type 0x{ptype:02X} — unrecognized in the lexicon. Is it invention or intrusion?")
        else:
            if ptype >= 0x80:
                questions.append(f"[🧬] Type code 0x{ptype:02X} bears experimental traits. Who sent this creature?")
            else:
                questions.append(f"[📦] Unknown type identifier: 0x{ptype:02X}.")

        # Flags check
        if flags != cls.EXPECTED_FLAGS:
            questions.append(
                f"[🚩] Unseen flags are waving — 0x{flags:02X}. What ritual do they trigger?"
            )

        # Timestamp check
        current_time = int(time.time())
        if not (0 <= timestamp <= current_time + 60):
            t_human = time.ctime(timestamp)
            questions.append(
                f"[🕰️] Temporal displacement? Timestamp whispers: {t_human}."
            )

        # Payload length
        if payload_len == 0:
            questions.append(
                f"[📦] An empty ciphered box? Payload length says {payload_len}."
            )

        # Digest sanity
        if digest_len == 0:
            questions.append("[🧊] Digest length is zero — no checksum rune was engraved.")
        elif digest_len > cls.MAX_DIGEST_LEN:
            questions.append(f"[🧠] Digest length unusually large ({digest_len}). Are we hashing gods or garbage?")

        # Nonce entropy check
        if nonce == b"\x00" * 24:
            questions.append(f"[🧊] Nonce frozen in zero-space. Entropy abandoned its post.")

        summary = "\n".join(questions) if questions else "[✅] The header bears no immediate contradictions — or hides them exquisitely."
        return len(questions) == 0, summary


