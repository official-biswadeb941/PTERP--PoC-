"""
Standalone crypto module for PTER Protocol.
Ephemeral key generation, shared secret derivation, encryption utilities.
"""

from nacl.public import PrivateKey, PublicKey
from nacl.bindings import crypto_scalarmult
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from nacl.utils import random
import hmac
import hashlib
import ctypes
from typing import Optional


class EphemeralKeyPair:
    """
    Generates and holds an ephemeral Curve25519 keypair.
    """
    def __init__(self, verbose: bool = False) -> None:
        self._private_key: Optional[PrivateKey] = PrivateKey.generate()
        self.public_key: PublicKey = self._private_key.public_key

        if verbose:
            print("[v] Private Key:", self.get_private_bytes().hex())
            print("[v] Public  Key:", self.get_public_bytes().hex())

    def get_private_bytes(self) -> bytes:
        return bytes(self._private_key) if self._private_key else b""

    def get_public_bytes(self) -> bytes:
        return bytes(self.public_key)

    def zeroize(self) -> None:
        if self._private_key:
            try:
                # Convert to mutable bytearray
                key_bytes = bytearray(bytes(self._private_key))
                # Use ctypes to zero memory
                buf = (ctypes.c_char * len(key_bytes)).from_buffer(key_bytes)
                for i in range(len(buf)):
                    buf[i] = 0
            except Exception as e:
                print("[-] Zeroization failed:", str(e))
            finally:
                self._private_key = None


def derive_shared_secret(private_key: bytes, peer_public_key: bytes, verbose: bool = False) -> bytes:
    shared: bytes = crypto_scalarmult(private_key, peer_public_key)
    if verbose:
        print("[v] Derived Shared Secret:", shared.hex())
    return shared


def encrypt(message: bytes, shared_key: bytes, verbose: bool = False) -> bytes:
    if len(shared_key) != 32:
        raise ValueError("Shared key must be 32 bytes")
    box: SecretBox = SecretBox(shared_key)
    encrypted: bytes = box.encrypt(message)
    if verbose:
        print("[v] Nonce Used:", encrypted.nonce.hex())
        print("[v] Ciphertext:", encrypted.ciphertext.hex())
    return encrypted


def decrypt(ciphertext: bytes, shared_key: bytes, verbose: bool = False) -> bytes:
    if len(shared_key) != 32:
        raise ValueError("Shared key must be 32 bytes")
    box: SecretBox = SecretBox(shared_key)
    try:
        decrypted: bytes = box.decrypt(ciphertext)
        if verbose:
            print("[v] Decrypted Message (hex):", decrypted.hex())
        return decrypted
    except CryptoError:
        raise ValueError("Decryption failed")


def constant_time_compare(val1: bytes, val2: bytes) -> bool:
    return hmac.compare_digest(val1, val2)


def hkdf_derive(
    key_material: bytes,
    salt: bytes,
    info: bytes = b'pter',
    length: int = 32,
    verbose: bool = False
) -> bytes:
    if not salt:
        raise ValueError("Salt must not be empty for HKDF")
    prk: bytes = hmac.new(salt, key_material, hashlib.sha256).digest()
    okm: bytes = b""
    prev: bytes = b""
    counter: int = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    derived: bytes = okm[:length]
    if verbose:
        print("[v] Salt:", salt.hex())
        print("[v] HKDF Output:", derived.hex())
    return derived


# ────────────────────────────────────────────────────────────────────────────────
# 🚀 Test Harness (Verbose Mode)
# ────────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    verbose: bool = True
    print("[*] Generating ephemeral keys...")
    alice: EphemeralKeyPair = EphemeralKeyPair(verbose=verbose)
    bob: EphemeralKeyPair = EphemeralKeyPair(verbose=verbose)

    print("[*] Deriving shared secrets...")
    alice_shared: bytes = derive_shared_secret(alice.get_private_bytes(), bob.get_public_bytes(), verbose=verbose)
    bob_shared: bytes = derive_shared_secret(bob.get_private_bytes(), alice.get_public_bytes(), verbose=verbose)

    print("[*] Verifying shared secrets match...")
    assert constant_time_compare(alice_shared, bob_shared), "Shared secrets do not match!"
    print("[+] ECDH key agreement successful.")

    print("[*] Testing HKDF...")
    salt: bytes = random(16)
    key: bytes = hkdf_derive(alice_shared, salt, verbose=verbose)
    assert len(key) == 32
    print("[+] HKDF output OK.")

    print("[*] Encrypting and decrypting a message...")
    message: bytes = b"PTER Protocol test message."
    ciphertext: bytes = encrypt(message, key, verbose=verbose)
    try:
        plaintext: bytes = decrypt(ciphertext, key, verbose=verbose)
        assert plaintext == message
        print("[+] Message decrypted correctly.")
    except Exception as e:
        print("[-] Decryption failed:", str(e))

    print("[*] Zeroizing private key...")
    alice.zeroize()
    print("[+] Done.")
