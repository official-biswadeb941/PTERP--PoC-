#For now PTER Protocol will be written in python and it will shifted to rust after I get a stable outcome. 

Post-Trust Ephemeral Relay Protocol (PTER Protocol)
|
├── pyproject.toml                  # Project metadata (if using Poetry or PEP 621)
├── setup.py                        # If using setuptools
├── requirements.txt                # Dependency declarations (e.g., pynacl, scapy)
|
├── pter/                           # Core library package
│   ├── __init__.py                 # Makes `pter` a package
│
│   ├── layer2/                     # L2: Ethernet/ARP
│   │   ├── __init__.py
│   │   ├── interface.py            # Raw socket (AF_PACKET or equivalent)
│   │   └── ethernet.py             # Frame creation/parsing
│
│   ├── layer3/                     # L3: IP packet crafting
│   │   ├── __init__.py
│   │   ├── ipv4.py                 # Custom IP header struct / crafting
│   │   └── checksum.py             # IP checksum, header utilities
│
│   ├── layer4/                     # L4: PTER Protocol logic
│   │   ├── __init__.py
│   │   ├── packet.py               # `PTERPacket` frame structure
│   │   ├── handshake.py            # Ephemeral key exchange
│   │   └── relay.py                # Stateless transport engine
│
│   ├── utils/                      # Shared utility modules
│   │   ├── __init__.py
│   │   ├── crypto.py               # Curve25519
│   │   ├── memory.py               # Volatile memory buffers, zeroing
│   │   └── obfuscation.py          # Header morphing, mimicry (future)
│
│   └── main.py                     # CLI stub or test runner
