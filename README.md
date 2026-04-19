# ChaCha20-Poly1305 AEAD — Interactive Demo

A visual, interactive desktop application that demonstrates how the **ChaCha20-Poly1305** Authenticated Encryption with Associated Data (AEAD) algorithm works — including encryption, MAC generation, tampering simulation, and tamper detection.

Built as a **Network Security course project**.

---

## What Is ChaCha20-Poly1305?

ChaCha20-Poly1305 is a modern AEAD cipher that provides two guarantees at once:

| Property | Provided by |
|---|---|
| **Confidentiality** — no one can read the message | ChaCha20 stream cipher |
| **Integrity & Authenticity** — no one can modify it undetected | Poly1305 MAC |

### How It Works

```
SENDER                                         RECEIVER
──────                                         ────────
Plaintext                                      Wire Packet
    │                                               │
    ▼                                               ▼
ChaCha20 (key + nonce)  ──► Ciphertext      Split: nonce │ ciphertext │ MAC
                                │                   │
Poly1305 (key + nonce)  ──► MAC (16 bytes)  Recompute MAC
                                │                   │
    nonce ──────────────────────┤            Compare MACs
    ciphertext ─────────────────┤                   │
    MAC ────────────────────────┘          ✓ Match → Decrypt
                                           ✗ Mismatch → REJECT
```

**Key properties:**
- The **nonce** (12 bytes) must be unique for every message encrypted with the same key. Reusing it breaks security.
- The **MAC** (16 bytes) is computed over the ciphertext. Any single flipped bit in the packet causes MAC verification to fail — the message is silently dropped.
- The **key** (32 bytes) is never transmitted. Both sides must share it in advance (or via a key exchange protocol like Diffie-Hellman).

---

## Project Structure

```
.
├── crypto_logic.py   # Pure cryptographic logic — no GUI dependencies
└── gui_app.py        # Tkinter desktop application
```

### `crypto_logic.py`
Contains all cryptographic operations:
- `generate_key()` — produces a random 256-bit secret key
- `generate_nonce()` — produces a random 96-bit nonce
- `encrypt_message(plaintext, key)` — encrypts and returns all components
- `decrypt_message(transmitted, key)` — verifies MAC then decrypts
- `tamper_ciphertext(transmitted)` — flips a bit to simulate an attacker
- `bytes_to_hex(data)` — display helper

### `gui_app.py`
Interactive three-panel desktop UI:
- **SENDER panel** — type a message, encrypt it, see the key / nonce / ciphertext / MAC and the full wire packet in hex
- **CHANNEL panel** — simulate an attacker flipping a bit in the ciphertext mid-transit
- **RECEIVER panel** — decrypt and verify; see whether authentication passed or failed

---

## Requirements

- Python **3.8+**
- [`cryptography`](https://pypi.org/project/cryptography/) library
- Tkinter (included with standard Python on Windows and macOS; see below for Linux)

---

## Installation & Running

### 1. Clone the repository

```bash
git clone https://github.com/your-username/chacha20-poly1305-demo.git
cd chacha20-poly1305-demo
```

### 2. Install the dependency

```bash
pip install cryptography
```

> On Linux you may also need Tkinter:
> ```bash
> sudo apt install python3-tk   # Debian / Ubuntu
> ```

### 3. Run the application

```bash
python gui_app.py
```

---

## How to Use the Demo

1. **Type** a message in the *Plaintext Message* box on the left (or keep the default).
2. Click **Encrypt →** — the sender panel fills with the key, nonce, ciphertext, MAC, and the full wire packet in hex.
3. Click **← Decrypt & Verify** — the receiver authenticates and decrypts the packet. You should see *Authentication PASSED* and the original message recovered.
4. Click **☠ Tamper** in the middle channel panel — this flips one bit in the ciphertext, simulating an attacker modifying the message in transit.
5. Click **← Decrypt & Verify** again — this time you will see *Authentication FAILED* and the message is rejected. Decryption is never attempted.
6. Click **↺ Reset** to restore the original packet and repeat.

---

## What the Demo Teaches

- Why **authenticated encryption** is stronger than encryption alone — an attacker can flip bits in a ciphertext even without knowing the key, but the MAC catches it.
- Why the **nonce must be random and unique** — it is sent in the clear alongside the ciphertext and is required for decryption.
- The exact **wire format**: `[ 12-byte nonce | ciphertext | 16-byte MAC ]`
- How a **single flipped bit** anywhere in the ciphertext produces a completely different MAC and causes immediate rejection.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | ≥ 3.0 | ChaCha20-Poly1305 AEAD via `cryptography.hazmat` |
| `tkinter` | stdlib | Desktop GUI |

---

## References

- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
- [Python `cryptography` library docs](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- D.J. Bernstein — *ChaCha, a variant of Salsa20* (2008)
