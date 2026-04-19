"""
crypto_logic.py
---------------
Pure cryptographic logic for ChaCha20-Poly1305 AEAD encryption.
Uses the standard `cryptography` library (pip install cryptography).
No GUI dependencies — can be imported or tested independently.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """Generate a random 256-bit (32-byte) secret key."""
    return os.urandom(32)


def generate_nonce() -> bytes:
    """Generate a random 96-bit (12-byte) nonce (must be unique per message)."""
    return os.urandom(12)


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt_message(plaintext: str, key: bytes) -> dict:
    """
    Encrypt *plaintext* with ChaCha20-Poly1305.

    Returns a dict with:
        nonce       - bytes  - random nonce used
        ciphertext  - bytes  - raw ciphertext (without the tag)
        mac         - bytes  - 128-bit Poly1305 authentication tag
        transmitted - bytes  - nonce + ciphertext + tag (what travels over the wire)
        key         - bytes  - the secret key (kept local, never transmitted)
    """
    nonce = generate_nonce()
    chacha = ChaCha20Poly1305(key)

    # The cryptography library appends the 16-byte Poly1305 tag at the end
    full_output = chacha.encrypt(nonce, plaintext.encode("utf-8"), None)

    ciphertext  = full_output[:-16]   # everything except last 16 bytes
    mac         = full_output[-16:]   # last 16 bytes = Poly1305 tag
    transmitted = nonce + full_output

    return {
        "nonce":       nonce,
        "ciphertext":  ciphertext,
        "mac":         mac,
        "transmitted": transmitted,
        "key":         key,
    }


# ---------------------------------------------------------------------------
# Tampering (educational demo only)
# ---------------------------------------------------------------------------

def tamper_ciphertext(transmitted: bytes) -> bytes:
    """
    Flip all bits in byte 12 of *transmitted* (first byte of ciphertext)
    to simulate an attacker modifying the message in transit.

    Layout: 12-byte nonce | ciphertext | 16-byte MAC
    """
    data = bytearray(transmitted)
    data[12] ^= 0xFF          # flip first ciphertext byte
    return bytes(data)


# ---------------------------------------------------------------------------
# Decryption & verification
# ---------------------------------------------------------------------------

def decrypt_message(transmitted: bytes, key: bytes) -> dict:
    """
    Authenticate and decrypt *transmitted*.

    Layout: 12-byte nonce | ciphertext | 16-byte MAC

    Returns a dict:
        success        - bool  - True if MAC verified and decryption succeeded
        plaintext      - str   - recovered plaintext (empty on failure)
        received_mac   - bytes - MAC extracted from the packet
        mac_match      - bool  - True if authentication passed
        error          - str   - human-readable error (empty on success)
    """
    nonce               = transmitted[:12]
    ciphertext_with_tag = transmitted[12:]
    received_mac        = ciphertext_with_tag[-16:]

    chacha = ChaCha20Poly1305(key)

    try:
        # decrypt() raises InvalidTag automatically if MAC does not match
        plaintext_bytes = chacha.decrypt(nonce, ciphertext_with_tag, None)

        return {
            "success":      True,
            "plaintext":    plaintext_bytes.decode("utf-8"),
            "received_mac": received_mac,
            "mac_match":    True,
            "error":        "",
        }

    except Exception as exc:
        return {
            "success":      False,
            "plaintext":    "",
            "received_mac": received_mac,
            "mac_match":    False,
            "error": (
                "Authentication FAILED - MAC mismatch detected!\n"
                "The message has been tampered with and was REJECTED.\n"
                f"({type(exc).__name__})"
            ),
        }


# ---------------------------------------------------------------------------
# Display helper
# ---------------------------------------------------------------------------

def bytes_to_hex(data: bytes, sep: str = " ") -> str:
    """Return *data* as an uppercase hex string separated by *sep*."""
    return sep.join(f"{b:02X}" for b in data)