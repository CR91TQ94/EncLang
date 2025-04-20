import os
import base64
import random
import hashlib
import zlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# === Syllables ===
syllables = [
    "ba", "be", "bi", "bo", "bu", "ca", "ce", "ci",
    "co", "cu", "da", "de", "di", "do", "du", "fa",
    "fe", "fi", "fo", "fu", "ga", "ge", "gi", "go",
    "gu", "ha", "he", "hi", "ho", "hu", "la", "le",
    "li", "lo", "lu", "ma", "me", "mi", "mo", "mu",
    "na", "ne", "ni", "no", "nu", "pa", "pe", "pi",
    "po", "pu", "ra", "re", "ri", "ro", "ru", "sa",
    "se", "si", "so", "su", "ta", "te", "ti", "to"
]

syllable_lookup = {i: s for i, s in enumerate(syllables)}
reverse_lookup = {s: i for i, s in enumerate(syllables)}

# === Utils ===

def derive_key_from_passphrase(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def get_key_from_input():
    key_input = input("Enter 64-character hex key (or leave blank to use default passphrase): ").strip()
    if key_input:
        try:
            key_bytes = bytes.fromhex(key_input)
            if len(key_bytes) != 32:
                raise ValueError
            return key_bytes
        except:
            raise ValueError("Invalid key. Must be 64-character hex string.")
    else:
        passphrase = "secret password"
        print(f"Using SHA-256 of default passphrase: '{passphrase}'")
        return derive_key_from_passphrase(passphrase)

def get_nonce_from_input():
    nonce_input = input("Enter 24-character hex nonce (or leave blank for random): ").strip()
    if nonce_input:
        try:
            nonce_bytes = bytes.fromhex(nonce_input)
            if len(nonce_bytes) != 12:
                raise ValueError
            return nonce_bytes
        except:
            raise ValueError("Invalid nonce. Must be 24-character hex string.")
    else:
        return os.urandom(12)

# === Crypto ===

def encrypt(plaintext: bytes, key: bytes, nonce: bytes):
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt(ciphertext: bytes, key: bytes):
    nonce = ciphertext[:12]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext[12:], None)

# === Encoding ===

def bytes_to_6bit_chunks(data: bytes):
    bitstream = ''.join(f'{byte:08b}' for byte in data)
    chunks = [bitstream[i:i+6] for i in range(0, len(bitstream), 6)]
    if len(chunks[-1]) < 6:
        chunks[-1] = chunks[-1].ljust(6, '0')
    return [int(chunk, 2) for chunk in chunks]

def chunks_to_bytes(chunks):
    bitstream = ''.join(f'{chunk:06b}' for chunk in chunks)
    byte_chunks = [bitstream[i:i+8] for i in range(0, len(bitstream), 8)]
    return bytes([int(b, 2) for b in byte_chunks if len(b) == 8])

def encode_to_fake_language(data: bytes):
    sixbit_chunks = bytes_to_6bit_chunks(data)
    syllable_seq = [syllable_lookup[chunk] for chunk in sixbit_chunks]
    words = []
    i = 0
    while i < len(syllable_seq):
        group_len = random.randint(1, 3)  # Max 3 syllables per word, min 1
        word = ''.join(syllable_seq[i:i+group_len])
        words.append(word)
        i += group_len
    return ' '.join(words)

def decode_from_fake_language(text: str):
    all_syllables = set(syllables)
    text = text.replace(" ", "").lower()
    i = 0
    decoded = []
    while i < len(text):
        matched = False
        for length in range(4, 0, -1):  # Try matching syllables of length 4, 3, 2, or 1
            syl = text[i:i+length]
            if syl in all_syllables:
                decoded.append(reverse_lookup[syl])
                i += length
                matched = True
                break
        if not matched:
            print(f"ERROR Skipping invalid syllable at position {i}: {text[i:i+4]}")
            i += 1  # Skip the invalid syllable and continue
    return chunks_to_bytes(decoded)

# === Main ===

if __name__ == "__main__":
    try:
        key = get_key_from_input()
        nonce = get_nonce_from_input()

        message = input("\nEnter message to encrypt: ").encode()

        # Compress plaintext before encryption
        compressed_message = zlib.compress(message)
        print(f" Compressed plaintext (size {len(compressed_message)} bytes)")

        # Encrypt → Encode
        encrypted = encrypt(compressed_message, key, nonce)
        encoded_text = encode_to_fake_language(encrypted)
        print("\n Encrypted QUASI LANGUAGE:\n" + encoded_text)

        # Decode → Decrypt
        recovered = decode_from_fake_language(encoded_text)
        decrypted = decrypt(recovered, key)

        # Decompress after decryption
        decompressed_message = zlib.decompress(decrypted)
        print("\n Decrypted and Decompressed:\n" + decompressed_message.decode())

        # Output key and nonce
        print("\n KEY (hex):", key.hex())
        print("NONCE (hex):", nonce.hex())

    except Exception as e:
        print("Error:", e)
