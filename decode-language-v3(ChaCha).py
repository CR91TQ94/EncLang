import os
import hashlib
import zlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# === Syllables ===
syllables = [
    "cre", "do", "in", "u", "num", "de", "um", "pa",
    "trem", "om", "ni", "po", "ten", "tem", "fac", "to",
    "rem", "cae", "li", "et", "ter", "rae", "vi", "si",
    "bi", "mi", "ie", "sum", "chri", "stum", "fi", "i",
    "ge", "ex", "na", "tum", "an", "te", "a", "sae",
    "cu", "lu", "men", "ne", "ve", "rum", "ro", "non",
    "con", "sub", "stan", "ti", "lem", "tri", "per", "quem",
    "sun", "qui", "prop", "no", "sa", "scen", "dit", "lis"
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

        encoded_text = input("\n Enter the encrypted fake language text: ")

        # Decode the fake language into encrypted ciphertext
        recovered = decode_from_fake_language(encoded_text)

        # Decrypt the ciphertext
        decrypted = decrypt(recovered, key)

        # Decompress after decryption
        decompressed_message = zlib.decompress(decrypted)

        print("\n Decrypted and Decompressed Message:\n" + decompressed_message.decode())

        # Output key and nonce
        print("\n Key (hex):", key.hex())
        print("Nonce (hex):", nonce.hex())

    except Exception as e:
        print("ERROR:", e)
