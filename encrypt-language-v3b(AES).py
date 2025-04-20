import os
import zlib
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

# === Syllables (64 Latin-esque, mixed lengths, no J Y W K) ===
syllables = [
    "cre", "do", "in", "u", "num", "de", "um", "pa",
    "tre", "om", "ni", "po", "ten", "tem", "fac", "to",
    "rem", "cae", "li", "et", "ter", "rae", "vi", "si",
    "bi", "mi", "ie", "sum", "chri", "stum", "fi", "i",
    "ge", "ex", "na", "tum", "an", "te", "a", "sae",
    "cu", "lu", "men", "ne", "ve", "rum", "ro", "non",
    "con", "sub", "stan", "ti", "lem", "tri", "per", "quem",
    "sun", "qui", "prop", "no", "sa", "scen", "dit", "lis"
]
syllable_lookup = {i: s for i, s in enumerate(syllables)}
reverse_lookup = {s: i for i, s in enumerate(syllables)}
sorted_syllables = sorted(syllables, key=lambda s: -len(s))  # longest first for decoding

# === Crypto ===
def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def aes_encrypt_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(data)

def aes_decrypt_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)

# === Encoding/Decoding ===
def bytes_to_6bit_chunks(data: bytes):
    bits = ''.join(f'{byte:08b}' for byte in data)
    chunks = [bits[i:i+6].ljust(6, '0') for i in range(0, len(bits), 6)]
    return [int(c, 2) for c in chunks]

def chunks_to_bytes(chunks):
    bits = ''.join(f'{c:06b}' for c in chunks)
    byte_strs = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return bytes([int(b, 2) for b in byte_strs if len(b) == 8])

def encode_to_syllables(data: bytes):
    chunks = bytes_to_6bit_chunks(data)
    seq = [syllable_lookup[c] for c in chunks]
    words = []
    i = 0
    while i < len(seq):
        r = random.random()
        group_len = (
            1 if r < 0.2 else
            2 if r < 0.6 else
            3 if r < 0.85 else 4
        )
        word = ''.join(seq[i:i+group_len])
        words.append(word)
        i += group_len
    return ' '.join(words)

def decode_from_syllables(text: str):
    text = text.replace(" ", "")
    i, chunks = 0, []
    while i < len(text):
        matched = False
        for syl in sorted_syllables:
            if text.startswith(syl, i):
                chunks.append(reverse_lookup[syl])
                i += len(syl)
                matched = True
                break
        if not matched:
            raise ValueError(f"Unknown syllable at position {i}: {text[i:i+4]}")
    return chunks_to_bytes(chunks)

# === Main ===
def run():
    message = input("Enter message to encrypt: ").strip().encode()
    passphrase = input("Enter passphrase: ").strip()
    key = derive_key(passphrase)

    nonce_input = input("Enter 32-char hex nonce (or leave blank to generate): ").strip()
    if nonce_input:
        try:
            nonce = bytes.fromhex(nonce_input)
            if len(nonce) != 16:
                raise ValueError
        except:
            print("Invalid nonce, must be 32 hex characters.")
            return
    else:
        nonce = os.urandom(16)

    compressed = zlib.compress(message)
    encrypted = aes_encrypt_ctr(compressed, key, nonce)
    encoded = encode_to_syllables(encrypted)

    print("\n=== Encrypted Quasi Language ===\n", encoded)
    print("\nKey (hex):", key.hex())
    print("Nonce (hex):", nonce.hex())

    # Optional: Test decoding immediately
    try:
        recovered = decode_from_syllables(encoded)
        decrypted = aes_decrypt_ctr(recovered, key, nonce)
        decompressed = zlib.decompress(decrypted)
        print("\n=== Decrypted Message ===\n", decompressed.decode())
    except Exception as e:
        print("Decryption test failed:", e)

if __name__ == "__main__":
    run()
