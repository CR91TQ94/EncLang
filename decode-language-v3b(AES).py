import zlib
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

# === Syllables (same set as encryption) ===
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
reverse_lookup = {s: i for i, s in enumerate(syllables)}
sorted_syllables = sorted(syllables, key=lambda s: -len(s))  # Match longest first

# === Crypto ===
def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def aes_decrypt_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)

# === Decoding ===
def chunks_to_bytes(chunks):
    bits = ''.join(f'{c:06b}' for c in chunks)
    byte_strs = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return bytes([int(b, 2) for b in byte_strs if len(b) == 8])

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
    encoded = input("Enter encrypted syllable text: ").strip()
    passphrase = input("Enter passphrase: ").strip()
    nonce_hex = input("Enter 32-char hex nonce: ").strip()

    try:
        nonce = bytes.fromhex(nonce_hex)
        if len(nonce) != 16:
            raise ValueError
    except:
        print("Invalid nonce. Must be 32-character hex string.")
        return

    key = derive_key(passphrase)

    try:
        recovered = decode_from_syllables(encoded)
        decrypted = aes_decrypt_ctr(recovered, key, nonce)
        decompressed = zlib.decompress(decrypted)
        print("\n=== Decrypted Message ===\n", decompressed.decode())
    except Exception as e:
        print("Failed to decrypt:", e)

if __name__ == "__main__":
    run()
