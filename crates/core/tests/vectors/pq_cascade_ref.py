import hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305

def lp32(b): return struct.pack(">I", len(b)) + b

def prf(key, label, inp, n):                       # crypt_guard::prf::prf
    h = hashlib.shake_256()
    h.update(b"crypt_guard/v3/prf"); h.update(lp32(label)); h.update(lp32(key)); h.update(lp32(inp))
    h.update(struct.pack(">I", n))
    return h.digest(n)

def rotl(x, n): return ((x << n) & 0xffffffff) | (x >> (32 - n))
def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl(s[b], 7)
def hchacha20(key, nonce16):
    s = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        qr(s,0,4,8,12); qr(s,1,5,9,13); qr(s,2,6,10,14); qr(s,3,7,11,15)
        qr(s,0,5,10,15); qr(s,1,6,11,12); qr(s,2,7,8,13); qr(s,3,4,9,14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))
def xchacha_seal(key, n24, aad, pt):
    return ChaCha20Poly1305(hchacha20(key, n24[:16])).encrypt(b"\x00"*4 + n24[16:], pt, aad)

# Selbsttest: draft-irtf-cfrg-xchacha-03 A.3.1
_pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
_ct = xchacha_seal(bytes(range(0x80, 0xa0)), bytes(range(0x40, 0x58)), bytes.fromhex("50515253c0c1c2c3c4c5c6c7"), _pt)
assert _ct[:16].hex() == "bd6d179d3e83d43b9576579493c0e939" and _ct[-16:].hex() == "c0875924c1c7987947deafd8780acf49"

L_IN, L_OUT, L_ONE, L_NONCE, L_RANDOM = (b"crypt_guard/v3/cascade/" + x for x in (b"inner", b"outer", b"single", b"nonce", b"random"))
A_IN, A_OUT, A_ONE = (b"crypt_guard/v3/cascade/aad/" + x for x in (b"inner", b"outer", b"single"))
CASCADE, XCHACHA, AESSIV, CHACHA = 4, 3, 2, 1

def ctxb(scheme, domain): return bytes([scheme]) + lp32(domain)
def nonce_key_unique(root, scheme, domain): return prf(root, L_NONCE, ctxb(scheme, domain), 24)
def nonce_counter(domain_byte, n): return bytes([domain_byte, 0, 0, 0]) + struct.pack(">Q", n) + b"\x00"*12
def nonce_stream(prefix, index, last): return prefix + struct.pack(">I", index) + bytes([1 if last else 0]) + b"\x00"*12

def seal(scheme, root, domain, n24, aad, pt):
    c = ctxb(scheme, domain)
    if scheme == CASCADE:
        inner = AESGCMSIV(prf(root, L_IN, c, 32)).encrypt(n24[:12], pt, A_IN + c + aad)
        return xchacha_seal(prf(root, L_OUT, c, 32), n24, A_OUT + c + aad, inner)
    k = prf(root, L_ONE, c, 32); body = pt + b"\x00"*16
    if scheme == XCHACHA: return xchacha_seal(k, n24, A_ONE + c + aad, body)
    if scheme == AESSIV:  return AESGCMSIV(k).encrypt(n24[:12], body, A_ONE + c + aad)
    if scheme == CHACHA:  return ChaCha20Poly1305(k).encrypt(n24[:12], body, A_ONE + c + aad)

def seal_random(scheme, root, domain, n24, aad, pt):       # Ausgabe: n24 || ct
    dom = L_RANDOM + lp32(domain) + n24
    return n24 + seal(scheme, root, dom, nonce_key_unique(root, scheme, dom), aad, pt)

if __name__ == "__main__":
    root = bytes(range(1, 33)); domain = b"crypt_guard/test/cascade"; aad = b"aad-1"; pt = b"cascade known answer"
    n = nonce_counter(1, 5)
    for s in (CASCADE, XCHACHA, AESSIV, CHACHA): print(s, seal(s, root, domain, n, aad, pt).hex())
    print("key_unique", seal(CASCADE, root, domain, nonce_key_unique(root, CASCADE, domain), aad, pt).hex())
    print("stream", seal(CASCADE, root, domain, nonce_stream(bytes([0,0,0,0,0,0,1]), 3, False), aad, pt).hex())
    print("random", seal_random(CASCADE, root, domain, bytes(range(0xa0, 0xb8)), aad, pt).hex())
