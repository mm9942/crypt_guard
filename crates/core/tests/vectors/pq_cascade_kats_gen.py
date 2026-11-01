# Generator of pq-cascade-kats.json (known-answer vectors for crypt_guard's `pq_cascade`
# and the cascade variant of `pq_multi`).
#
# The first part is the reference model of Anhang A of the comnet
# docs/plans/cipher-suite-contract.md, unchanged (the same text as pq_cascade_ref.py);
# the second part builds the vector set from it and cross-checks the numbers printed in
# section 2.2.6 of the contract and the prf KAT of prf.rs before printing.
#
# Usage (needs Python 3 and the `cryptography` package; prints JSON on stdout):
#   python3 -I pq_cascade_kats_gen.py > pq-cascade-kats.json
#   sha256sum pq-cascade-kats.json     # must equal the entry in SHA256SUMS
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


# ---------------------------------------------------------------------------
# Vector generator (worker for crates/core/tests/vectors/pq-cascade-kats.json)
# ---------------------------------------------------------------------------
import json, sys

SCHEMES = [(CASCADE, "Cascade"), (XCHACHA, "XChaCha20Poly1305"), (AESSIV, "Aes256GcmSiv"), (CHACHA, "ChaCha20Poly1305")]

def counter_n24(domain_byte, n): return nonce_counter(domain_byte, n)

def make_case(name, root, domain, aad, pt):
    case = {
        "name": name,
        "root": root.hex(),
        "domain": domain.hex(),
        "domain_text": domain.decode("ascii"),
        "aad": aad.hex(),
        "pt": pt.hex(),
    }
    sub = {}
    for sid, sname in SCHEMES:
        c = ctxb(sid, domain)
        sub[str(sid)] = {
            "scheme": sname,
            "ctx": c.hex(),
            "k_in": prf(root, L_IN, c, 32).hex(),
            "k_out": prf(root, L_OUT, c, 32).hex(),
            "k_one": prf(root, L_ONE, c, 32).hex(),
            "nonce_once": nonce_key_unique(root, sid, domain).hex(),
        }
    case["subkeys"] = sub
    vecs = []
    for sid, sname in SCHEMES:
        # counter mode: two nonces, including a >32-bit counter
        for dom_byte, n in ((0x01, 5), (0x02, 0x0102030405060708)):
            n24 = nonce_counter(dom_byte, n)
            vecs.append({"id": f"counter/{sname}/{dom_byte}/{n}", "scheme": sid, "mode": "counter",
                         "domain_byte": dom_byte, "n": str(n), "n24": n24.hex(),
                         "ct": seal(sid, root, domain, n24, aad, pt).hex()})
        # derived-nonce one-shot
        n24 = nonce_key_unique(root, sid, domain)
        vecs.append({"id": f"once/{sname}", "scheme": sid, "mode": "once", "n24": n24.hex(),
                     "ct": seal(sid, root, domain, n24, aad, pt).hex()})
        # stream mode: non-final and final, two prefixes, large index
        for prefix, index, last in ((bytes([0,0,0,0,0,0,1]), 3, False),
                                    (bytes([0,0,0,0,0,0,1]), 3, True),
                                    (bytes([9,8,7,6,5,4,3]), 0xffffffff, True),
                                    (bytes([9,8,7,6,5,4,3]), 0, False)):
            n24 = nonce_stream(prefix, index, last)
            vecs.append({"id": f"stream/{sname}/{prefix.hex()}/{index}/{'last' if last else 'more'}",
                         "scheme": sid, "mode": "stream", "prefix": prefix.hex(), "index": index,
                         "last": last, "n24": n24.hex(),
                         "ct": seal(sid, root, domain, n24, aad, pt).hex()})
        # random mode (fixed n24 so it is a known answer for open_random)
        rn = bytes(range(0xa0, 0xb8))
        vecs.append({"id": f"random/{sname}", "scheme": sid, "mode": "random", "n24": rn.hex(),
                     "sealed": seal_random(sid, root, domain, rn, aad, pt).hex()})
    case["vectors"] = vecs
    return case

root_main = bytes(range(1, 33))
cases = [
    make_case("main", root_main, b"crypt_guard/test/cascade", b"aad-1", b"cascade known answer"),
    make_case("empty", bytes([0xa5]*32), b"comnet/session/frame/v1", b"", b""),
    make_case("long", bytes((i*7+11) % 255 + 1 for i in range(32)), b"comnet/store/value/v2",
              bytes((i*3+1) % 256 for i in range(100)), bytes((i*7+3) % 256 for i in range(300))),
]

# Cross-check against the numbers printed in section 2.2.6 of the contract.
main = cases[0]
by_id = {v["id"]: v for v in main["vectors"]}
assert main["subkeys"]["4"]["k_in"]  == "29eecf9a61cb966250a804b1e531c86ace2802ab217d9a1b8800d74a3cef0292"
assert main["subkeys"]["4"]["k_out"] == "0b6df53cdb3e6329fe08c6fe5407857f7e29b8d36f26315da007695562b214f9"
assert main["subkeys"]["4"]["k_one"] == "583d269f6ab03d2bcadf39dd2fbd9abd774c26f143df0ce9c6f972e9389589bd"
assert main["subkeys"]["3"]["k_one"] == "58d81669dd4795a3b6a4da233d5457f79b593db66e6255e74776987d035f0b2a"
assert main["subkeys"]["2"]["k_one"] == "2102f5469119816ad0d688e01cc989dca845c9218b012a48509ce5a5ebcd5a7c"
assert main["subkeys"]["1"]["k_one"] == "36ff7bfbe6df1ee33b991468ce48b8b1a2001e47ceb6a318e4debb7c4f007195"
assert main["subkeys"]["4"]["nonce_once"] == "e0fbac1160eeeec3cdf30d68d18a7586b88e68d6be2858af"
assert by_id["counter/Cascade/1/5"]["n24"] == "010000000000000000000005000000000000000000000000"
assert by_id["counter/Cascade/1/5"]["ct"] == "71b3d7c5e2cc0ec27edec4dd0949e0039d80207ee810c95567adb765640b7c1a79b269fe0bba036e20b52090685895bbe46fc06b"
assert by_id["counter/XChaCha20Poly1305/1/5"]["ct"] == "432f81fce4584c0be14cc6e5641387f84f21c702fb8ce953256ab62e90e182ff7c3f16972f93fd002116bb28f25953f67e36778c"
assert by_id["counter/Aes256GcmSiv/1/5"]["ct"] == "b6428725da3ab72ca71605ae5c0e93fd9e8729215eff00d1c88dbd2c03649960632d737c8a28c82812d90adce5a5db899b5fc2f5"
assert by_id["counter/ChaCha20Poly1305/1/5"]["ct"] == "975ab325c73f69cf5e2633291eb9d7384a7b4893189aa5e581391226b9ed33f89dea2a5784b25164f3e542f1ec3c52d9ef4ecc4c"
assert by_id["once/Cascade"]["ct"] == "a649da40579f391994babd7f2ebef1217b13efe922f5cf6c61ff6723237ff270c0e65d57be1c5d7107dad7fe419dc59ccc362f10"
assert by_id["stream/Cascade/00000000000001/3/more"]["n24"] == "000000000000010000000300000000000000000000000000"
assert by_id["stream/Cascade/00000000000001/3/more"]["ct"] == "1af3e77dec051584db464a63a695e45d63d1eb26835926adca9508b0bfa12878d6d2093f2d80cd13c032e4af8c1b63604010f18b"
assert by_id["stream/Cascade/00000000000001/3/last"]["ct"] == "1ce90b5ed61e3be892e424ae37b90dca8041e4ccffd3b8b12707a4b6abb1e346a09202e1de2a5ff3452270d8d91de6de73fe0dcf"
assert by_id["random/Cascade"]["sealed"] == "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7057f374419c4fdc4aae3e6a494831e67db98e6ef20e3f00f27501fbaf827112c2df118fa802cc302a0f0e41019ab7084def2c80d"
# prf KAT from crates/core/src/prf.rs / tests/m0_ext_primitives.rs
assert prf(bytes(range(32)), b"mailbox-id", b"alice@example", 32).hex() == "86124c8b9d90980fc84e7f8a9c31a11318e1ed7439ab4dae5d6b9eefb60b487b"
# every ciphertext is plaintext + 32
for c in cases:
    ptl = len(bytes.fromhex(c["pt"]))
    for v in c["vectors"]:
        l = len(bytes.fromhex(v["ct"] if "ct" in v else v["sealed"]))
        assert l == ptl + 32 + (24 if v["mode"] == "random" else 0), v["id"]
# k_one(4) is distinct from k_in / k_out
assert main["subkeys"]["4"]["k_one"] not in (main["subkeys"]["4"]["k_in"], main["subkeys"]["4"]["k_out"])


# ---------------------------------------------------------------------------
# Negative known answers (main case inputs): ciphertexts that are well formed
# AEAD output of a *wrong* construction and must be rejected by open().
# ---------------------------------------------------------------------------
def negatives():
    root, domain, aad, pt = root_main, b"crypt_guard/test/cascade", b"aad-1", b"cascade known answer"
    n24 = nonce_counter(1, 5)
    out = []
    def add(nid, scheme, why, ct):
        out.append({"id": nid, "scheme": scheme, "mode": "counter", "domain_byte": 1, "n": "5",
                    "n24": n24.hex(), "why": why, "ct": ct.hex()})
    # single-layer schemes: the 16 filler bytes inside the AEAD must be zero
    for sid, sname in ((XCHACHA, "XChaCha20Poly1305"), (AESSIV, "Aes256GcmSiv"), (CHACHA, "ChaCha20Poly1305")):
        c = ctxb(sid, domain); k = prf(root, L_ONE, c, 32)
        for label, filler in (("first_byte", b"\x01" + b"\x00"*15), ("last_byte", b"\x00"*15 + b"\x01"), ("all_ff", b"\xff"*16)):
            body = pt + filler
            if sid == XCHACHA: ct = xchacha_seal(k, n24, A_ONE + c + aad, body)
            elif sid == AESSIV: ct = AESGCMSIV(k).encrypt(n24[:12], body, A_ONE + c + aad)
            else: ct = ChaCha20Poly1305(k).encrypt(n24[:12], body, A_ONE + c + aad)
            add(f"filler_nonzero/{sname}/{label}", sid, "authentic AEAD output whose filler is not zero", ct)
        # no filler at all (a bare single-layer ciphertext of |pt|+16 bytes is too short / wrong)
        if sid == XCHACHA: ct = xchacha_seal(k, n24, A_ONE + c + aad, pt)
        elif sid == AESSIV: ct = AESGCMSIV(k).encrypt(n24[:12], pt, A_ONE + c + aad)
        else: ct = ChaCha20Poly1305(k).encrypt(n24[:12], pt, A_ONE + c + aad)
        add(f"no_filler/{sname}", sid, "authentic AEAD output without the 16 filler bytes", ct)
    # Cascade: build wrong-but-authentic constructions
    c = ctxb(CASCADE, domain)
    k_in, k_out = prf(root, L_IN, c, 32), prf(root, L_OUT, c, 32)
    good_inner = AESGCMSIV(k_in).encrypt(n24[:12], pt, A_IN + c + aad)
    bad_inner = bytearray(good_inner); bad_inner[3] ^= 0x01
    add("cascade/inner_corrupt_outer_valid", CASCADE, "outer layer valid, inner ciphertext has a flipped bit",
        xchacha_seal(k_out, n24, A_OUT + c + aad, bytes(bad_inner)))
    add("cascade/inner_wrong_aad_outer_valid", CASCADE, "outer valid, inner AAD lacks the caller aad",
        xchacha_seal(k_out, n24, A_OUT + c + aad, AESGCMSIV(k_in).encrypt(n24[:12], pt, A_IN + c)))
    add("cascade/layer_keys_swapped", CASCADE, "inner under k_out, outer under k_in",
        xchacha_seal(k_in, n24, A_OUT + c + aad, AESGCMSIV(k_out).encrypt(n24[:12], pt, A_IN + c + aad)))
    inner_x = xchacha_seal(k_in, n24, A_IN + c + aad, pt)
    add("cascade/layer_order_swapped", CASCADE, "XChaCha20-Poly1305 inside, AES-256-GCM-SIV outside",
        AESGCMSIV(k_out).encrypt(n24[:12], inner_x, A_OUT + c + aad))
    add("cascade/outer_only", CASCADE, "single outer layer over pt || 0^16, no inner layer",
        xchacha_seal(k_out, n24, A_OUT + c + aad, pt + b"\x00"*16))
    add("cascade/inner_only", CASCADE, "single inner layer over pt || 0^16, no outer layer",
        AESGCMSIV(k_in).encrypt(n24[:12], pt + b"\x00"*16, A_IN + c + aad))
    add("cascade/swapped_aad_prefixes", CASCADE, "inner uses A_OUT, outer uses A_IN",
        xchacha_seal(k_out, n24, A_IN + c + aad, AESGCMSIV(k_in).encrypt(n24[:12], pt, A_OUT + c + aad)))
    # Cascade ciphertext built for another scheme id in ctx (scheme byte substituted)
    c1 = ctxb(CHACHA, domain)
    add("cascade/ctx_scheme_byte_substituted", CASCADE, "all keys/AAD derived with scheme id 1 instead of 4",
        xchacha_seal(prf(root, L_OUT, c1, 32), n24, A_OUT + c1 + aad,
                     AESGCMSIV(prf(root, L_IN, c1, 32)).encrypt(n24[:12], pt, A_IN + c1 + aad)))
    return out

doc = {
    "source": "Reference model of Anhang A (docs/plans/cipher-suite-contract.md in the comnet repository), run with python3 -I; same text as crates/core/tests/vectors/pq_cascade_ref.py. Regenerate with that model; do not edit by hand.",
    "contract_sections": ["2.2.3", "2.2.6", "Anhang A"],
    "format": "all binary values are lowercase hex; ct = AEAD output, |ct| = |pt| + 32; sealed = n24 || ct (random mode); domain_byte/n/index are decimal (n is a string to carry the full u64)",
    "labels": {
        "L_IN": L_IN.decode(), "L_OUT": L_OUT.decode(), "L_ONE": L_ONE.decode(),
        "L_NONCE": L_NONCE.decode(), "L_RANDOM": L_RANDOM.decode(),
        "A_IN": A_IN.decode(), "A_OUT": A_OUT.decode(), "A_ONE": A_ONE.decode(),
    },
    "primitive_selftest": {
        "xchacha20_poly1305_draft_irtf_cfrg_xchacha_03_a31": {
            "key": bytes(range(0x80, 0xa0)).hex(),
            "nonce": bytes(range(0x40, 0x58)).hex(),
            "aad": "50515253c0c1c2c3c4c5c6c7",
            "ct_first16": "bd6d179d3e83d43b9576579493c0e939",
            "tag": "c0875924c1c7987947deafd8780acf49",
        }
    },
    "negatives": negatives(),
    "cases": cases,
}
json.dump(doc, sys.stdout, indent=1, sort_keys=False)
sys.stdout.write("\n")
