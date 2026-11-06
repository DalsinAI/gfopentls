#!/usr/bin/env python3
"""GFOpenCrypto against Python's cryptography package (OpenSSL underneath) on
random inputs: X25519, Ed25519 (good and altered signatures), ChaCha20,
Poly1305, AES (CTR, CBC, ECB; 128, 192, 256), RSA's public operation
(2048, 3072, 4096 bits), ECDSA (P-256, P-384, P-521; good and altered),
SHA-1, SHA-256, SHA-512, and sntrup761 round trips; and since 2.4 HMAC and
PBKDF2 over SHA-1/256/384/512, SHA-3 and SHAKE256, Argon2id, Ed25519 and
deterministic (RFC 6979) ECDSA signatures byte for byte, EC key generation,
modular exponentiation, RSA's private operation and the prime test.
  python3 tests/differential.py OC_CLI [ROUNDS]
Copyright (c) 2026 AmiCradle Team. MIT."""
import hashlib, hmac, os, random, subprocess, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives import serialization

cli = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 200
H = lambda b: b.hex() if b else "-"
fails, counts = 0, {}
ORDERS = {256: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
          384: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
          521: 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409}

def ask(*words):
    cli.stdin.write(" ".join(words) + "\n")
    cli.stdin.flush()
    return cli.stdout.readline().strip()

def check(name, ok, detail=""):
    global fails
    counts[name] = counts.get(name, 0) + 1
    if not ok:
        fails += 1
        print("FAIL", name, detail)

raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
for i in range(rounds):
    # X25519
    k, u = os.urandom(32), x25519.X25519PrivateKey.generate().public_key().public_bytes(*raw)
    want = x25519.X25519PrivateKey.from_private_bytes(k).exchange(x25519.X25519PublicKey.from_public_bytes(u))
    check("X25519", ask("x25519", H(k), H(u)) == want.hex())
    # Ed25519
    sk = ed25519.Ed25519PrivateKey.generate()
    msg = os.urandom(random.randrange(0, 300))
    sig = sk.sign(msg)
    pk = sk.public_key().public_bytes(*raw)
    check("Ed25519 good", ask("ed25519", H(sig), H(pk), H(msg)) == "1")
    bad = bytearray(sig); bad[random.randrange(64)] ^= 1 << random.randrange(8)
    check("Ed25519 altered", ask("ed25519", H(bytes(bad)), H(pk), H(msg)) == "0")
    # ChaCha20 (Python's 16-byte nonce is the 64-bit counter, little-endian, then the 64-bit nonce)
    key, nonce, ctr = os.urandom(32), os.urandom(8), random.randrange(0, 2**40)
    data = os.urandom(random.randrange(0, 500))
    enc = Cipher(algorithms.ChaCha20(key, ctr.to_bytes(8, "little") + nonce), None).encryptor().update(data)
    check("ChaCha20", ask("chacha", H(key), H(nonce), "%x" % ctr, H(data)) == (enc.hex() or "-"))
    # Poly1305
    pkey = os.urandom(32)
    check("Poly1305", ask("poly", H(pkey), H(data)) == Poly1305.generate_tag(pkey, data).hex())
    # AES
    for kl in (16, 24, 32):
        key, iv = os.urandom(kl), os.urandom(16)
        blocks = os.urandom(16 * random.randrange(1, 12))
        odd = os.urandom(random.randrange(1, 200))
        want = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(odd)
        check("AES-CTR", ask("aes", "0", H(key), H(iv), H(odd)) == want.hex())
        want = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(blocks)
        check("AES-CBC encrypt", ask("aes", "1", H(key), H(iv), H(blocks)) == want.hex())
        want = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(blocks)
        check("AES-CBC decrypt", ask("aes", "2", H(key), H(iv), H(blocks)) == want.hex())
    # SHA-2
    data = os.urandom(random.randrange(0, 1000))
    check("SHA-256", ask("sha256", H(data)) == hashlib.sha256(data).hexdigest())
    check("SHA-1", ask("sha1", H(data)) == hashlib.sha1(data).hexdigest())
    check("SHA-512", ask("sha512", H(data)) == hashlib.sha512(data).hexdigest())
    # 2.4: HMAC, PBKDF2, SHA-3, SHAKE256 (Python's hashlib)
    names = {1: "sha1", 2: "sha256", 3: "sha384", 4: "sha512"}
    for hid, name in names.items():
        key = os.urandom(random.choice((0, 7, 64, 128, 129, 200)))
        check("HMAC-" + name, ask("hmac", str(hid), H(key), H(data)) == hmac.new(key, data, name).hexdigest())
        salt, it, ol = os.urandom(random.randrange(0, 140)), random.randrange(1, 40), random.randrange(1, 150)
        check("PBKDF2-" + name, ask("pbkdf2", str(hid), H(key), H(salt), str(it), str(ol))
              == hashlib.pbkdf2_hmac(name, key, salt, it, ol).hex())
    for v, f in ((256, hashlib.sha3_256), (384, hashlib.sha3_384), (512, hashlib.sha3_512)):
        check("SHA3-%d" % v, ask("sha3", str(v), H(data), str(f().digest_size)) == f(data).hexdigest())
    ol = random.randrange(1, 400)
    check("SHAKE256", ask("sha3", "0x10100", H(data), str(ol)) == hashlib.shake_256(data).hexdigest(ol))
    # 2.4: Ed25519 signing (OpenSSL's signature, byte for byte)
    seed = os.urandom(32)
    esk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    check("Ed25519 sign", ask("edsign", H(seed), H(msg)) == (esk.public_key().public_bytes(*raw) + esk.sign(msg)).hex())

# slower ones, fewer rounds
for i in range(max(4, rounds // 20)):
    for bits in (2048, 3072, 4096):
        k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        n = k.public_key().public_numbers().n
        s = random.randrange(2, n)
        nb = n.to_bytes(bits // 8, "big")
        check("RSA public", ask("rsa", H(nb), "010001", H(s.to_bytes(bits // 8, "big"))) == pow(s, 65537, n).to_bytes(bits // 8, "big").hex())
    for curve, bits, h in ((ec.SECP256R1(), 256, hashes.SHA256()), (ec.SECP384R1(), 384, hashes.SHA384()), (ec.SECP521R1(), 521, hashes.SHA512())):
        k = ec.generate_private_key(curve)
        msg = os.urandom(50)
        r, s = utils.decode_dss_signature(k.sign(msg, ec.ECDSA(h)))
        pn = k.public_key().public_numbers()
        L = (bits + 7) // 8
        dig = hashlib.new(h.name, msg).digest()
        args = ["ecdsa", str(bits)] + [x.to_bytes(L, "big").hex() for x in (pn.x, pn.y, r, s)]
        check("ECDSA good", ask(*args, dig.hex()) == "1")
        bad = bytearray(dig); bad[3] ^= 0x10
        check("ECDSA altered", ask(*args, bytes(bad).hex()) == "0")
    check("sntrup761 round trip", ask("kem", H(os.urandom(32)), H(os.urandom(32))) == "1")
    # 2.4: deterministic ECDSA signatures and key generation
    for curve, bits in ((ec.SECP256R1(), 256), (ec.SECP384R1(), 384), (ec.SECP521R1(), 521)):
        L = (bits + 7) // 8
        n = ORDERS[bits]
        for hl, h in ((20, hashes.SHA1()), (32, hashes.SHA256()), (48, hashes.SHA384()), (64, hashes.SHA512())):
            k = ec.generate_private_key(curve)
            dig = hashlib.new(h.name, os.urandom(40)).digest()
            r, s = utils.decode_dss_signature(k.sign(dig, ec.ECDSA(utils.Prehashed(h), deterministic_signing=True)))
            d = k.private_numbers().private_value.to_bytes(L, "big")
            check("ECDSA sign", ask("ecsign", str(bits), H(d), H(dig)) == (r.to_bytes(L, "big") + s.to_bytes(L, "big")).hex())
        seed = os.urandom(L + 8)
        got = ask("eckeygen", str(bits), H(seed))
        d = int.from_bytes(seed, "big") % (n - 1) + 1
        pub = ec.derive_private_key(d, curve).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        check("EC key generation", got == d.to_bytes(L, "big").hex() + pub.hex())
    # 2.4: modular exponentiation, RSA private operations, the prime test
    for bits in (1024, 2048, 4096, 8192):
        m = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        b, e = random.getrandbits(bits + 32), random.getrandbits(random.choice((256, bits)))
        check("modexp", ask("modexp", H(b.to_bytes((bits + 39) // 8, "big")), H(e.to_bytes((e.bit_length() + 7) // 8 or 1, "big")),
                            H(m.to_bytes(bits // 8, "big"))) == pow(b, e, m).to_bytes(bits // 8, "big").hex())
    for bits in (1024, 2048, 3072, 4096):
        pn = rsa.generate_private_key(public_exponent=65537, key_size=bits).private_numbers()
        pub = pn.public_numbers
        B = lambda x, l=None: x.to_bytes(l or (x.bit_length() + 7) // 8, "big").hex()
        c = random.randrange(pub.n)
        args = [B(pub.n, bits // 8), B(pub.e), B(pn.d), B(pn.p), B(pn.q), B(c, bits // 8)]
        want = B(pow(c, pn.d, pub.n), bits // 8)
        check("RSA private (d, p, q)", ask("rsapriv", *args) == want)
        check("RSA private (CRT values)", ask("rsapriv", *args, B(pn.dmp1), B(pn.dmq1), B(pn.iqmp)) == want)
        check("prime test: p", ask("prime", B(pn.p)) == "1")
        check("prime test: p q", ask("prime", B(pub.n)) == "0")

# 2.4: Argon2id against OpenSSL's (cryptography 44 or newer)
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:
    Argon2id = None
if Argon2id:
    for i in range(max(2, rounds // 50)):
        lanes = random.choice((1, 2, 4))
        mem, t, ol = random.choice((8, 64, 100, 256)) * lanes, random.randrange(1, 4), random.choice((4, 32, 64, 65, 100))
        pw, salt = os.urandom(random.randrange(0, 40)), os.urandom(16)
        want = Argon2id(salt=salt, length=ol, iterations=t, lanes=lanes, memory_cost=mem).derive(pw)
        check("Argon2id", ask("argon2", "2", str(t), str(mem), str(lanes), str(ol), H(pw), H(salt)) == want.hex())

print("differential against Python cryptography %s: %s; %d failures" % (
    __import__("cryptography").__version__, ", ".join("%s %d" % kv for kv in counts.items()), fails))
sys.exit(1 if fails else 0)
