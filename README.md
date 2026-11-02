# GFOpenTLS

GFOpenTLS is the native TLS and cryptography stack for the GFOpenAmiga platform.

The repository contains two public Amiga-facing layers:

- **GFOpenCrypto** — hashes, MAC/KDF, RNG, AEAD and public-key primitives.
- **GFOpenTLS** — TLS 1.2/1.3, certificate validation, sessions and trust policy.

Applications use these APIs directly. AmiSSL/OpenSSL become reference and
compatibility technology during qualification rather than production
dependencies of GFOpenBrowser.

Current slice (8 October 2026): `gfopencrypto.library` 2.0, with what SSH
needs, for GFOpenPuTTY first:

| What | Notes |
| --- | --- |
| SHA-256, SHA-384, SHA-512, HMAC, HKDF | version 1; version 2 adds the block functions (`OC_SHA256Blocks`, `OC_SHA512Blocks`) |
| X25519 | RFC 7748, constant time |
| sntrup761 | NTRU Prime as SSH's `sntrup761x25519-sha512` uses it, constant time; keys from a 32-byte seed |
| Ed25519 verification | RFC 8032 |
| ECDSA verification | P-256, P-384, P-521 |
| RSA public operation | up to 8192 bits, for PKCS #1 signatures |
| RSASSA-PSS verification | version 2.1 (`OC_RSAPSSVerify`), for TLS 1.3 certificates |
| AES-128/192/256 | CTR (SSH's SDCTR), CBC, ECB; constant time |
| ChaCha20, Poly1305 | the 64-bit nonce form SSH's `chacha20-poly1305@openssh.com` uses |

On AmiCradle the x86 or ARM64 cores do the heavy work: each operation is an AC090
magic function (`library/oc_magic.h`), which AC090 runs as x86 or ARM64 code from
the same C (amicradle's `jit_crypto.c`); everywhere else the library
runs it as 68k code. `OC_Accelerated()` says which operations are x86 or ARM64 code. In an
AmiCradle lab (scratch copy of Instance-11, AC090 68040, 8 October 2026)
GFOpenPuTTY's NTRU Prime / Curve25519 key exchange went from 11 s with
PuTTY's own code on the old JIT to about 60 ms with GFOpenCrypto as x86
code; DESIGN.md section 8 has the 68k figures and the tests.

`gfopentls.library` 1.0 (9 October 2026): a TLS 1.2 client on BearSSL (MIT)
with GFOpenCrypto doing the maths that the x86 or ARM64 cores can do on
AmiCradle. Certificate chains against a trust store
(`S:GFOpenTLS/ca-bundle.pem`, local additions in `ENVARC:GFOpenTLS/certs/`), host names and
IP addresses, SNI, ALPN, session resumption by session ID (FTPS data
connections), verify modes and pinned certificates.
`docs/AutoDocs-GFOpenTLS.md` is the API; DESIGN.md section 9 the design.

`gfopentls.library` 1.3 (20 October 2026): TLS 1.3 as well, our own code from
RFC 8446: one round trip less per connection. One ClientHello offers TLS
1.3 and 1.2; a TLS 1.2 server is handed to BearSSL on the same connection.
X25519 (P-256 after a HelloRetryRequest), AES-GCM and ChaCha20-Poly1305,
ECDSA, RSA-PSS and Ed25519 certificates, resumption with tickets through
the same `OT_GetSession()`/`OT_SetSession()`, KeyUpdate. No 0-RTT, no
client certificates. `OT_SetVersion()` sets one connection's range.
DESIGN.md section 10 has the design.

## Building and testing

    cmake -S . -B build && cmake --build build && ctest --test-dir build
        GFOpenTLS on the x86 or ARM64 cores against local servers (openssl
        s_server, tests/ftps_server.py), and GFOpenCrypto: the published vectors
        (tests/test_ssh_primitives.c) and, with Python's cryptography
        package, random inputs against OpenSSL (tests/differential.py)
    tests/interop_putty.sh
        sntrup761 against PuTTY 0.85's own, both ways (PuTTY is fetched
        as its release tarball and checked against its SHA-256)
    ./build-amiga-tls.sh
        gfopentls.library and its Amiga test programs (GFOpenTLSClient,
        GFOpenTLSFTPSGet), with the os32 GCC 16 stove; STOVE= another stove
        (the os32 stove's GCC 6.5 builds it too); 68040 code, CPU=060 for
        the 68060
    tools/make_ca_bundle.py OUTDIR
        ca-bundle.pem and ca-bundle.LICENSE for S:GFOpenTLS/: Mozilla's
        CA list from this machine's ca-certificates package (MPL-2.0), and
        nothing else
    tests/lab/lab_amiga.sh LAB BUILD LABEL
        the same programs on the Amiga, in a lab made with AmiCradle's
        scripts/lab_instance.py, against local test servers
    ./build-amiga.sh
        gfopencrypto.library and the Amiga tests (GFOpenCryptoLibTest,
        GFOpenCryptoVectors: the same vectors on the 68k; GFOpenCryptoBench:
        each call checked and timed), with the os32 GCC 16 stove; 68040
        code, CPU=060 for the 68060

## Architecture

```text
GFOpenBrowser / curl GFOpenTLS backend / native applications
                         |
                    gfopentls.library
                         |
                  gfopencrypto.library
              /          |           \
           68040       AC090       x86/ARM64/GFOpenGPU
```

GFOpenGPU is optional and only used where batching makes it faster. TLS semantics
never live in GFOpenGPU.

## Correctness rule

Crypto is stricter than graphics: no accelerated implementation is enabled
until it passes standard vectors and differential tests against a trusted
reference implementation.

The existing `opentls.key/1` service in DalsinAI/gfopenservice remains the
bridge-era reference for slow public-key work while this native stack grows.
