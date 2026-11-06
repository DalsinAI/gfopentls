#!/usr/bin/env python3
"""OT_CertInfo() and OT_CertAltName() against the openssl command, with no
network: makes certificates with awkward names, serials, dates, keys and
alternative names in OPENTLS_TEST_DIR (default ./cert-fields), and checks
every field opentls_client --certfile prints against what openssl says.

  test_cert_fields.py opentls_client

MIT licensed and free. Copyright (c) 2026 AmiCradle Team."""
import datetime
import ipaddress
import os
import re
import subprocess
import sys

CLIENT = os.path.abspath(sys.argv[1])
WORK = os.path.abspath(os.environ.get("OPENTLS_TEST_DIR", "cert-fields"))
os.makedirs(WORK, exist_ok=True)
failures = []


def sh(*args):
    return subprocess.run(args, check=True, cwd=WORK, capture_output=True, text=True).stdout


def write(name, text):
    with open(os.path.join(WORK, name), "w", encoding="utf-8") as f:
        f.write(text)


def fields(der):
    p = subprocess.run([CLIENT, "--certfile", der], capture_output=True, text=True, cwd=WORK,
                       encoding="utf-8")
    out = {}
    for line in p.stdout.splitlines():
        if line.startswith("conn0.cert0.") and "=" in line:
            k, v = line[len("conn0.cert0."):].split("=", 1)
            out[k] = v
    return out


def openssl_name(pem, which):
    """openssl's RFC 2253 form, put the way GFOpenTLS writes it: EMAIL for
    emailAddress, lower-case hex, and a multi-valued RDN in DER order (openssl
    turns those round with the rest)."""
    line = sh("openssl", "x509", "-in", pem, "-noout", "-" + which, "-nameopt", "RFC2253,-esc_msb")
    name = line.strip().split("=", 1)[1]
    name = name.replace("emailAddress=", "EMAIL=")
    name = re.sub(r"=#([0-9A-F]+)", lambda m: "=#" + m.group(1).lower(), name)
    rdns = re.split(r"(?<!\\),", name)
    rdns = ["+".join(reversed(re.split(r"(?<!\\)\+", r))) for r in rdns]
    return ",".join(rdns)


def openssl_time(pem, which):
    t = sh("openssl", "x509", "-in", pem, "-noout", "-" + which).strip().split("=", 1)[1]
    d = datetime.datetime.strptime(t, "%b %d %H:%M:%S %Y GMT")
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def openssl_alts(pem):
    text = sh("openssl", "x509", "-in", pem, "-noout", "-ext", "subjectAltName")
    out = []
    for part in "".join(text.splitlines()[1:]).split(","):
        kind, _, value = part.strip().partition(":")
        if kind == "DNS":
            out.append("DNS:" + value)
        elif kind == "IP Address":
            out.append("IP:" + ipaddress.ip_address(value).compressed)
        elif kind == "email":
            out.append("email:" + value)
        elif kind == "URI":
            out.append("URI:" + value)
    return ",".join(out)


def check(label, pem, want_key, want_sig, want_version=3, want_self="0"):
    der = pem[:-4] + ".der"
    sh("openssl", "x509", "-in", pem, "-outform", "der", "-out", der)
    got = fields(der)
    serial = sh("openssl", "x509", "-in", pem, "-noout", "-serial").strip().split("=", 1)[1].lower()
    serial = serial.lstrip("0") or "0"
    if len(serial) % 2:
        serial = "0" + serial
    fp256 = sh("openssl", "x509", "-in", pem, "-noout", "-fingerprint", "-sha256").strip().split("=", 1)[1]
    fp1 = sh("openssl", "x509", "-in", pem, "-noout", "-fingerprint", "-sha1").strip().split("=", 1)[1]
    try:
        alts = openssl_alts(pem)
    except subprocess.CalledProcessError:
        alts = ""
    want = {
        "subject": openssl_name(pem, "subject"),
        "issuer": openssl_name(pem, "issuer"),
        "notbefore": openssl_time(pem, "startdate"),
        "notafter": openssl_time(pem, "enddate"),
        "serial": serial,
        "version": str(want_version),
        "key": want_key,
        "sig": want_sig,
        "self": want_self,
        "sha256": fp256.replace(":", "").lower(),
        "sha1": fp1.replace(":", "").lower(),
        "alt": alts,
        "altcount": str(len(alts.split(",")) if alts else 0),
    }
    bad = {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v}
    if bad:
        failures.append(label)
        print("FAIL %s:" % label)
        for k, (g, w) in bad.items():
            print("     %s: got %r, wanted %r" % (k, g, w))
    else:
        print("ok   %s" % label)


def main():
    os.chdir(WORK)
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem",
       "-days", "3650", "-subj", "/CN=Cert Fields Root/O=GFOpenTLS", "-addext",
       "basicConstraints=critical,CA:TRUE")
    write("fields.cnf", "oid_section = oids\n[oids]\ntestAttr = 1.2.3.4\n[req]\ndistinguished_name = dn\n"
                        "string_mask = utf8only\n[dn]\n")
    write("fields.ext", "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:2001:db8::1,"
                        "IP:::1,IP:fe80::1:0:0:2,IP:1:0:0:2:0:0:0:3,IP:::,email:ops@example.org,"
                        "URI:https://example.org/x,DNS:*.example.org\n")
    # awkward names: escapes, UTF-8, a multi-valued RDN, an OID openssl x509 does not know, DC, email
    sh("openssl", "req", "-config", "fields.cnf", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384",
       "-nodes", "-keyout", "fields.key", "-out", "fields.csr", "-utf8", "-multivalue-rdn", "-subj",
       "/DC=org/DC=example/C=GB/ST=Wiltshire/O=Smith\\, Jones \\+ Co/OU=Ops+CN=fields.example/"
       "CN=Zoë Ünïcode <x>;#/testAttr=odd/emailAddress=a@b.c/CN= lead and trail ")
    sh("openssl", "x509", "-req", "-in", "fields.csr", "-CA", "root.pem", "-CAkey", "root.key",
       "-set_serial", "0x00f1e2d3c4b5a69788796a5b4c3d2e1f00", "-out", "fields.pem", "-sha384", "-days", "30",
       "-extfile", "fields.ext")
    check("names, a 16-byte serial, IPv4/IPv6/email/URI alt names, P-384 under RSA-SHA384",
          "fields.pem", "ECDSA/384/secp384r1", "RSA-SHA384")
    # RSA 3072, signed with RSA-SHA512, a serial with the top bit set, notAfter in GeneralizedTime (2050+)
    write("plain.ext", "basicConstraints=CA:FALSE\n")
    sh("openssl", "req", "-newkey", "rsa:3072", "-nodes", "-keyout", "rsa.key", "-out", "rsa.csr", "-subj",
       "/CN=rsa.example")
    sh("openssl", "x509", "-req", "-in", "rsa.csr", "-CA", "root.pem", "-CAkey", "root.key", "-set_serial",
       "0x80", "-out", "rsa.pem", "-sha512", "-days", "12000", "-extfile", "plain.ext")
    check("RSA 3072, RSA-SHA512, serial 0x80, notAfter past 2049", "rsa.pem", "RSA/3072/", "RSA-SHA512")
    # Ed25519, self-signed
    sh("openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", "ed.key", "-out", "ed.pem",
       "-days", "10", "-subj", "/CN=ed.example", "-addext", "subjectAltName=DNS:ed.example")
    check("Ed25519, self-signed", "ed.pem", "Ed25519/256/", "Ed25519", want_self="1")
    # P-256 signed by P-521 (ECDSA-SHA512)
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521", "-nodes",
       "-keyout", "p521.key", "-out", "p521.pem", "-days", "10", "-subj", "/CN=P-521 CA")
    check("P-521, self-signed", "p521.pem", "ECDSA/521/secp521r1", "ECDSA-SHA256", want_self="1")
    sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
       "p256.key", "-out", "p256.csr", "-subj", "/CN=p256.example/L=Bath")
    sh("openssl", "x509", "-req", "-in", "p256.csr", "-CA", "p521.pem", "-CAkey", "p521.key",
       "-set_serial", "1", "-out", "p256.pem", "-sha512", "-days", "10", "-extfile", "plain.ext")
    check("P-256 under P-521, ECDSA-SHA512, serial 1", "p256.pem", "ECDSA/256/secp256r1", "ECDSA-SHA512")
    # RSA-PSS key and signature
    sh("openssl", "req", "-x509", "-newkey", "rsa-pss", "-pkeyopt", "rsa_keygen_bits:2048", "-nodes",
       "-keyout", "pss.key", "-out", "pss.pem", "-days", "10", "-subj", "/CN=pss.example")
    check("RSA-PSS key, RSA-PSS signature", "pss.pem", "RSA-PSS/2048/", "RSA-PSS", want_self="1")
    # a version 1 certificate (no extensions)
    sh("openssl", "x509", "-req", "-in", "rsa.csr", "-CA", "root.pem", "-CAkey", "root.key", "-set_serial",
       "7", "-out", "v1.pem", "-sha256", "-days", "10")
    with open("v1.pem") as f:
        v1 = "Version: 1" in sh("openssl", "x509", "-in", "v1.pem", "-noout", "-text") or "Version: 1 " in f.read()
    if v1:
        check("version 1, no extensions", "v1.pem", "RSA/3072/", "RSA-SHA256", want_version=1)
    # rubbish in: an answer, not a crash
    with open("junk.der", "wb") as f:
        f.write(bytes(range(200)))
    got = subprocess.run([CLIENT, "--certfile", "junk.der"], capture_output=True, text=True).stdout
    label = "not a certificate: OTERR_BADCERT"
    if "conn0.cert0.info=-13" in got:
        print("ok   " + label)
    else:
        failures.append(label)
        print("FAIL %s\n%s" % (label, got))
    der = open("fields.der", "rb").read()
    for cut in (1, 10, len(der) // 2, len(der) - 1):
        with open("cut.der", "wb") as f:
            f.write(der[:cut])
        got = subprocess.run([CLIENT, "--certfile", "cut.der"], capture_output=True, text=True).stdout
        if "conn0.cert0.info=-13" not in got:
            failures.append("cut at %d" % cut)
            print("FAIL a certificate cut at %d bytes\n%s" % (cut, got))
    print("ok   cut certificates refused" if not any(f.startswith("cut") for f in failures) else "")
    print("OPENTLS CERT FIELDS %s (%d failures)" % ("FAIL" if failures else "PASS", len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
