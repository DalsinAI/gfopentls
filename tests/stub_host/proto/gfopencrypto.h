/* the host stub test: each library call is a function of mock.c */
#include <exec/libraries.h>
#include <libraries/gfopencrypto.h>
#define C(n, t) LONG n(struct t *r);
C(OC_SHA256, OCBufferHash) C(OC_SHA384, OCBufferHash) C(OC_SHA512, OCBufferHash) C(OC_SHA1, OCBufferHash)
C(OC_HMAC_SHA256, OCHmacRequest) C(OC_HMAC_SHA384, OCHmacRequest) C(OC_HMAC_SHA1, OCHmacRequest) C(OC_HMAC_SHA512, OCHmacRequest)
C(OC_HKDF_SHA256, OCHKDFRequest) C(OC_HKDF_SHA384, OCHKDFRequest) C(OC_CtEqual, OCCompareRequest) C(OC_Cleanse, OCCleanseRequest)
C(OC_X25519, OCX25519Request) C(OC_Ed25519Verify, OCEd25519Request)
C(OC_SNTRUP761KeyPair, OCKemRequest) C(OC_SNTRUP761Enc, OCKemRequest) C(OC_SNTRUP761Dec, OCKemRequest)
C(OC_SHA256Blocks, OCBlocksRequest) C(OC_SHA512Blocks, OCBlocksRequest) C(OC_SHA1Blocks, OCBlocksRequest) C(OC_MD5Blocks, OCBlocksRequest)
C(OC_ChaCha20, OCChaChaRequest) C(OC_Poly1305, OCPolyRequest) C(OC_AES, OCAESRequest) C(OC_GHASH, OCGHASHRequest)
C(OC_RSAPublic, OCRSARequest) C(OC_ECDSAVerify, OCECDSARequest) C(OC_RSAPSSVerify, OCRSAPSSRequest)
C(OC_ECMul, OCECMulRequest) C(OC_ECMulGen, OCECMulRequest)
C(OC_PBKDF2, OCPBKDF2Request) C(OC_SHA3, OCSHA3Request) C(OC_SHA3Init, OCSHA3Request) C(OC_SHA3Update, OCSHA3Request) C(OC_SHA3Final, OCSHA3Request)
C(OC_Argon2, OCArgon2Request) C(OC_Ed25519Sign, OCEd25519SignRequest) C(OC_Ed25519PublicKey, OCEd25519SignRequest)
C(OC_ECDSASign, OCECDSASignRequest) C(OC_ECKeyGen, OCECKeyGenRequest) C(OC_ModExp, OCModExpRequest)
C(OC_RSAPrivate, OCRSAPrivateRequest) C(OC_IsProbablePrime, OCPrimeRequest)
#undef C
extern struct Library *OpenCryptoBase;
