/* GFOpenCrypto: AES-128, -192 and -256 (FIPS 197) in CTR (SSH's SDCTR), CBC
 * and ECB, constant time, bit-sliced for 32-bit registers.
 * Copyright (c) 2026 AmiCradle Team. MIT.
 *
 * Two blocks go through the rounds together, as eight 32-bit words: word i
 * holds bit i of all 32 state bytes, byte (row r, column c) of block b at
 * bit 8 (3 - r) + 2 c + b (columns load as big-endian words). SubBytes is then a Boolean circuit over the eight words
 * (Boyar and Peralta, "A depth-16 circuit for the AES S-box", 2012: 113
 * gates), ShiftRows a rotation inside each row's eight bits and MixColumns
 * rotations of whole words by a row, with no table and no secret index or
 * branch anywhere. The key schedule runs its S-box lookups through the same
 * circuit. */
#include "gfopencrypto/gfopencrypto.h"

#include <string.h>

typedef uint32_t W;

/* a word move for an even address where words are big-endian (the 68k) */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define WORD_OK(p) (!((uintptr_t)(p) & 1))
#else
#define WORD_OK(p) 0
#endif

#define SWAPMOVE(a, b, m, n) do { W t_ = (((a) >> (n)) ^ (b)) & (m); (b) ^= t_; (a) ^= t_ << (n); } while (0)

/* q[2 c + b] = column c of block b, big-endian (row r in bits 24 - 8 r..):
 * out, q[i] = bit i of every byte. Its own inverse. */
static void transpose(W q[8])
{
    SWAPMOVE(q[0], q[1], 0x55555555u, 1);
    SWAPMOVE(q[2], q[3], 0x55555555u, 1);
    SWAPMOVE(q[4], q[5], 0x55555555u, 1);
    SWAPMOVE(q[6], q[7], 0x55555555u, 1);
    SWAPMOVE(q[0], q[2], 0x33333333u, 2);
    SWAPMOVE(q[1], q[3], 0x33333333u, 2);
    SWAPMOVE(q[4], q[6], 0x33333333u, 2);
    SWAPMOVE(q[5], q[7], 0x33333333u, 2);
    SWAPMOVE(q[0], q[4], 0x0f0f0f0fu, 4);
    SWAPMOVE(q[1], q[5], 0x0f0f0f0fu, 4);
    SWAPMOVE(q[2], q[6], 0x0f0f0f0fu, 4);
    SWAPMOVE(q[3], q[7], 0x0f0f0f0fu, 4);
}

static W be32(const uint8_t *p)
{
    if (WORD_OK(p)) return *(const W *)(const void *)p;
    return (W)p[0] << 24 | (W)p[1] << 16 | (W)p[2] << 8 | (W)p[3];
}

static void put_be32(uint8_t *p, W v)
{
    if (WORD_OK(p)) { *(W *)(void *)p = v; return; }
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* two blocks (b1 may equal b0) into the sliced state */
static void load2(W q[8], const uint8_t *b0, const uint8_t *b1)
{
    int c;
    for (c = 0; c < 4; ++c) {
        q[2 * c] = be32(b0 + 4 * c);
        q[2 * c + 1] = be32(b1 + 4 * c);
    }
    transpose(q);
}

static void store2(uint8_t *b0, uint8_t *b1, const W s[8])
{
    W q[8];
    int c;
    memcpy(q, s, sizeof q);
    transpose(q);
    for (c = 0; c < 4; ++c) {
        put_be32(b0 + 4 * c, q[2 * c]);
        if (b1) put_be32(b1 + 4 * c, q[2 * c + 1]);
    }
}

/* SubBytes on all 32 bytes: the circuit's inputs U0..U7 are bits 7..0 */
static void sub_bytes(W q[8])
{
    W u0 = q[7], u1 = q[6], u2 = q[5], u3 = q[4], u4 = q[3], u5 = q[2], u6 = q[1], u7 = q[0];
    W t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
    W t20, t21, t22, t23, t24, t25, t26, t27;
    W m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19;
    W m20, m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36;
    W m37, m38, m39, m40, m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53;
    W m54, m55, m56, m57, m58, m59, m60, m61, m62, m63;
    W l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, l17, l18;
    W l19, l20, l21, l22, l23, l24, l25, l26, l27, l28, l29;

    /* top linear layer */
    t1 = u0 ^ u3; t2 = u0 ^ u5; t3 = u0 ^ u6; t4 = u3 ^ u5; t5 = u4 ^ u6;
    t6 = t1 ^ t5; t7 = u1 ^ u2; t8 = u7 ^ t6; t9 = u7 ^ t7; t10 = t6 ^ t7;
    t11 = u1 ^ u5; t12 = u2 ^ u5; t13 = t3 ^ t4; t14 = t6 ^ t11; t15 = t5 ^ t11;
    t16 = t5 ^ t12; t17 = t9 ^ t16; t18 = u3 ^ u7; t19 = t7 ^ t18; t20 = t1 ^ t19;
    t21 = u6 ^ u7; t22 = t7 ^ t21; t23 = t2 ^ t22; t24 = t2 ^ t10; t25 = t20 ^ t17;
    t26 = t3 ^ t16; t27 = t1 ^ t12;

    /* middle: the inversion in GF(2^8) */
    m1 = t13 & t6; m2 = t23 & t8; m3 = t14 ^ m1; m4 = t19 & u7; m5 = m4 ^ m1;
    m6 = t3 & t16; m7 = t22 & t9; m8 = t26 ^ m6; m9 = t20 & t17; m10 = m9 ^ m6;
    m11 = t1 & t15; m12 = t4 & t27; m13 = m12 ^ m11; m14 = t2 & t10; m15 = m14 ^ m11;
    m16 = m3 ^ m2; m17 = m5 ^ t24; m18 = m8 ^ m7; m19 = m10 ^ m15; m20 = m16 ^ m13;
    m21 = m17 ^ m15; m22 = m18 ^ m13; m23 = m19 ^ t25; m24 = m22 ^ m23; m25 = m22 & m20;
    m26 = m21 ^ m25; m27 = m20 ^ m21; m28 = m23 ^ m25; m29 = m28 & m27; m30 = m26 & m24;
    m31 = m20 & m23; m32 = m27 & m31; m33 = m27 ^ m25; m34 = m21 & m22; m35 = m24 & m34;
    m36 = m24 ^ m25; m37 = m21 ^ m29; m38 = m32 ^ m33; m39 = m23 ^ m30; m40 = m35 ^ m36;
    m41 = m38 ^ m40; m42 = m37 ^ m39; m43 = m37 ^ m38; m44 = m39 ^ m40; m45 = m42 ^ m41;
    m46 = m44 & t6; m47 = m40 & t8; m48 = m39 & u7; m49 = m43 & t16; m50 = m38 & t9;
    m51 = m37 & t17; m52 = m42 & t15; m53 = m45 & t27; m54 = m41 & t10; m55 = m44 & t13;
    m56 = m40 & t23; m57 = m39 & t19; m58 = m43 & t3; m59 = m38 & t22; m60 = m37 & t20;
    m61 = m42 & t1; m62 = m45 & t4; m63 = m41 & t2;

    /* bottom linear layer, with the affine map */
    l0 = m61 ^ m62; l1 = m50 ^ m56; l2 = m46 ^ m48; l3 = m47 ^ m55; l4 = m54 ^ m58;
    l5 = m49 ^ m61; l6 = m62 ^ l5; l7 = m46 ^ l3; l8 = m51 ^ m59; l9 = m52 ^ m53;
    l10 = m53 ^ l4; l11 = m60 ^ l2; l12 = m48 ^ m51; l13 = m50 ^ l0; l14 = m52 ^ m61;
    l15 = m55 ^ l1; l16 = m56 ^ l0; l17 = m57 ^ l1; l18 = m58 ^ l8; l19 = m63 ^ l4;
    l20 = l0 ^ l1; l21 = l1 ^ l7; l22 = l3 ^ l12; l23 = l18 ^ l2; l24 = l15 ^ l9;
    l25 = l6 ^ l10; l26 = l7 ^ l9; l27 = l8 ^ l10; l28 = l11 ^ l14; l29 = l11 ^ l17;

    q[7] = l6 ^ l24;
    q[6] = ~(l16 ^ l26);
    q[5] = ~(l19 ^ l28);
    q[4] = l6 ^ l21;
    q[3] = l20 ^ l22;
    q[2] = l25 ^ l29;
    q[1] = ~(l13 ^ l27);
    q[0] = ~(l6 ^ l23);
}

/* the inverse of the affine map (FIPS 197 5.3.2): bit i of the result is
 * bits i+2, i+5 and i+7 of the input (mod 8), and 0x05 */
static void inv_affine(W q[8])
{
    W q0 = q[0], q1 = q[1], q2 = q[2], q3 = q[3], q4 = q[4], q5 = q[5], q6 = q[6], q7 = q[7];
    q[0] = ~(q2 ^ q5 ^ q7);
    q[1] = q3 ^ q6 ^ q0;
    q[2] = ~(q4 ^ q7 ^ q1);
    q[3] = q5 ^ q0 ^ q2;
    q[4] = q6 ^ q1 ^ q3;
    q[5] = q7 ^ q2 ^ q4;
    q[6] = q0 ^ q3 ^ q5;
    q[7] = q1 ^ q4 ^ q6;
}

/* InvSubBytes: S^-1 = A^-1 . S . A^-1, as S = A . inv */
static void inv_sub_bytes(W q[8])
{
    inv_affine(q);
    sub_bytes(q);
    inv_affine(q);
}

/* ShiftRows: row r's eight bits (two per column, in byte 3 - r) turn right
 * by 2 r */
static W shift_rows1(W x)
{
    return (x & 0xff000000u)
         | ((x >> 2) & 0x003f0000u) | ((x << 6) & 0x00c00000u)
         | ((x >> 4) & 0x00000f00u) | ((x << 4) & 0x0000f000u)
         | ((x >> 6) & 0x00000003u) | ((x << 2) & 0x000000fcu);
}

static W inv_shift_rows1(W x)
{
    return (x & 0xff000000u)
         | ((x << 2) & 0x00fc0000u) | ((x >> 6) & 0x00030000u)
         | ((x << 4) & 0x0000f000u) | ((x >> 4) & 0x00000f00u)
         | ((x << 6) & 0x000000c0u) | ((x >> 2) & 0x0000003fu);
}

#if defined(__GNUC__) && (defined(__mc68020__) || defined(__mc68030__) || defined(__mc68040__) || defined(__mc68060__))
/* on the 68020 and up the rows turn in registers: the low byte with ror.b,
 * the next with it brought down by ror.w #8, the third by swap */
#define SR1(x) __asm__("ror.b #6,%0\n\tror.w #8,%0\n\tror.b #4,%0\n\tror.w #8,%0\n\t" \
                       "swap %0\n\tror.b #2,%0\n\tswap %0" : "+d"(x))
#define ISR1(x) __asm__("rol.b #6,%0\n\tror.w #8,%0\n\trol.b #4,%0\n\tror.w #8,%0\n\t" \
                        "swap %0\n\trol.b #2,%0\n\tswap %0" : "+d"(x))
#else
#define SR1(x) ((x) = shift_rows1(x))
#define ISR1(x) ((x) = inv_shift_rows1(x))
#endif

static void shift_rows(W q[8])
{
    W a = q[0], b = q[1], c = q[2], d = q[3];
    SR1(a); SR1(b); SR1(c); SR1(d);
    q[0] = a; q[1] = b; q[2] = c; q[3] = d;
    a = q[4]; b = q[5]; c = q[6]; d = q[7];
    SR1(a); SR1(b); SR1(c); SR1(d);
    q[4] = a; q[5] = b; q[6] = c; q[7] = d;
}

static void inv_shift_rows(W q[8])
{
    W a = q[0], b = q[1], c = q[2], d = q[3];
    ISR1(a); ISR1(b); ISR1(c); ISR1(d);
    q[0] = a; q[1] = b; q[2] = c; q[3] = d;
    a = q[4]; b = q[5]; c = q[6]; d = q[7];
    ISR1(a); ISR1(b); ISR1(c); ISR1(d);
    q[4] = a; q[5] = b; q[6] = c; q[7] = d;
}

static W rol8(W x)  { return (x << 8) | (x >> 24); }   /* row r + 1 into row r */
static W ror16(W x) { return (x >> 16) | (x << 16); }

/* q = 2 q in GF(2^8), bit plane by bit plane */
static void xtime_q(W q[8])
{
    W hi = q[7];
    q[7] = q[6]; q[6] = q[5]; q[5] = q[4]; q[4] = q[3] ^ hi;
    q[3] = q[2] ^ hi; q[2] = q[1]; q[1] = q[0] ^ hi; q[0] = hi;
}

/* MixColumns: a_r' = 2 (a_r + a_r+1) + a_r+1 + a_r+2 + a_r+3, one plane at a
 * time: with t = q + rol8(q), plane i of 2 t is t_i-1, plus t_7 in planes 0,
 * 1, 3 and 4 */
#define MIXP(i, xt) do { W r_ = rol8(q[i]); W ti_ = q[i] ^ r_; \
    q[i] = r_ ^ ror16(ti_) ^ (xt); tp = ti_; } while (0)
static void mix_columns(W q[8])
{
    W t7 = q[7] ^ rol8(q[7]), tp;
    MIXP(0, t7);
    MIXP(1, tp ^ t7);
    MIXP(2, tp);
    MIXP(3, tp ^ t7);
    MIXP(4, tp ^ t7);
    MIXP(5, tp);
    MIXP(6, tp);
    MIXP(7, tp);
}

/* InvMixColumns = MixColumns after a_r += 4 (a_r + a_r+2) */
static void inv_mix_columns(W q[8])
{
    W t[8];
    int i;
    for (i = 0; i < 8; ++i) t[i] = q[i] ^ ror16(q[i]);
    xtime_q(t);
    xtime_q(t);
    for (i = 0; i < 8; ++i) q[i] ^= t[i];
    mix_columns(q);
}

/* the round keys, sliced for two blocks: 8 (Nr + 1) words; Nr returned
 * (0: bad length) */
static int expand_key(W sk[120], const uint8_t *key, size_t keylen)
{
    W w[60], q[8], tmp;
    int nk = (int)(keylen / 4), nr, i, words;
    W rcon = 1;
    if (keylen != 16 && keylen != 24 && keylen != 32) return 0;
    nr = nk + 6;
    words = 4 * (nr + 1);
    for (i = 0; i < nk; ++i) w[i] = be32(key + 4 * i);
    for (i = nk; i < words; ++i) {
        tmp = w[i - 1];
        if (i % nk == 0 || (nk > 6 && i % nk == 4)) {
            if (i % nk == 0) tmp = (tmp << 8) | (tmp >> 24);    /* RotWord */
            /* SubWord: the word as block 0's column 0 */
            memset(q, 0, sizeof q);
            q[0] = tmp;
            transpose(q);
            sub_bytes(q);
            transpose(q);
            tmp = q[0];
            if (i % nk == 0) {
                tmp ^= rcon << 24;
                rcon = ((rcon << 1) ^ (0x1b & -(rcon >> 7))) & 0xff;
            }
        }
        w[i] = w[i - nk] ^ tmp;
    }
    for (i = 0; i <= nr; ++i) {
        int c;
        W *k = sk + 8 * i;
        for (c = 0; c < 4; ++c) k[2 * c] = k[2 * c + 1] = w[4 * i + c];
        transpose(k);
    }
    oc_cleanse(w, sizeof w);
    oc_cleanse(q, sizeof q);
    return nr;
}

static void add_round_key(W q[8], const W *k)
{
    q[0] ^= k[0]; q[1] ^= k[1]; q[2] ^= k[2]; q[3] ^= k[3];
    q[4] ^= k[4]; q[5] ^= k[5]; q[6] ^= k[6]; q[7] ^= k[7];
}

static void encrypt2(W q[8], const W *sk, int nr)
{
    int r;
    add_round_key(q, sk);
    for (r = 1; r < nr; ++r) {
        sub_bytes(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, sk + 8 * r);
    }
    sub_bytes(q);
    shift_rows(q);
    add_round_key(q, sk + 8 * nr);
}

static void decrypt2(W q[8], const W *sk, int nr)
{
    int r;
    add_round_key(q, sk + 8 * nr);
    for (r = nr - 1; r > 0; --r) {
        inv_shift_rows(q);
        inv_sub_bytes(q);
        add_round_key(q, sk + 8 * r);
        inv_mix_columns(q);
    }
    inv_shift_rows(q);
    inv_sub_bytes(q);
    add_round_key(q, sk);
}

/* the 128-bit big-endian counter as four words, moved on by one */
static void ctr_next(W v[4])
{
    if (++v[3]) return;
    if (++v[2]) return;
    if (++v[1]) return;
    ++v[0];
}

int oc_aes(uint8_t *buf, size_t length, const uint8_t *key, size_t keylen,
           const uint8_t iv[16], int mode)
{
    W sk[120], q[8];
    uint8_t v[16], c0[16], c1[16], k0[16], k1[16];
    size_t i, n;
    int nr = expand_key(sk, key, keylen);
    if (!nr) return -1;
    if (mode != OC_AES_CTR && (length & 15)) return -1;
    memcpy(v, iv, 16);
    switch (mode) {
    case OC_AES_CTR: {
        W ctr[4], *k;
        int c;
        for (c = 0; c < 4; ++c) ctr[c] = be32(iv + 4 * c);
        while (length) {
            for (c = 0; c < 4; ++c) q[2 * c] = ctr[c];
            ctr_next(ctr);
            for (c = 0; c < 4; ++c) q[2 * c + 1] = ctr[c];
            ctr_next(ctr);
            transpose(q);
            encrypt2(q, sk, nr);
            transpose(q);
            n = length < 32 ? length : 32;
            if (n == 32 && WORD_OK(buf)) {
                k = (W *)(void *)buf;
                k[0] ^= q[0]; k[1] ^= q[2]; k[2] ^= q[4]; k[3] ^= q[6];
                k[4] ^= q[1]; k[5] ^= q[3]; k[6] ^= q[5]; k[7] ^= q[7];
            } else {
                for (c = 0; c < 4; ++c) { put_be32(k0 + 4 * c, q[2 * c]); put_be32(k1 + 4 * c, q[2 * c + 1]); }
                for (i = 0; i < n && i < 16; ++i) buf[i] ^= k0[i];
                for (; i < n; ++i) buf[i] ^= k1[i - 16];
            }
            buf += n;
            length -= n;
        }
        oc_cleanse(ctr, sizeof ctr);
        break;
    }
    case OC_AES_CBC_ENCRYPT:
        for (; length; length -= 16, buf += 16) {
            for (i = 0; i < 16; ++i) buf[i] ^= v[i];
            load2(q, buf, buf);
            encrypt2(q, sk, nr);
            store2(buf, NULL, q);
            memcpy(v, buf, 16);
        }
        break;
    case OC_AES_CBC_DECRYPT:
        while (length) {
            size_t two = length >= 32;
            memcpy(c0, buf, 16);
            if (two) memcpy(c1, buf + 16, 16);
            load2(q, buf, two ? buf + 16 : buf);
            decrypt2(q, sk, nr);
            store2(buf, two ? buf + 16 : NULL, q);
            for (i = 0; i < 16; ++i) buf[i] ^= v[i];
            if (two) {
                for (i = 0; i < 16; ++i) buf[16 + i] ^= c0[i];
                memcpy(v, c1, 16);
            } else {
                memcpy(v, c0, 16);
            }
            n = two ? 32 : 16;
            buf += n;
            length -= n;
        }
        break;
    case OC_AES_ECB_ENCRYPT:
        while (length) {
            size_t two = length >= 32;
            load2(q, buf, two ? buf + 16 : buf);
            encrypt2(q, sk, nr);
            store2(buf, two ? buf + 16 : NULL, q);
            n = two ? 32 : 16;
            buf += n;
            length -= n;
        }
        break;
    default:
        oc_cleanse(sk, sizeof sk);
        return -1;
    }
    oc_cleanse(sk, sizeof sk);
    oc_cleanse(q, sizeof q);
    oc_cleanse(k0, sizeof k0);
    oc_cleanse(k1, sizeof k1);
    return 0;
}
