/**
 * pq_chacha20poly1305.c — ChaCha20-Poly1305 AEAD 구현 (RFC 8439)
 * pqenvEditor (양자내성 .env 암호화 도구)
 *
 * ChaCha20: RFC 8439 §2.3~2.4
 * Poly1305: RFC 8439 §2.5 (poly1305-donna 32bit 알고리즘 구조 기반)
 * AEAD 구성: RFC 8439 §2.8
 */
#include "pq_chacha20poly1305.h"
#include <string.h>

/* ================================================================
 * §1  바이트 <-> 32비트 리틀엔디안
 * ================================================================ */
static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void store64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)v; v >>= 8; }
}

/* ================================================================
 * §2  ChaCha20 블록 함수 (RFC 8439 §2.3)
 * ================================================================ */
static uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = rotl32(d,16); \
    c += d; b ^= c; b = rotl32(b,12); \
    a += b; d ^= a; d = rotl32(d,8);  \
    c += d; b ^= c; b = rotl32(b,7);  \
} while (0)

static void chacha20_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    memcpy(x, in, sizeof(x));

    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; i++)
        store32_le(out + i * 4, x[i] + in[i]);
}

static void chacha20_init_state(uint32_t state[16],
                                 const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12])
{
    state[0] = 0x61707865u; state[1] = 0x3320646eu;
    state[2] = 0x79622d32u; state[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) state[4 + i] = load32_le(key + 4 * i);
    state[12] = counter;
    for (int i = 0; i < 3; i++) state[13 + i] = load32_le(nonce + 4 * i);
}

/* in==NULL 이면 순수 키스트림 생성(out에 keystream만 채움) */
static void chacha20_xor(const uint8_t key[32], uint32_t counter,
                          const uint8_t nonce[12],
                          const uint8_t *in, size_t len, uint8_t *out)
{
    uint32_t state[16];
    chacha20_init_state(state, key, counter, nonce);

    size_t pos = 0;
    uint8_t ks[64];
    while (pos < len) {
        chacha20_block(state, ks);
        size_t n = (len - pos < 64) ? (len - pos) : 64;
        for (size_t i = 0; i < n; i++)
            out[pos + i] = (uint8_t)((in ? in[pos + i] : 0) ^ ks[i]);
        state[12]++;
        pos += n;
    }
}

/* ================================================================
 * §3  Poly1305 (RFC 8439 §2.5, poly1305-donna 32bit 구조)
 * ================================================================ */
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
    int      final;
} Poly1305Ctx;

static void poly1305_init(Poly1305Ctx *st, const uint8_t key[32])
{
    uint32_t t0 = load32_le(key + 0),  t1 = load32_le(key + 4);
    uint32_t t2 = load32_le(key + 8),  t3 = load32_le(key + 12);

    st->r[0] = ( t0                    ) & 0x3ffffff;
    st->r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x3ffff03;
    st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    st->r[4] = ((t3 >>  8)             ) & 0x00fffff;

    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;

    st->pad[0] = load32_le(key + 16);
    st->pad[1] = load32_le(key + 20);
    st->pad[2] = load32_le(key + 24);
    st->pad[3] = load32_le(key + 28);

    st->leftover = 0;
    st->final = 0;
}

static void poly1305_blocks(Poly1305Ctx *st, const uint8_t *m, size_t bytes)
{
    const uint32_t hibit = st->final ? 0 : (1UL << 24); /* 1<<128 표현용 */
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    while (bytes >= 16) {
        uint32_t t0 = load32_le(m + 0),  t1 = load32_le(m + 4);
        uint32_t t2 = load32_le(m + 8),  t3 = load32_le(m + 12);

        h0 += ( t0                                    ) & 0x3ffffff;
        h1 += ((uint32_t)(((uint64_t)t1 << 32 | t0) >> 26)) & 0x3ffffff;
        h2 += ((uint32_t)(((uint64_t)t2 << 32 | t1) >> 20)) & 0x3ffffff;
        h3 += ((uint32_t)(((uint64_t)t3 << 32 | t2) >> 14)) & 0x3ffffff;
        h4 += (t3 >> 8) | hibit;

        d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

                      c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;      c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;      c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;      c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;      c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;  c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    st->h[0]=h0; st->h[1]=h1; st->h[2]=h2; st->h[3]=h3; st->h[4]=h4;
}

static void poly1305_update(Poly1305Ctx *st, const uint8_t *m, size_t bytes)
{
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want);
        m += want; bytes -= want;
    }
    if (bytes) {
        memcpy(st->buffer + st->leftover, m, bytes);
        st->leftover += bytes;
    }
}

static void poly1305_finish(Poly1305Ctx *st, uint8_t mac[16])
{
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }

    uint32_t h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4], c;
                 c = h1 >> 26; h1 &= 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 +=     c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1UL << 26);

    uint32_t mask = (g4 >> 31) - 1u;   /* g4가 음수로 wrap됐으면(=h<p) 0, 아니면 0xFFFFFFFF */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;

    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    uint64_t f;
    f = (uint64_t)h0 + st->pad[0];              h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32);  h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32);  h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32);  h3 = (uint32_t)f;

    store32_le(mac + 0,  h0);
    store32_le(mac + 4,  h1);
    store32_le(mac + 8,  h2);
    store32_le(mac + 12, h3);
}

static void poly1305_mac(const uint8_t key[32], const uint8_t *m, size_t len, uint8_t mac[16])
{
    Poly1305Ctx st;
    poly1305_init(&st, key);
    poly1305_update(&st, m, len);
    poly1305_finish(&st, mac);
}

/* ================================================================
 * §4  AEAD 구성 (RFC 8439 §2.8)
 * ================================================================ */

static size_t pad16(size_t n) { size_t r = n % 16; return r ? 16 - r : 0; }

static void poly1305_mac_aead(const uint8_t poly_key[32],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct,  size_t ct_len,
                               uint8_t tag[16])
{
    Poly1305Ctx st;
    poly1305_init(&st, poly_key);

    static const uint8_t zeros[16] = {0};

    poly1305_update(&st, aad, aad_len);
    if (pad16(aad_len)) poly1305_update(&st, zeros, pad16(aad_len));

    poly1305_update(&st, ct, ct_len);
    if (pad16(ct_len)) poly1305_update(&st, zeros, pad16(ct_len));

    uint8_t lens[16];
    store64_le(lens + 0, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)ct_len);
    poly1305_update(&st, lens, 16);

    poly1305_finish(&st, tag);
}

void pq_chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint8_t *ct, uint8_t tag[16])
{
    uint8_t poly_key_block[64];
    uint32_t state[16];
    chacha20_init_state(state, key, 0, nonce);
    chacha20_block(state, poly_key_block);

    chacha20_xor(key, 1, nonce, pt, pt_len, ct);

    poly1305_mac_aead(poly_key_block /*앞 32B가 poly1305 key*/,
                       aad, aad_len, ct, pt_len, tag);
    (void)poly1305_mac; /* 단일 호출 유틸(테스트용) 미사용 경고 억제 */
}

int pq_chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct, size_t ct_len,
                                 const uint8_t tag[16], uint8_t *pt)
{
    uint8_t poly_key_block[64];
    uint32_t state[16];
    chacha20_init_state(state, key, 0, nonce);
    chacha20_block(state, poly_key_block);

    uint8_t computed_tag[16];
    poly1305_mac_aead(poly_key_block, aad, aad_len, ct, ct_len, computed_tag);

    /* 상수시간 비교 */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (computed_tag[i] ^ tag[i]);
    if (diff != 0) return -1;   /* 태그 불일치 — pt를 채우지 않고 즉시 반환 */

    chacha20_xor(key, 1, nonce, ct, ct_len, pt);
    return 0;
}
