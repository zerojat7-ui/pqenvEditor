/**
 * pq_keccak.c — Keccak-f[1600] / SHA3 / SHAKE 구현
 * pqenvEditor (양자내성 .env 암호화 도구)
 *
 * FIPS 202 표준. 리틀엔디안 가정 없이 명시적 load/store로 이식성 확보.
 */
#include "pq_keccak.h"
#include <string.h>

/* ─── 리틀엔디안 안전 64비트 load/store ──────────────────────── */

static uint64_t load64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

static void store64(uint8_t *b, uint64_t v)
{
    for (int i = 0; i < 8; i++) { b[i] = (uint8_t)v; v >>= 8; }
}

static uint64_t rotl64(uint64_t x, int n)
{
    return (x << n) | (x >> (64 - n));
}

/* ─── Keccak-f[1600] 라운드 상수/오프셋 (FIPS 202 표준값) ──────── */

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int ROTC[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int PILN[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static void keccakf1600(uint64_t st[25])
{
    uint64_t bc[5], t;

    for (int r = 0; r < 24; r++) {
        /* θ (Theta) */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }

        /* ρ (Rho) + π (Pi) */
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = PILN[i];
            uint64_t tmp = st[j];
            st[j] = rotl64(t, ROTC[i]);
            t = tmp;
        }

        /* χ (Chi) */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j+i];
            for (int i = 0; i < 5; i++)
                st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
        }

        /* ι (Iota) */
        st[0] ^= RC[r];
    }
}

/* ─── 스트리밍 sponge API ────────────────────────────────────── */

static void ctx_init(PqShakeCtx *ctx, size_t rate)
{
    memset(ctx->s, 0, sizeof(ctx->s));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->rate      = rate;
    ctx->pos       = 0;
    ctx->abs_pos   = 0;
    ctx->absorbing = 1;
}

void pq_shake128_init(PqShakeCtx *ctx) { ctx_init(ctx, 168); }
void pq_shake256_init(PqShakeCtx *ctx) { ctx_init(ctx, 136); }

void pq_shake_absorb(PqShakeCtx *ctx, const uint8_t *in, size_t inlen)
{
    /* buf에 rate 바이트만큼 모으고, 채워지면 state에 XOR 후 permute */
    while (inlen > 0) {
        size_t take = ctx->rate - ctx->abs_pos;
        if (take > inlen) take = inlen;
        memcpy(ctx->buf + ctx->abs_pos, in, take);
        ctx->abs_pos += take;
        in    += take;
        inlen -= take;

        if (ctx->abs_pos == ctx->rate) {
            for (size_t i = 0; i < ctx->rate / 8; i++)
                ctx->s[i] ^= load64(ctx->buf + i*8);
            /* rate가 8의 배수가 아닌 경우는 없음 (168/136 모두 8배수) */
            keccakf1600(ctx->s);
            ctx->abs_pos = 0;
        }
    }
}

void pq_shake_finalize(PqShakeCtx *ctx)
{
    /* SHAKE 도메인 분리 비트: 0x1F, padding: pad10*1 → 마지막 바이트에 0x80 OR */
    memset(ctx->buf + ctx->abs_pos, 0, ctx->rate - ctx->abs_pos);
    ctx->buf[ctx->abs_pos] ^= 0x1F;
    ctx->buf[ctx->rate - 1] ^= 0x80;

    for (size_t i = 0; i < ctx->rate / 8; i++)
        ctx->s[i] ^= load64(ctx->buf + i*8);
    keccakf1600(ctx->s);

    /* squeeze 준비: 현재 state를 buf에 풀어놓는다 */
    for (size_t i = 0; i < ctx->rate / 8; i++)
        store64(ctx->buf + i*8, ctx->s[i]);
    ctx->pos = 0;
    ctx->absorbing = 0;
}

void pq_shake_squeeze(PqShakeCtx *ctx, uint8_t *out, size_t outlen)
{
    while (outlen > 0) {
        size_t avail = ctx->rate - ctx->pos;
        size_t take  = avail < outlen ? avail : outlen;
        memcpy(out, ctx->buf + ctx->pos, take);
        out    += take;
        outlen -= take;
        ctx->pos += take;

        if (ctx->pos == ctx->rate && outlen > 0) {
            keccakf1600(ctx->s);
            for (size_t i = 0; i < ctx->rate / 8; i++)
                store64(ctx->buf + i*8, ctx->s[i]);
            ctx->pos = 0;
        }
    }
}

void pq_shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    PqShakeCtx ctx;
    pq_shake128_init(&ctx);
    pq_shake_absorb(&ctx, in, inlen);
    pq_shake_finalize(&ctx);
    pq_shake_squeeze(&ctx, out, outlen);
}

void pq_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    PqShakeCtx ctx;
    pq_shake256_init(&ctx);
    pq_shake_absorb(&ctx, in, inlen);
    pq_shake_finalize(&ctx);
    pq_shake_squeeze(&ctx, out, outlen);
}

/* ─── SHA3-256 / SHA3-512 (domain sep 0x06, 고정 출력) ─────────── */

static void sha3_fixed(const uint8_t *in, size_t inlen,
                        uint8_t *out, size_t outlen, size_t rate)
{
    uint64_t s[25];
    uint8_t  buf[200];
    memset(s, 0, sizeof(s));
    memset(buf, 0, sizeof(buf));

    size_t pos = 0;
    while (inlen >= rate) {
        for (size_t i = 0; i < rate/8; i++) s[i] ^= load64(in + i*8);
        keccakf1600(s);
        in += rate; inlen -= rate;
    }
    memcpy(buf, in, inlen);
    pos = inlen;

    /* SHA3 domain sep: 0x06, padding pad10*1 */
    memset(buf + pos, 0, rate - pos);
    buf[pos] ^= 0x06;
    buf[rate - 1] ^= 0x80;

    for (size_t i = 0; i < rate/8; i++) s[i] ^= load64(buf + i*8);
    keccakf1600(s);

    /* SHA3-256/512는 출력이 rate보다 작거나 같아 1회 squeeze로 충분 */
    uint8_t out_buf[200];
    for (size_t i = 0; i < rate/8; i++) store64(out_buf + i*8, s[i]);
    memcpy(out, out_buf, outlen);
}

void pq_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32])
{
    sha3_fixed(in, inlen, out, 32, 136);
}

void pq_sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64])
{
    sha3_fixed(in, inlen, out, 64, 72);
}
