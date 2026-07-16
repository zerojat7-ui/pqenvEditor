/**
 * pq_mlkem.c — ML-KEM-768 (FIPS 203) 구현부
 * pqenvEditor (양자내성 .env 암호화 도구)
 */
#include "pq_mlkem.h"
#include "pq_keccak.h"
#include "pq_random.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * §0  파라미터 (ML-KEM-768)
 * ================================================================ */
#define PQ_N     256
#define PQ_Q     3329
#define PQ_K     3
#define PQ_ETA1  2
#define PQ_ETA2  2
#define PQ_DU    10
#define PQ_DV    4

typedef int16_t Poly[PQ_N];          /* 계수 mod q, 표현 범위 [0, Q) */
typedef Poly     PolyVec[PQ_K];

/* 난수는 pq_random.c(pq_random_bytes)로 일원화 — getentropy() 우선,
 * /dev/urandom+poll 타임아웃 폴백, 절대 비암호학적 PRNG로 대체 안 함.
 * (임베디드/엔트로피 부족 환경 대응 — 자세한 내용은 pq_random.h 참고) */

/* ================================================================
 * §2  해시 래퍼 (FIPS 203 §4.1)
 * ================================================================ */

/* G(x) = SHA3-512(x), 64B 출력을 (a,b) 32B씩 분리 */
static void G(const uint8_t *in, size_t inlen, uint8_t a[32], uint8_t b[32])
{
    uint8_t out[64];
    pq_sha3_512(in, inlen, out);
    memcpy(a, out, 32);
    memcpy(b, out + 32, 32);
}

/* H(x) = SHA3-256(x) */
static void H(const uint8_t *in, size_t inlen, uint8_t out[32])
{
    pq_sha3_256(in, inlen, out);
}

/* J(x) = SHAKE256(x, 32) — 묵시적 거부용 */
static void J(const uint8_t *in, size_t inlen, uint8_t out[32])
{
    pq_shake256(in, inlen, out, 32);
}

/* PRF_eta(s(32B), b(1B)) = SHAKE256(s||b, 64*eta) */
static void PRF(int eta, const uint8_t s[32], uint8_t b, uint8_t *out)
{
    uint8_t in[33];
    memcpy(in, s, 32);
    in[32] = b;
    pq_shake256(in, 33, out, (size_t)64 * (size_t)eta);
}

/* ================================================================
 * §3  BitRev7 / zeta 테이블 (런타임 계산 — 오타 위험 있는 상수 테이블 배제)
 * ================================================================ */

static int16_t ZETA[128];     /* ZETA[i] = 17^BitRev7(i) mod q, i=0..127 */
static int16_t ZETA_INV_128 = 3303; /* 128^{-1} mod 3329 (역NTT 마지막 스케일) */

static unsigned bitrev7(unsigned x)
{
    unsigned r = 0;
    for (int i = 0; i < 7; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static int16_t modpow(int base, int exp, int mod)
{
    long long b = base % mod, r = 1;
    while (exp > 0) {
        if (exp & 1) r = (r * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return (int16_t)r;
}

static void zeta_init(void)
{
    for (int i = 0; i < 128; i++)
        ZETA[i] = modpow(17, (int)bitrev7((unsigned)i), PQ_Q);
}

/* ================================================================
 * §4  모듈러 산술 헬퍼
 * ================================================================ */

static inline int16_t mod_q(int32_t x)
{
    int32_t r = x % PQ_Q;
    if (r < 0) r += PQ_Q;
    return (int16_t)r;
}

/* ================================================================
 * §5  NTT / 역NTT / NTT곱 (FIPS 203 Alg.9~11)
 * ================================================================ */

static void ntt(Poly f)
{
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < PQ_N; start += 2 * len) {
            int16_t zeta = ZETA[k++];
            for (int j = start; j < start + len; j++) {
                int32_t t = ((int32_t)zeta * f[j + len]) % PQ_Q;
                int16_t a = f[j];
                f[j]       = mod_q(a + t);
                f[j + len] = mod_q(a - t);
            }
        }
    }
}

static void inv_ntt(Poly f)
{
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < PQ_N; start += 2 * len) {
            int16_t zeta = ZETA[k--];
            for (int j = start; j < start + len; j++) {
                int16_t a = f[j], b = f[j + len];
                f[j]       = mod_q(a + b);
                int32_t t  = mod_q(b - a);
                f[j + len] = (int16_t)(((int32_t)zeta * t) % PQ_Q);
            }
        }
    }
    for (int i = 0; i < PQ_N; i++)
        f[i] = (int16_t)(((int32_t)f[i] * ZETA_INV_128) % PQ_Q);
}

/* 두 NTT-도메인 다항식의 곱 (128개의 도-2 기약다항식 기준 base 곱셈) */
static void base_case_mul(int16_t a0, int16_t a1, int16_t b0, int16_t b1,
                           int16_t gamma, int16_t *c0, int16_t *c1)
{
    int32_t t = ((int32_t)a1 * b1) % PQ_Q;
    t = (t * gamma) % PQ_Q;
    *c0 = mod_q((int32_t)((int32_t)a0 * b0) % PQ_Q + t);
    *c1 = mod_q((int32_t)a0 * b1 + (int32_t)a1 * b0);
}

static void poly_mul_ntt(const Poly a, const Poly b, Poly out)
{
    /* gamma_i = zeta^(2*BitRev7(i)+1) mod q, i=0..127 — 직접 계산 */
    for (int i = 0; i < PQ_N / 2; i++) {
        int16_t gamma = modpow(17, 2 * (int)bitrev7((unsigned)i) + 1, PQ_Q);
        base_case_mul(a[2*i], a[2*i+1], b[2*i], b[2*i+1], gamma,
                      &out[2*i], &out[2*i+1]);
    }
}

/* ================================================================
 * §6  다항식 덧셈/뺄셈
 * ================================================================ */
static void poly_add(const Poly a, const Poly b, Poly out)
{ for (int i = 0; i < PQ_N; i++) out[i] = mod_q(a[i] + b[i]); }

static void poly_sub(const Poly a, const Poly b, Poly out)
{ for (int i = 0; i < PQ_N; i++) out[i] = mod_q(a[i] - b[i]); }

/* ================================================================
 * §7  Compress / Decompress (FIPS 203 §4.2.1)
 * ================================================================ */
static int16_t compress_d(int16_t x, int d)
{
    /* round(x * 2^d / q) mod 2^d, 정수 반올림 */
    int32_t num = (int32_t)x << d;
    int32_t r = (num + PQ_Q / 2) / PQ_Q;
    return (int16_t)(r & ((1 << d) - 1));
}
static int16_t decompress_d(int16_t y, int d)
{
    int32_t num = (int32_t)y * PQ_Q;
    return (int16_t)((num + (1 << (d - 1))) >> d);
}
static void poly_compress(const Poly a, int d, Poly out)
{ for (int i = 0; i < PQ_N; i++) out[i] = compress_d(a[i], d); }
static void poly_decompress(const Poly a, int d, Poly out)
{ for (int i = 0; i < PQ_N; i++) out[i] = decompress_d(a[i], d); }

/* ================================================================
 * §8  ByteEncode / ByteDecode (FIPS 203 Alg.4~5)
 * ================================================================ */
static void byte_encode(const Poly a, int d, uint8_t *out)
{
    /* d비트씩 리틀엔디안 비트스트림으로 패킹 */
    uint32_t acc = 0; int accbits = 0; int outpos = 0;
    for (int i = 0; i < PQ_N; i++) {
        acc |= ((uint32_t)a[i]) << accbits;
        accbits += d;
        while (accbits >= 8) {
            out[outpos++] = (uint8_t)(acc & 0xFF);
            acc >>= 8; accbits -= 8;
        }
    }
    if (accbits > 0) out[outpos++] = (uint8_t)(acc & 0xFF);
}
static void byte_decode(const uint8_t *in, int d, Poly out)
{
    uint32_t acc = 0; int accbits = 0; int inpos = 0;
    uint32_t mask = (1u << d) - 1u;
    for (int i = 0; i < PQ_N; i++) {
        while (accbits < d) {
            acc |= ((uint32_t)in[inpos++]) << accbits;
            accbits += 8;
        }
        out[i] = (int16_t)(acc & mask);
        acc >>= d; accbits -= d;
    }
}
static size_t encoded_len(int d) { return (size_t)(PQ_N * d) / 8; }

/* ================================================================
 * §9  SamplePolyCBD_eta (Alg.8) / SampleNTT (Alg.7, rejection sampling)
 * ================================================================ */
static void sample_cbd(int eta, const uint8_t *buf /* 64*eta bytes */, Poly out)
{
    /* 비트스트림에서 eta개씩 두 그룹 뽑아 차 계산 */
    int total_bits = 8 * 64 * eta;
    (void)total_bits;
    int bitpos = 0;
    for (int i = 0; i < PQ_N; i++) {
        int x = 0, y = 0;
        for (int j = 0; j < eta; j++) {
            int bit = (buf[bitpos / 8] >> (bitpos % 8)) & 1; bitpos++;
            x += bit;
        }
        for (int j = 0; j < eta; j++) {
            int bit = (buf[bitpos / 8] >> (bitpos % 8)) & 1; bitpos++;
            y += bit;
        }
        out[i] = mod_q(x - y);
    }
}

/* XOF(rho,i,j) 스트림에서 3바이트씩 읽어 12비트 두 개(mod q 미만인 것만 채택) 추출 */
static void sample_ntt(const uint8_t rho[32], uint8_t i, uint8_t j, Poly out)
{
    uint8_t seed[34];
    memcpy(seed, rho, 32);
    seed[32] = i;
    seed[33] = j;

    PqShakeCtx ctx;
    pq_shake128_init(&ctx);
    pq_shake_absorb(&ctx, seed, 34);
    pq_shake_finalize(&ctx);

    int count = 0;
    uint8_t block[3];
    while (count < PQ_N) {
        pq_shake_squeeze(&ctx, block, 3);
        uint16_t d1 = (uint16_t)(block[0] | ((block[1] & 0x0F) << 8));
        uint16_t d2 = (uint16_t)((block[1] >> 4) | (block[2] << 4));
        if (d1 < PQ_Q) out[count++] = (int16_t)d1;
        if (count < PQ_N && d2 < PQ_Q) out[count++] = (int16_t)d2;
    }
}

/* ================================================================
 * §10 K-PKE (Alg.13~15)
 * ================================================================ */

/* A_hat[i][j] 생성 — FIPS203 최종본(Â fix): A_hat[i][j] = SampleNTT(XOF(rho, j, i))
 * 즉 열(column)-우선이 아니라 (j,i) 순서로 XOF 시드를 만든다.               */
static void gen_matrix(const uint8_t rho[32], Poly A[PQ_K][PQ_K])
{
    for (int i = 0; i < PQ_K; i++)
        for (int j = 0; j < PQ_K; j++)
            sample_ntt(rho, (uint8_t)j, (uint8_t)i, A[i][j]);
}

typedef struct {
    uint8_t t_hat_enc[PQ_K * 384];   /* ByteEncode12(t_hat[0..k-1]) */
    uint8_t rho[32];
} PkeEk;

typedef struct {
    uint8_t s_hat_enc[PQ_K * 384];   /* ByteEncode12(s_hat[0..k-1]) */
} PkeDk;

static void pke_keygen(const uint8_t d[32], PkeEk *ek, PkeDk *dk)
{
    uint8_t rho[32], sigma[32];
    G(d, 32, rho, sigma);

    Poly A[PQ_K][PQ_K];
    gen_matrix(rho, A);

    PolyVec s, e;
    uint8_t prfbuf[64 * PQ_ETA1];
    uint8_t bcount = 0;
    for (int i = 0; i < PQ_K; i++) {
        PRF(PQ_ETA1, sigma, bcount++, prfbuf);
        sample_cbd(PQ_ETA1, prfbuf, s[i]);
    }
    for (int i = 0; i < PQ_K; i++) {
        PRF(PQ_ETA1, sigma, bcount++, prfbuf);
        sample_cbd(PQ_ETA1, prfbuf, e[i]);
    }

    PolyVec s_hat, e_hat, t_hat;
    for (int i = 0; i < PQ_K; i++) { memcpy(s_hat[i], s[i], sizeof(Poly)); ntt(s_hat[i]); }
    for (int i = 0; i < PQ_K; i++) { memcpy(e_hat[i], e[i], sizeof(Poly)); ntt(e_hat[i]); }

    for (int i = 0; i < PQ_K; i++) {
        Poly acc = {0};
        for (int j = 0; j < PQ_K; j++) {
            Poly prod;
            poly_mul_ntt(A[i][j], s_hat[j], prod);
            poly_add(acc, prod, acc);
        }
        poly_add(acc, e_hat[i], t_hat[i]);
    }

    for (int i = 0; i < PQ_K; i++)
        byte_encode(t_hat[i], 12, ek->t_hat_enc + i * 384);
    memcpy(ek->rho, rho, 32);

    for (int i = 0; i < PQ_K; i++)
        byte_encode(s_hat[i], 12, dk->s_hat_enc + i * 384);
}

static void pke_encrypt(const PkeEk *ek, const uint8_t m[32],
                         const uint8_t r_seed[32], uint8_t ct[PQ_MLKEM768_CT_LEN])
{
    PolyVec t_hat;
    for (int i = 0; i < PQ_K; i++)
        byte_decode(ek->t_hat_enc + i * 384, 12, t_hat[i]);

    Poly A[PQ_K][PQ_K];
    gen_matrix(ek->rho, A);

    PolyVec r_vec, e1;
    Poly e2;
    uint8_t prfbuf1[64 * PQ_ETA1];
    uint8_t prfbuf2[64 * PQ_ETA2];
    uint8_t bcount = 0;
    for (int i = 0; i < PQ_K; i++) {
        PRF(PQ_ETA1, r_seed, bcount++, prfbuf1);
        sample_cbd(PQ_ETA1, prfbuf1, r_vec[i]);
    }
    for (int i = 0; i < PQ_K; i++) {
        PRF(PQ_ETA2, r_seed, bcount++, prfbuf2);
        sample_cbd(PQ_ETA2, prfbuf2, e1[i]);
    }
    PRF(PQ_ETA2, r_seed, bcount++, prfbuf2);
    sample_cbd(PQ_ETA2, prfbuf2, e2);

    PolyVec r_hat;
    for (int i = 0; i < PQ_K; i++) { memcpy(r_hat[i], r_vec[i], sizeof(Poly)); ntt(r_hat[i]); }

    /* u = NTT^-1(A_hat^T . r_hat) + e1  (A^T: u_i = sum_j A[j][i] * r_hat[j]) */
    PolyVec u;
    for (int i = 0; i < PQ_K; i++) {
        Poly acc = {0};
        for (int j = 0; j < PQ_K; j++) {
            Poly prod;
            poly_mul_ntt(A[j][i], r_hat[j], prod);
            poly_add(acc, prod, acc);
        }
        inv_ntt(acc);
        poly_add(acc, e1[i], u[i]);
    }

    /* mu = Decompress_1(ByteDecode_1(m)) */
    Poly mu_bits, mu;
    byte_decode(m, 1, mu_bits);
    poly_decompress(mu_bits, 1, mu);

    /* v = NTT^-1(t_hat^T . r_hat) + e2 + mu */
    Poly v_acc = {0};
    for (int j = 0; j < PQ_K; j++) {
        Poly prod;
        poly_mul_ntt(t_hat[j], r_hat[j], prod);
        poly_add(v_acc, prod, v_acc);
    }
    inv_ntt(v_acc);
    Poly v;
    poly_add(v_acc, e2, v);
    poly_add(v, mu, v);

    /* c1 = ByteEncode_du(Compress_du(u)) */
    size_t c1_len = encoded_len(PQ_DU);
    for (int i = 0; i < PQ_K; i++) {
        Poly uc;
        poly_compress(u[i], PQ_DU, uc);
        byte_encode(uc, PQ_DU, ct + i * c1_len);
    }
    /* c2 = ByteEncode_dv(Compress_dv(v)) */
    Poly vc;
    poly_compress(v, PQ_DV, vc);
    byte_encode(vc, PQ_DV, ct + PQ_K * c1_len);
}

static void pke_decrypt(const PkeDk *dk, const uint8_t ct[PQ_MLKEM768_CT_LEN],
                         uint8_t m[32])
{
    size_t c1_len = encoded_len(PQ_DU);

    PolyVec u;
    for (int i = 0; i < PQ_K; i++) {
        Poly uc;
        byte_decode(ct + i * c1_len, PQ_DU, uc);
        poly_decompress(uc, PQ_DU, u[i]);
    }
    Poly vc, v;
    byte_decode(ct + PQ_K * c1_len, PQ_DV, vc);
    poly_decompress(vc, PQ_DV, v);

    PolyVec s_hat;
    for (int i = 0; i < PQ_K; i++)
        byte_decode(dk->s_hat_enc + i * 384, 12, s_hat[i]);

    PolyVec u_hat;
    for (int i = 0; i < PQ_K; i++) { memcpy(u_hat[i], u[i], sizeof(Poly)); ntt(u_hat[i]); }

    Poly acc = {0};
    for (int j = 0; j < PQ_K; j++) {
        Poly prod;
        poly_mul_ntt(s_hat[j], u_hat[j], prod);
        poly_add(acc, prod, acc);
    }
    inv_ntt(acc);

    Poly w;
    poly_sub(v, acc, w);

    Poly wc;
    poly_compress(w, 1, wc);
    byte_encode(wc, 1, m);
}

/* ================================================================
 * §11 ML-KEM 공개 API (Alg.16~20 wrap)
 *
 * 경고: 위 NTT/CBD/압축 연산은 데이터 의존 분기가 없는 산술 위주라
 * 타이밍 누출 표면은 작지만, 엄밀한 상수시간 보증(마스킹 등)은
 * 하지 않았음. 로컬 파일 암호화(공격자가 같은 머신에서 정밀 타이밍
 * 측정을 할 수 없는 위협모델) 용도로 범위를 한정할 것.
 * ================================================================ */

int pq_mlkem768_keygen_internal(const uint8_t d[32], const uint8_t z[32],
                                 uint8_t ek[PQ_MLKEM768_EK_LEN],
                                 uint8_t dk[PQ_MLKEM768_DK_LEN])
{
    static int inited = 0;
    if (!inited) { zeta_init(); inited = 1; }

    PkeEk pke_ek; PkeDk pke_dk;
    pke_keygen(d, &pke_ek, &pke_dk);

    /* ek = t_hat_enc || rho */
    memcpy(ek, pke_ek.t_hat_enc, PQ_K * 384);
    memcpy(ek + PQ_K * 384, pke_ek.rho, 32);

    uint8_t h_ek[32];
    H(ek, PQ_MLKEM768_EK_LEN, h_ek);

    /* dk = s_hat_enc || ek || H(ek) || z */
    size_t off = 0;
    memcpy(dk + off, pke_dk.s_hat_enc, PQ_K * 384); off += PQ_K * 384;
    memcpy(dk + off, ek, PQ_MLKEM768_EK_LEN);         off += PQ_MLKEM768_EK_LEN;
    memcpy(dk + off, h_ek, 32);                        off += 32;
    memcpy(dk + off, z, 32);                            off += 32;

    return (off == PQ_MLKEM768_DK_LEN) ? 0 : -1;
}

int pq_mlkem768_keygen(uint8_t ek[PQ_MLKEM768_EK_LEN], uint8_t dk[PQ_MLKEM768_DK_LEN])
{
    uint8_t d[32], z[32];
    if (pq_random_bytes(d, 32) != 0) return -1;
    if (pq_random_bytes(z, 32) != 0) return -1;
    return pq_mlkem768_keygen_internal(d, z, ek, dk);
}

int pq_mlkem768_encaps_internal(const uint8_t ek[PQ_MLKEM768_EK_LEN],
                                 const uint8_t m[32],
                                 uint8_t ct[PQ_MLKEM768_CT_LEN],
                                 uint8_t ss[PQ_MLKEM768_SS_LEN])
{
    static int inited = 0;
    if (!inited) { zeta_init(); inited = 1; }

    uint8_t h_ek[32];
    H(ek, PQ_MLKEM768_EK_LEN, h_ek);

    uint8_t gin[64];
    memcpy(gin, m, 32);
    memcpy(gin + 32, h_ek, 32);
    uint8_t K[32], r[32];
    G(gin, 64, K, r);

    PkeEk pke_ek;
    memcpy(pke_ek.t_hat_enc, ek, PQ_K * 384);
    memcpy(pke_ek.rho, ek + PQ_K * 384, 32);

    pke_encrypt(&pke_ek, m, r, ct);
    memcpy(ss, K, 32);
    return 0;
}

int pq_mlkem768_encaps(const uint8_t ek[PQ_MLKEM768_EK_LEN],
                        uint8_t ct[PQ_MLKEM768_CT_LEN],
                        uint8_t ss[PQ_MLKEM768_SS_LEN])
{
    uint8_t m[32];
    if (pq_random_bytes(m, 32) != 0) return -1;
    return pq_mlkem768_encaps_internal(ek, m, ct, ss);
}

int pq_mlkem768_decaps(const uint8_t dk[PQ_MLKEM768_DK_LEN],
                        const uint8_t ct[PQ_MLKEM768_CT_LEN],
                        uint8_t ss[PQ_MLKEM768_SS_LEN])
{
    static int inited = 0;
    if (!inited) { zeta_init(); inited = 1; }

    PkeDk pke_dk;
    memcpy(pke_dk.s_hat_enc, dk, PQ_K * 384);
    const uint8_t *ek     = dk + PQ_K * 384;
    const uint8_t *h_ek   = ek + PQ_MLKEM768_EK_LEN;
    const uint8_t *z      = h_ek + 32;

    uint8_t mp[32];
    pke_decrypt(&pke_dk, ct, mp);

    uint8_t gin[64];
    memcpy(gin, mp, 32);
    memcpy(gin + 32, h_ek, 32);
    uint8_t Kp[32], rp[32];
    G(gin, 64, Kp, rp);

    uint8_t zct[32 + PQ_MLKEM768_CT_LEN];
    memcpy(zct, z, 32);
    memcpy(zct + 32, ct, PQ_MLKEM768_CT_LEN);
    uint8_t Kbar[32];
    J(zct, sizeof(zct), Kbar);

    PkeEk pke_ek;
    memcpy(pke_ek.t_hat_enc, ek, PQ_K * 384);
    memcpy(pke_ek.rho, ek + PQ_K * 384, 32);

    uint8_t ct2[PQ_MLKEM768_CT_LEN];
    pke_encrypt(&pke_ek, mp, rp, ct2);

    /* 상수시간 비교 (타이밍 누출 최소화) */
    uint8_t diff = 0;
    for (int i = 0; i < PQ_MLKEM768_CT_LEN; i++) diff |= (ct[i] ^ ct2[i]);

    /* diff==0 이면 Kp, 아니면 Kbar 를 상수시간에 선택 */
    uint8_t mask = (uint8_t)(-(diff == 0));  /* 0x00 or 0xFF */
    for (int i = 0; i < 32; i++)
        ss[i] = (Kp[i] & mask) | (Kbar[i] & (uint8_t)~mask);

    return 0;
}
