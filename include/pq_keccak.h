/**
 * pq_keccak.h — Keccak-f[1600] 기반 SHA3 / SHAKE 구현
 * pqenvEditor (양자내성 .env 암호화 도구)
 *
 * FIPS 202 표준 구현. ML-KEM(FIPS 203)의 G/H/J/PRF/XOF 함수가
 * 전부 이 위에서 동작한다.
 *
 * 외부 라이브러리 미사용 — 표준 알고리즘 직접 구현.
 */
#ifndef PQ_KECCAK_H
#define PQ_KECCAK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── 단발성 해시 (one-shot) ───────────────────────────────── */
void pq_sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);
void pq_sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]);

/* SHAKE128/256 — 임의 길이 출력 */
void pq_shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
void pq_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

/* ── 스트리밍 XOF (ML-KEM의 rejection sampling에서 필요:
 *    출력을 얼마나 뽑을지 모르는 상태로 블록 단위로 계속 뽑아야 함) ── */
typedef struct {
    uint64_t s[25];      /* Keccak 상태 (5x5 x 64bit) */
    uint8_t  buf[200];   /* rate 블록 버퍼 (SHAKE128 rate=168, SHAKE256 rate=136) */
    size_t   rate;       /* 바이트 단위 rate */
    size_t   pos;        /* buf 내 현재 읽기 위치 (squeeze 단계) */
    int      absorbing;  /* 1=아직 absorb 단계, 0=squeeze 단계로 전환됨 */
    size_t   abs_pos;    /* absorb 단계에서 buf 내 누적 위치 */
} PqShakeCtx;

void pq_shake128_init(PqShakeCtx *ctx);
void pq_shake256_init(PqShakeCtx *ctx);
void pq_shake_absorb(PqShakeCtx *ctx, const uint8_t *in, size_t inlen);
void pq_shake_finalize(PqShakeCtx *ctx);   /* padding 적용, absorb 종료 */
void pq_shake_squeeze(PqShakeCtx *ctx, uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif
#endif /* PQ_KECCAK_H */
