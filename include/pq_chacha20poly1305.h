/**
 * pq_chacha20poly1305.h — ChaCha20-Poly1305 AEAD (RFC 8439)
 * pqenvEditor (양자내성 .env 암호화 도구)
 *
 * ML-KEM으로 캡슐화한 32B 공유비밀을 대칭키로 써서
 * 실제 .env 내용을 암/복호화하는 AEAD 레이어.
 */
#ifndef PQ_CHACHA20POLY1305_H
#define PQ_CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_CHACHA_KEY_LEN   32
#define PQ_CHACHA_NONCE_LEN 12
#define PQ_POLY1305_TAG_LEN 16

/**
 * pq_chacha20poly1305_encrypt
 *   AEAD 암호화. ct 버퍼는 pt와 같은 길이, tag는 별도 16B.
 * @param key    32B 대칭키
 * @param nonce  12B (재사용 금지 — 매 암호화마다 새 난수)
 * @param aad    부가 인증 데이터 (무결성만 검증, 암호화되지 않음). NULL 허용.
 * @param aad_len
 * @param pt     평문
 * @param pt_len
 * @param ct     [out] 암호문 (pt_len과 동일 길이)
 * @param tag    [out] 16B 인증 태그
 */
void pq_chacha20poly1305_encrypt(const uint8_t key[PQ_CHACHA_KEY_LEN],
                                  const uint8_t nonce[PQ_CHACHA_NONCE_LEN],
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint8_t *ct,
                                  uint8_t tag[PQ_POLY1305_TAG_LEN]);

/**
 * pq_chacha20poly1305_decrypt
 * @return 0=성공(인증 통과), -1=태그 불일치(변조/오류 — pt 버퍼 신뢰 금지)
 */
int pq_chacha20poly1305_decrypt(const uint8_t key[PQ_CHACHA_KEY_LEN],
                                 const uint8_t nonce[PQ_CHACHA_NONCE_LEN],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ct, size_t ct_len,
                                 const uint8_t tag[PQ_POLY1305_TAG_LEN],
                                 uint8_t *pt);

#ifdef __cplusplus
}
#endif
#endif /* PQ_CHACHA20POLY1305_H */
