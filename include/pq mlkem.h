/**
 * pq_mlkem.h — ML-KEM-768 (FIPS 203, 구 Kyber768) 구현
 * pqenvEditor (양자내성 .env 암호화 도구)
 *
 * NIST FIPS 203 ipd (Kyber round-3 호환, Â-fix 적용) 기준.
 * C2SP/CCTV 공식 누적 테스트벡터(10,000회) 완전 일치 검증 완료:
 *   ML-KEM-768 expected: f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3
 *   본 구현 결과       : f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3  ✅ MATCH
 * 외부 라이브러리 미사용 — pq_keccak.h 위에서 직접 구현.
 *
 * 크기 (ML-KEM-768, k=3):
 *   공개키(ek)   1184 B
 *   비밀키(dk)   2400 B
 *   암호문(ct)   1088 B
 *   공유비밀(K)    32 B
 *
 * 경고:
 *   격자암호 수학(NTT/CBD 등) 구현은 상수시간(constant-time)이
 *   아직 아님 — 로컬 단일 사용자 파일 암호화 용도로는 사이드채널
 *   위협 모델이 낮지만, 이 코드를 원격/공유 환경에 그대로 쓰면 안 됨.
 *   §11 참조.
 */
#ifndef PQ_MLKEM_H
#define PQ_MLKEM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_MLKEM768_EK_LEN   1184
#define PQ_MLKEM768_DK_LEN   2400
#define PQ_MLKEM768_CT_LEN   1088
#define PQ_MLKEM768_SS_LEN   32     /* 공유 비밀(shared secret) 길이 */
#define PQ_MLKEM768_SEED_LEN 32     /* d, z, m 각각의 길이 */

/**
 * pq_mlkem768_keygen — 키 쌍 생성 (내부에서 안전한 난수 32B×2 사용)
 * @param ek  [out] 공개키 1184B
 * @param dk  [out] 비밀키 2400B
 * @return 0=성공, -1=난수 생성 실패
 */
int pq_mlkem768_keygen(uint8_t ek[PQ_MLKEM768_EK_LEN],
                        uint8_t dk[PQ_MLKEM768_DK_LEN]);

/**
 * pq_mlkem768_keygen_internal — 결정론적 키 생성 (테스트/KAT 전용)
 * d, z를 외부에서 주입. 프로덕션 코드에서는 pq_mlkem768_keygen() 사용.
 */
int pq_mlkem768_keygen_internal(const uint8_t d[PQ_MLKEM768_SEED_LEN],
                                 const uint8_t z[PQ_MLKEM768_SEED_LEN],
                                 uint8_t ek[PQ_MLKEM768_EK_LEN],
                                 uint8_t dk[PQ_MLKEM768_DK_LEN]);

/**
 * pq_mlkem768_encaps — 캡슐화 (공유비밀 생성 + 암호문 생성)
 * @param ek  [in]  공개키 1184B
 * @param ct  [out] 암호문 1088B
 * @param ss  [out] 공유비밀 32B (이 값으로 AEAD 대칭키 유도)
 * @return 0=성공, -1=난수/입력 오류
 */
int pq_mlkem768_encaps(const uint8_t ek[PQ_MLKEM768_EK_LEN],
                        uint8_t ct[PQ_MLKEM768_CT_LEN],
                        uint8_t ss[PQ_MLKEM768_SS_LEN]);

/**
 * pq_mlkem768_encaps_internal — 결정론적 캡슐화 (테스트/KAT 전용)
 */
int pq_mlkem768_encaps_internal(const uint8_t ek[PQ_MLKEM768_EK_LEN],
                                 const uint8_t m[PQ_MLKEM768_SEED_LEN],
                                 uint8_t ct[PQ_MLKEM768_CT_LEN],
                                 uint8_t ss[PQ_MLKEM768_SS_LEN]);

/**
 * pq_mlkem768_decaps — 역캡슐화 (묵시적 거부(implicit rejection) 포함)
 * @param dk  [in]  비밀키 2400B
 * @param ct  [in]  암호문 1088B
 * @param ss  [out] 공유비밀 32B
 * @return 0=성공 (참고: FO 변환 특성상 위조 ct에도 "성공"처럼 값이 나오되
 *              그 값은 예측 불가능한 난수라 공격자가 못 씀 — 스펙 의도된 동작)
 */
int pq_mlkem768_decaps(const uint8_t dk[PQ_MLKEM768_DK_LEN],
                        const uint8_t ct[PQ_MLKEM768_CT_LEN],
                        uint8_t ss[PQ_MLKEM768_SS_LEN]);

#ifdef __cplusplus
}
#endif
#endif /* PQ_MLKEM_H */
