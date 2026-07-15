/**
 * pq_env_crypto.h — 양자내성 .env 암호화 포맷
 * pqenvEditor
 *
 * 스택:
 *   ML-KEM-768 (FIPS 203 ipd, CCTV KAT 검증완료) — 키캡슐화
 *   ChaCha20-Poly1305 (RFC 8439, 공식벡터 검증완료) — 실제 내용 AEAD
 *
 * 위협모델 — "AI/제3자에 의한 .env 변조 방지":
 *   1. 내용 위조   → AEAD 태그가 없으면 복호화 자체가 실패 (거짓 수정 불가능,
 *                    ML-KEM 비밀키 없이는 태그를 위조할 수 없음)
 *   2. 롤백/재생   → seq 단조증가 카운터를 별도 로컬 상태파일과 대조.
 *                    "예전의 유효했던 암호문으로 되돌려치기"를 탐지
 *   3. 평문 노출   → 디스크에 평문 .env가 존재하는 시간을 편집 세션 중으로만 한정
 *                    (edit 워크플로우 §4)
 *
 * 파일 포맷 (.env.kpqe):
 *   [4B]    magic "KPQE"
 *   [1B]    version (=1)
 *   [3B]    reserved
 *   [1088B] mlkem_ct   (이 저장 시점의 ML-KEM-768 캡슐)
 *   [8B]    seq        (빅엔디안 단조증가 카운터)
 *   [16B]   file_id    (최초 생성시 난수 고정 — seq 상태파일과 짝짓기용)
 *   [12B]   nonce      (ChaCha20 nonce)
 *   [16B]   tag        (Poly1305 태그)
 *   [N]     ciphertext (.env 평문 길이 N)
 *   AAD = magic..file_id 전체 (1123B, 위 위치까지 전부 인증)
 */
#ifndef PQ_ENV_CRYPTO_H
#define PQ_ENV_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_ENV_MAGIC        "KPQE"
#define PQ_ENV_VERSION      1
#define PQ_ENV_HDR_LEN      (4+1+3+1088+8+16+12+16)   /* 1148B 고정 헤더 */
#define PQ_ENV_FILE_ID_LEN  16

/* ── 키 관리 ──────────────────────────────────────────────────── */

/**
 * pq_env_keypair_generate — ML-KEM-768 키쌍 생성 + 파일 저장
 * @param seckey_path  비밀키 저장 경로 (0600 권한으로 생성)
 * @param pubkey_path  공개키 저장 경로
 * @return 0=성공
 *
 * 엔진 초기화 스크립트나 최초 설정 단계에서 1회 호출하는 걸 권장.
 */
int pq_env_keypair_generate(const char *seckey_path, const char *pubkey_path);

/* ── 암/복호화 ────────────────────────────────────────────────── */

/**
 * pq_env_encrypt_file
 *   평문 .env 내용을 암호화해 .kpqe 포맷 버퍼로 만든다.
 * @param pubkey        ML-KEM-768 공개키 (1184B, 파일에서 읽어온 것)
 * @param file_id       16B — 최초 생성시 난수, 이후 재저장시 동일값 재사용
 * @param seq           이번 저장의 seq 값 (호출자가 이전값+1로 관리)
 * @param plaintext     .env 평문
 * @param plaintext_len
 * @param out           [out] 호출자가 PQ_ENV_HDR_LEN+plaintext_len 만큼 할당
 * @return 0=성공
 */
int pq_env_encrypt_file(const uint8_t pubkey[1184],
                         const uint8_t file_id[PQ_ENV_FILE_ID_LEN],
                         uint64_t seq,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *out);

/**
 * pq_env_decrypt_file
 *   .kpqe 포맷 버퍼를 복호화. 롤백 검사 포함.
 * @param seckey         ML-KEM-768 비밀키 (2400B)
 * @param in             .kpqe 파일 전체 바이트
 * @param in_len
 * @param min_seq        이 값보다 작은 seq는 거부 (마지막으로 확인한 seq —
 *                       같은 값이면 "변경 없음"으로 정상 허용, 그보다 작으면
 *                       롤백/재생 공격으로 간주)
 * @param out_plaintext  [out] 호출자가 (in_len - PQ_ENV_HDR_LEN) 만큼 할당
 * @param out_seq        [out] 파일에서 읽은 seq (성공 시 호출자가 저장소 갱신)
 * @return  0=성공
 *         -1=포맷/매직 오류
 *         -2=AEAD 태그 불일치 (변조됨)
 *         -3=seq 롤백 감지 (예전 버전으로 되돌리기 시도)
 */
int pq_env_decrypt_file(const uint8_t seckey[2400],
                         const uint8_t *in, size_t in_len,
                         uint64_t min_seq,
                         uint8_t *out_plaintext, uint64_t *out_seq);

/* ── CLI edit 워크플로우용 파일 I/O 헬퍼 (0600 권한 고정) ────────── */
int pq_env_write_file_0600(const char *path, const uint8_t *data, size_t len);
int pq_env_read_file_exact(const char *path, uint8_t *data, size_t len);

/**
 * pq_env_peek_file_id — 복호화 없이 file_id/seq만 미리 읽기
 * (재저장 시 file_id를 그대로 재사용하기 위한 용도. 이 값들은 비밀이
 *  아니며 AEAD 인증 검증 전에 읽어도 보안상 문제 없음 — 위조된 파일이면
 *  어차피 뒤이은 pq_env_decrypt_file()에서 태그 검증에 실패함)
 * @return 0=성공, -1=형식 오류(길이 부족/매직 불일치)
 */
int pq_env_peek_file_id(const uint8_t *in, size_t in_len,
                         uint8_t file_id[PQ_ENV_FILE_ID_LEN], uint64_t *seq);

#ifdef __cplusplus
}
#endif
#endif /* PQ_ENV_CRYPTO_H */
