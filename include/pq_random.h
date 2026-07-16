/**
 * pq_random.h — 암호학적 난수 소스 (모든 키/시드/nonce 생성의 단일 출처)
 * pqenvEditor
 *
 * 이전까지는 pq_mlkem.c / pq_env_crypto.c / pq_env_editor_core.c /
 * pq_env_encrypt_cli.c 가 각자 /dev/urandom을 따로 열었다. 이 파일로
 * 하나로 합쳐서:
 *   1) getentropy() 우선 사용 (Linux/macOS 둘 다 지원, 커널 CSPRNG 직결)
 *   2) 실패시 /dev/urandom 폴백 — 단, poll()로 타임아웃을 걸어서
 *      엔트로피 풀이 아직 준비 안 된 임베디드/컨테이너 환경에서
 *      "영원히 블로킹"하는 대신 정해진 시간 안에 명확히 실패하게 함
 *   3) 절대로 비암호학적(예측 가능한) PRNG로 조용히 대체하지 않음 —
 *      실패하면 반드시 에러를 반환한다. 이건 협상 불가능한 보안
 *      불변식이다: 느리게/실패하는 게 "그럴듯해 보이지만 예측 가능한
 *      키"보다 훨씬 안전하다.
 */
#ifndef PQ_RANDOM_H
#define PQ_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * pq_random_bytes — 암호학적으로 안전한 난수 len바이트를 buf에 채움
 *
 * @return  0=성공
 *         -1=실패 (엔트로피 소스 없음 / 타임아웃 / 읽기 오류)
 *            실패 시 buf 내용은 사용하면 안 됨. stderr에 원인 진단 메시지 출력.
 */
int pq_random_bytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* PQ_RANDOM_H */
