/**
 * pq_env_loader.h — 암호화된 .env를 다른 프로그램에 "적용"하는 방법
 * pqenvEditor
 *
 * 여기 API는 두 가지 방식을 제공한다:
 *
 * 1) C 프로그램에 직접 링크 — 가장 안전, 평문이 프로세스 메모리를 벗어나지 않음
 *      #include "pq_env_loader.h"
 *      pq_env_load_into_process("./.env.kpqe", pub_path, sec_path);
 *      // 이후 getenv("OPENAI_API_KEY") 등으로 정상 사용
 *
 * 2) C가 아닌 다른 프로그램(파이썬/노드/셸 스크립트 등) — CLI exec 래퍼
 *      pq_env_loader ./.env.kpqe --pub P --sec S -- python3 app.py
 *      복호화된 값을 환경변수로 세팅한 뒤 execvp()로 대상 프로그램을 그대로
 *      대체 실행한다. 표준출력/파일 어디에도 평문이 찍히지 않는다.
 *      (단, 실행된 자식 프로세스의 환경변수는 같은 사용자의 다른 프로세스가
 *       /proc/<pid>/environ 등으로 볼 수 있다는 건 OS 수준의 일반적인 한계다 —
 *       direnv/dotenv-cli 등 어떤 .env 로더도 이 한계는 동일하게 가진다.)
 */
#ifndef PQ_ENV_LOADER_H
#define PQ_ENV_LOADER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * pq_env_load_into_process
 *   .kpqe 파일을 복호화해 KEY=VALUE 줄들을 파싱하고, 각각 setenv()로
 *   현재 프로세스 환경에 적용한다. 평문은 함수 안에서만 존재하고
 *   반환 전에 메모리를 지운다.
 *
 *   파싱 규칙(단순 .env 포맷): 빈 줄/ '#'로 시작하는 줄은 무시, 그 외
 *   줄은 첫 '=' 기준으로 KEY/VALUE 분리. 쉘 스타일 따옴표/이스케이프는
 *   해석하지 않는다(값 그대로 사용) — 필요하면 값에 따옴표를 넣지 말 것.
 *
 * @return  0=성공
 *         -1=키 로드 실패 / 형식 오류
 *         -2=AEAD 태그 불일치(변조)
 *         -3=seq 롤백 감지
 *         -4=IO 오류
 */
int pq_env_load_into_process(const char *path,
                              const char *pubkey_path,
                              const char *seckey_path);

/**
 * pq_env_load_into_process_filtered
 *   여러 서비스의 키를 한 .env에 다 저장해두고, 프로그램마다 자기한테
 *   필요한 키만 받게 하고 싶을 때(최소 권한 원칙) 쓴다 — 파일 하나에
 *   OPENAI_API_KEY / STRIPE_KEY / DB_PASSWORD 가 다 있어도, 이 프로그램은
 *   "OPENAI_API_KEY"만 받도록 제한 가능. 나머지 키는 환경변수로 아예
 *   세팅되지 않아서, 이 프로세스가 나중에 로그를 흘리거나 침해당해도
 *   무관한 다른 서비스의 시크릿까지 같이 새지 않는다.
 *
 * @param only_keys   허용할 키 이름 배열(정확 일치). NULL이면 전부 허용
 *                    (=pq_env_load_into_process()와 동일 동작)
 * @param n_only_keys only_keys 배열 길이 (only_keys가 NULL이면 무시)
 * @return  pq_env_load_into_process()와 동일한 반환 코드
 */
int pq_env_load_into_process_filtered(const char *path,
                                       const char *pubkey_path,
                                       const char *seckey_path,
                                       const char **only_keys,
                                       int n_only_keys);

#ifdef __cplusplus
}
#endif
#endif /* PQ_ENV_LOADER_H */
