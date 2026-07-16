/**
 * pq_env_editor_core.h — 암호화 .env 편집기 핵심 로직
 * pqenvEditor
 *
 * 터미널 렌더링/키입력과 분리된 부분만 모아 유닛테스트 가능하게 함.
 * 실제 화면 그리기/raw mode는 pq_env_editor.c(main)에 있음.
 */
#ifndef PQ_ENV_EDITOR_CORE_H
#define PQ_ENV_EDITOR_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── 줄 단위 버퍼 ─────────────────────────────────────────────── */
typedef struct {
    char *chars;
    int   len;
} PqEditRow;

typedef struct {
    PqEditRow *rows;
    int        numrows;
    int        dirty;          /* 저장 안 된 변경 여부 */

    char      *path;           /* .kpqe 파일 경로 */
    char      *seq_sidecar;    /* "<path>.seq" — 롤백 방지 상태 */

    uint8_t    pubkey[1184];
    uint8_t    seckey[2400];
    int        have_seckey;    /* 0=공개키만 있음(읽기 불가, 새 파일 생성만 가능) */

    uint8_t    file_id[16];
    uint64_t   seq;            /* 마지막으로 확인/저장한 seq */
} PqEditBuf;

/* ── 평문 <-> 줄 배열 직렬화 ──────────────────────────────────── */
void pq_edit_split_lines(PqEditBuf *buf, const char *text, size_t len);
/* 반환 버퍼는 호출자가 free(). *out_len에 길이(널 미포함) 기록 */
char *pq_edit_join_lines(const PqEditBuf *buf, size_t *out_len);

/* ── seq 사이드카 파일 (<path>.seq, 0600, 10진수 텍스트) ─────────── */
uint64_t pq_edit_seq_load(const char *sidecar_path);      /* 없으면 0 */
int      pq_edit_seq_store(const char *sidecar_path, uint64_t seq);

/* ── 키 로드 ──────────────────────────────────────────────────── */
int pq_edit_load_keys(PqEditBuf *buf, const char *pubkey_path,
                       const char *seckey_path /* NULL 허용 */);

/* ── 열기/저장 (암복호화 포함) ────────────────────────────────── */
/**
 * @return 0=성공(기존 파일 로드), 1=신규 생성(파일 없음, 빈 버퍼로 시작),
 *        -1=키 오류, -2=변조(태그 불일치), -3=롤백 감지, -4=기타 IO 오류,
 *        -5=CSPRNG 사용 불가(엔트로피 소스 없음/타임아웃 — 임베디드·컨테이너
 *           환경에서 발생 가능, pq_random.c가 stderr에 상세 원인 출력)
 */
int pq_edit_open(PqEditBuf *buf, const char *path,
                  const char *pubkey_path, const char *seckey_path);

/**
 * 현재 버퍼를 암호화해 저장. 성공 시 seq/dirty 갱신, 사이드카 파일 갱신.
 * @return 0=성공, -1=비밀키 없음(공개키만으론 재캡슐화는 가능하나 무결성상
 *             seckey로 이전 seq 확인이 안 되면 새 파일로 간주),
 *         -4=IO 오류
 */
int pq_edit_save(PqEditBuf *buf);

/* 버퍼/키 메모리를 확실히 지우고 해제 (평문 잔존 방지) */
void pq_edit_free(PqEditBuf *buf);

#ifdef __cplusplus
}
#endif
#endif /* PQ_ENV_EDITOR_CORE_H */
