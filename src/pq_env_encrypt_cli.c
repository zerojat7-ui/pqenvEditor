/**
 * pq_env_encrypt_cli.c — stdin으로 받은 평문을 암호화해 .kpqe로 저장
 * pqenvEditor
 *
 * 편집기 없이 스크립트/마이그레이션 파이프라인에서 쓰기 위한 도구.
 * 비밀키는 필요 없음(암호화는 공개키만으로 가능) — 기존 파일이 있으면
 * seq만 평문 헤더에서 미리 읽어(복호화 없이) 이어서 증가시킨다.
 *
 * 사용법:
 *   cat .env | pq_env_encrypt_cli ./.env.kpqe --pub ~/.atema/pq_public.key
 *   echo "FOO=bar" | pq_env_encrypt_cli ./new.env.kpqe --pub PATH
 */
#define _POSIX_C_SOURCE 200809L
#include "pq_env_crypto.h"
#include "pq_mlkem.h"
#include "pq_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static void expand_home(char *out, size_t outsz, const char *rel)
{
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(out, outsz, "%s/%s", home, rel);
}

static long file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <path.env.kpqe> [--pub PATH]\n", argv[0]);
        return 1;
    }
    char pub_default[512];
    expand_home(pub_default, sizeof(pub_default), ".atema/pq_public.key");

    const char *path = argv[1];
    const char *pub = pub_default;
    for (int i = 2; i < argc - 1; i++)
        if (strcmp(argv[i], "--pub") == 0) pub = argv[++i];

    uint8_t pubkey[PQ_MLKEM768_EK_LEN];
    if (pq_env_read_file_exact(pub, pubkey, PQ_MLKEM768_EK_LEN) != 0) {
        fprintf(stderr, "공개키를 읽을 수 없습니다: %s\n", pub);
        return 1;
    }

    /* stdin 전체 읽기 */
    size_t cap = 4096, len = 0;
    uint8_t *plaintext = malloc(cap);
    for (;;) {
        if (len == cap) { cap *= 2; plaintext = realloc(plaintext, cap); }
        size_t n = fread(plaintext + len, 1, cap - len, stdin);
        len += n;
        if (n == 0) break;
    }

    /* 기존 파일이 있으면 seq/file_id 이어받기 (복호화 없이 헤더만 읽음) */
    uint8_t file_id[PQ_ENV_FILE_ID_LEN];
    uint64_t seq = 0;
    long fsz = file_size(path);
    if (fsz >= (long)PQ_ENV_HDR_LEN) {
        uint8_t *old = malloc((size_t)fsz);
        if (pq_env_read_file_exact(path, old, (size_t)fsz) == 0 &&
            pq_env_peek_file_id(old, (size_t)fsz, file_id, &seq) == 0) {
            seq += 1;
        } else {
            fprintf(stderr, "기존 파일 헤더를 읽는 데 실패해 새로 생성합니다.\n");
            if (pq_random_bytes(file_id, sizeof(file_id)) != 0) {
                free(old);
                return 1;   /* pq_random이 이미 stderr에 원인 출력함 */
            }
            seq = 1;
        }
        free(old);
    } else {
        if (pq_random_bytes(file_id, sizeof(file_id)) != 0)
            return 1;
        seq = 1;
    }

    size_t out_len = PQ_ENV_HDR_LEN + len;
    uint8_t *out = malloc(out_len);
    if (pq_env_encrypt_file(pubkey, file_id, seq, plaintext, len, out) != 0) {
        fprintf(stderr, "암호화 실패\n");
        return 1;
    }
    if (pq_env_write_file_0600(path, out, out_len) != 0) {
        fprintf(stderr, "파일 저장 실패: %s\n", path);
        return 1;
    }

    char sidecar[600];
    snprintf(sidecar, sizeof(sidecar), "%s.seq", path);
    FILE *sf = fopen(sidecar, "w");
    if (sf) { fprintf(sf, "%llu\n", (unsigned long long)seq); fclose(sf); }

    memset(plaintext, 0, len);
    memset(out, 0, out_len);
    free(plaintext);
    free(out);

    fprintf(stderr, "저장됨: %s (seq=%llu)\n", path, (unsigned long long)seq);
    return 0;
}
