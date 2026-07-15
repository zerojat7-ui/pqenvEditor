/**
 * pq_env_loader.c — pq_env_load_into_process() 구현
 * pqenvEditor
 */
#define _POSIX_C_SOURCE 200809L
#include "pq_env_loader.h"
#include "pq_env_crypto.h"
#include "pq_mlkem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static long file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

/* seq 사이드카 — pq_env_editor_core.c와 동일한 관례("<path>.seq")를 따르되
 * 로더는 에디터 코어에 의존하지 않도록 여기서 별도로 최소 구현한다. */
static uint64_t seq_load(const char *sidecar)
{
    FILE *f = fopen(sidecar, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return (uint64_t)v;
}
static void seq_store(const char *sidecar, uint64_t seq)
{
    FILE *f = fopen(sidecar, "w");
    if (!f) return;
    fprintf(f, "%llu\n", (unsigned long long)seq);
    fclose(f);
}

/* only_keys가 NULL이면 전부 setenv, 아니면 목록에 있는 키(정확 일치)만 */
static int key_allowed(const char *key, const char **only_keys, int n_only_keys)
{
    if (!only_keys) return 1;
    for (int i = 0; i < n_only_keys; i++)
        if (strcmp(key, only_keys[i]) == 0) return 1;
    return 0;
}

static void apply_env_lines(char *plaintext, size_t len,
                             const char **only_keys, int n_only_keys)
{
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || plaintext[i] == '\n') {
            size_t linelen = i - start;
            if (linelen > 0) {
                char *line = plaintext + start;
                line[linelen] = '\0';   /* '\n' 자리를 임시로 널 종료로 사용 */

                if (line[0] != '#') {
                    char *eq = strchr(line, '=');
                    if (eq) {
                        *eq = '\0';
                        const char *key = line;
                        const char *val = eq + 1;
                        if (key[0] != '\0' && key_allowed(key, only_keys, n_only_keys))
                            setenv(key, val, 1);
                        *eq = '=';   /* 원상복구(아래 memset으로 어차피 지워짐) */
                    }
                }
                line[linelen] = '\n';   /* 원상복구 */
            }
            start = i + 1;
        }
    }
}

int pq_env_load_into_process(const char *path,
                              const char *pubkey_path,
                              const char *seckey_path)
{
    return pq_env_load_into_process_filtered(path, pubkey_path, seckey_path, NULL, 0);
}

int pq_env_load_into_process_filtered(const char *path,
                                       const char *pubkey_path,
                                       const char *seckey_path,
                                       const char **only_keys,
                                       int n_only_keys)
{
    uint8_t seckey[PQ_MLKEM768_DK_LEN];
    if (pq_env_read_file_exact(seckey_path, seckey, PQ_MLKEM768_DK_LEN) != 0) {
        memset(seckey, 0, sizeof(seckey));
        return -1;
    }
    (void)pubkey_path; /* 로드(복호화)에는 비밀키만 필요 — 공개키는 안 씀 */

    long fsz = file_size(path);
    if (fsz < 0 || (size_t)fsz < PQ_ENV_HDR_LEN) {
        memset(seckey, 0, sizeof(seckey));
        return -4;
    }

    uint8_t *filebuf = malloc((size_t)fsz);
    if (!filebuf) { memset(seckey, 0, sizeof(seckey)); return -4; }
    if (pq_env_read_file_exact(path, filebuf, (size_t)fsz) != 0) {
        free(filebuf); memset(seckey, 0, sizeof(seckey));
        return -4;
    }

    char sidecar[600];
    snprintf(sidecar, sizeof(sidecar), "%s.seq", path);
    uint64_t min_seq = seq_load(sidecar);

    size_t pt_len = (size_t)fsz - PQ_ENV_HDR_LEN;
    uint8_t *plaintext = malloc(pt_len + 1); /* +1: 마지막 줄 널종료 여유 */
    uint64_t got_seq = 0;

    int r = pq_env_decrypt_file(seckey, filebuf, (size_t)fsz, min_seq,
                                 plaintext, &got_seq);

    memset(filebuf, 0, (size_t)fsz);
    free(filebuf);
    memset(seckey, 0, sizeof(seckey));

    if (r == 0) {
        plaintext[pt_len] = '\0';
        apply_env_lines((char *)plaintext, pt_len, only_keys, n_only_keys);
        seq_store(sidecar, got_seq);
    }

    memset(plaintext, 0, pt_len + 1);
    free(plaintext);

    return r;   /* 0, -2(변조), -3(롤백), -4(IO) 그대로 전달 */
}
