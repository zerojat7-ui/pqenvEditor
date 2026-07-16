/**
 * pq_env_decrypt_cli.c — 복호화된 내용을 stdout으로 출력
 * pqenvEditor
 *
 * pq_env_exec는 "프로세스를 통째로 대체 실행"하는 방식이라 언어 상관없이
 * 제일 안전하지만, 때로는 대상 프로그램이 자기 설정 시스템(JSON config,
 * 커스텀 파서 등)에 직접 넣고 싶어서 "값 자체"가 필요할 때가 있다.
 * 그럴 때 쓰는 최소 도구 — 그냥 복호화해서 KEY=VALUE 그대로 stdout에 찍는다.
 *
 * 보안 주의: 이 출력을 파일로 리다이렉트(`> .env`)하면 평문이 디스크에
 * 남는다 — 이 도구가 막으려던 바로 그 문제가 재발한다. 반드시 파이프로만
 * 다른 프로세스에 직접 넘길 것 (사용법 참고). 이건 sops -d, pass show 같은
 * 기존 시크릿 관리 CLI들도 동일하게 갖는 한계다.
 *
 * 사용법:
 *   ./pq_env_decrypt_cli ./.env.kpqe --sec ~/.atema/pq_secret.key
 *   ./pq_env_decrypt_cli ./.env.kpqe --sec SEC --key OPENAI_API_KEY   # 값 하나만
 *
 * 안전한 사용 예:
 *   export $(./pq_env_decrypt_cli ./.env.kpqe --sec SEC | xargs)
 *   docker run --env-file <(./pq_env_decrypt_cli ./.env.kpqe --sec SEC) myimage
 *   API_KEY=$(./pq_env_decrypt_cli ./.env.kpqe --sec SEC --key OPENAI_API_KEY)
 *
 * 위험한 사용 예 (하지 말 것):
 *   ./pq_env_decrypt_cli ./.env.kpqe --sec SEC > .env      # 평문이 디스크에 남음!
 */
#define _POSIX_C_SOURCE 200809L
#include "pq_env_crypto.h"
#include "pq_mlkem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* key와 정확히 일치하는 줄을 찾아 값만 stdout에 출력.
 * @return 1=찾음, 0=못찾음 */
static int print_single_key(const char *plaintext, size_t len, const char *key)
{
    size_t keylen = strlen(key);
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || plaintext[i] == '\n') {
            size_t linelen = i - start;
            const char *line = plaintext + start;
            if (linelen > keylen && line[0] != '#' &&
                strncmp(line, key, keylen) == 0 && line[keylen] == '=') {
                fwrite(line + keylen + 1, 1, linelen - keylen - 1, stdout);
                fputc('\n', stdout);
                return 1;
            }
            start = i + 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <path.env.kpqe> [--sec PATH] [--key NAME]\n", argv[0]);
        return 1;
    }
    char sec_default[512];
    expand_home(sec_default, sizeof(sec_default), ".atema/pq_secret.key");

    const char *path = argv[1];
    const char *sec = sec_default;
    const char *only_key = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sec") == 0 && i + 1 < argc) sec = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) only_key = argv[++i];
    }

    uint8_t seckey[PQ_MLKEM768_DK_LEN];
    if (pq_env_read_file_exact(sec, seckey, PQ_MLKEM768_DK_LEN) != 0) {
        fprintf(stderr, "비밀키를 읽을 수 없습니다: %s\n", sec);
        return 1;
    }

    long fsz = file_size(path);
    if (fsz < (long)PQ_ENV_HDR_LEN) {
        fprintf(stderr, "파일을 열 수 없거나 형식이 잘못됨: %s\n", path);
        memset(seckey, 0, sizeof(seckey));
        return 1;
    }

    uint8_t *filebuf = malloc((size_t)fsz);
    pq_env_read_file_exact(path, filebuf, (size_t)fsz);

    char sidecar[600];
    snprintf(sidecar, sizeof(sidecar), "%s.seq", path);
    FILE *sf = fopen(sidecar, "r");
    unsigned long long min_seq = 0;
    if (sf) { if (fscanf(sf, "%llu", &min_seq) != 1) min_seq = 0; fclose(sf); }

    size_t pt_len = (size_t)fsz - PQ_ENV_HDR_LEN;
    uint8_t *plaintext = malloc(pt_len + 1);
    uint64_t got_seq = 0;

    int r = pq_env_decrypt_file(seckey, filebuf, (size_t)fsz, min_seq,
                                 plaintext, &got_seq);
    memset(filebuf, 0, (size_t)fsz);
    free(filebuf);
    memset(seckey, 0, sizeof(seckey));

    if (r != 0) {
        const char *msg = (r == -2) ? "변조 감지(AEAD 태그 불일치)"
                         : (r == -3) ? "롤백 감지(예전 버전으로 되돌리기 시도)"
                         : "복호화 실패";
        fprintf(stderr, "%s — 출력을 거부합니다.\n", msg);
        memset(plaintext, 0, pt_len + 1);
        free(plaintext);
        return 1;
    }

    /* seq 사이드카 갱신 (다음 호출부터 롤백 방지 기준선이 됨) */
    FILE *out_seq = fopen(sidecar, "w");
    if (out_seq) { fprintf(out_seq, "%llu\n", (unsigned long long)got_seq); fclose(out_seq); }

    int ret = 0;
    if (only_key) {
        if (!print_single_key((const char *)plaintext, pt_len, only_key)) {
            fprintf(stderr, "키를 찾을 수 없습니다: %s\n", only_key);
            ret = 2;   /* '변조/롤백/IO'(1)과 구분되는 '키 없음' 전용 코드 */
        }
    } else {
        fwrite(plaintext, 1, pt_len, stdout);
    }

    memset(plaintext, 0, pt_len + 1);
    free(plaintext);
    return ret;
}
