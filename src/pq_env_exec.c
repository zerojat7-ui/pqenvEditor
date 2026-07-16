/**
 * pq_env_exec.c — 암호화된 .env를 "다른 프로그램"에 적용하는 CLI
 * pqenvEditor
 *
 * C로 링크할 수 없는 프로그램(파이썬/노드/셸스크립트/바이너리 등)에
 * 복호화된 값을 환경변수로 넘겨주는 실행기. execvp()로 대상 프로세스를
 * 그대로 대체하므로 이 프로그램 자신은 사라지고, 표준출력/파일 어디에도
 * 평문이 찍히지 않는다.
 *
 * 사용법:
 *   pq_env_exec <path.env.kpqe> [--pub PATH] [--sec PATH] [--only K1,K2,...] -- <command> [args...]
 *
 * 예:
 *   pq_env_exec ./.env.kpqe -- python3 app.py
 *   pq_env_exec ./.env.kpqe --sec ~/.atema/pq_secret.key -- node server.js
 *   pq_env_exec ./.env.kpqe -- ./my_c_program --flag
 *
 *   여러 서비스 키를 한 .env에 다 저장해두고, 이 프로그램에는 자기한테
 *   필요한 키만 넘기고 싶을 때 --only 사용(최소 권한 원칙):
 *     pq_env_exec ./.env.kpqe --only OPENAI_API_KEY -- python3 ai_worker.py
 *     pq_env_exec ./.env.kpqe --only DB_PASSWORD,DB_HOST -- ./db_migrate
 *   .env에 STRIPE_KEY/JWT_SECRET 등이 같이 있어도 ai_worker.py 프로세스
 *   환경에는 OPENAI_API_KEY 하나만 세팅된다 — 이 프로세스가 나중에 로그를
 *   흘리거나 침해당해도 무관한 다른 서비스의 시크릿까지 새지 않는다.
 */
#define _POSIX_C_SOURCE 200809L
#include "pq_env_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void expand_home(char *out, size_t outsz, const char *rel)
{
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(out, outsz, "%s/%s", home, rel);
}

/* "A,B,C" -> {"A","B","C"} (콤마 자리를 널로 바꿔 in-place 분할, 인자
 * 문자열은 argv가 가리키는 실제 메모리라 프로세스 생애 동안 안전) */
static int split_csv(char *s, const char **out, int max)
{
    int n = 0;
    char *tok = strtok(s, ",");
    while (tok && n < max) {
        out[n++] = tok;
        tok = strtok(NULL, ",");
    }
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "사용법: %s <path.env.kpqe> [--pub PATH] [--sec PATH] -- <command> [args...]\n",
            argv[0]);
        return 1;
    }

    char pub_default[512], sec_default[512];
    expand_home(pub_default, sizeof(pub_default), ".atema/pq_public.key");
    expand_home(sec_default, sizeof(sec_default), ".atema/pq_secret.key");

    const char *path = argv[1];
    const char *pub = pub_default;
    const char *sec = sec_default;
    char *only_csv = NULL;

    int i = 2;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc) { pub = argv[++i]; }
        else if (strcmp(argv[i], "--sec") == 0 && i + 1 < argc) { sec = argv[++i]; }
        else if (strcmp(argv[i], "--only") == 0 && i + 1 < argc) { only_csv = argv[++i]; }
        else if (strcmp(argv[i], "--") == 0) { i++; break; }
        else break;
    }

    if (i >= argc) {
        fprintf(stderr, "실행할 명령이 없습니다. '--' 뒤에 명령을 지정하세요.\n");
        return 1;
    }

    const char *only_keys[64];
    int n_only = 0;
    if (only_csv) n_only = split_csv(only_csv, only_keys, 64);

    int r = pq_env_load_into_process_filtered(path, pub, sec,
                                               only_csv ? only_keys : NULL, n_only);
    if (r == -1) {
        fprintf(stderr, "키를 읽을 수 없습니다.\n  공개키: %s\n  비밀키: %s\n", pub, sec);
        return 1;
    } else if (r == -2) {
        fprintf(stderr, "!! 변조 감지: AEAD 태그 불일치. 실행을 거부합니다.\n");
        return 1;
    } else if (r == -3) {
        fprintf(stderr, "!! 롤백 감지: 예전 버전으로 되돌리기 시도. 실행을 거부합니다.\n");
        return 1;
    } else if (r == -4) {
        fprintf(stderr, "IO 오류로 파일을 열 수 없습니다: %s\n", path);
        return 1;
    }

    /* 현재 프로세스를 대상 명령으로 완전히 대체 — 이 프로그램의 흔적(평문을
     * 잠깐 들고 있던 프로세스)조차 exec 이후에는 존재하지 않음 */
    execvp(argv[i], &argv[i]);

    /* execvp가 반환했다는 건 실패했다는 뜻 */
    fprintf(stderr, "실행 실패: %s (%s)\n", argv[i], strerror(errno));
    return 127;
}
