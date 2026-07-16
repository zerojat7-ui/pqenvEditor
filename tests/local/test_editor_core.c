#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pq_env_editor_core.h"
#include "pq_env_crypto.h"

static void add_line(PqEditBuf *buf, const char *s) {
    int n = buf->numrows + 1;
    buf->rows = realloc(buf->rows, sizeof(PqEditRow) * n);
    PqEditRow *r = &buf->rows[buf->numrows];
    r->len = (int)strlen(s);
    r->chars = strdup(s);
    buf->numrows = n;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 매 실행마다 격리된 임시 디렉터리 사용 — 실제 ~/.atema/나
     * 고정 /tmp 경로를 절대 건드리지 않음 (병렬 실행/CI에서도 충돌 없음) */
    char tmpl[] = "/tmp/pqenv_test_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }
    printf("sandbox dir: %s\n", dir);

    char pub[256], sec[256], envfile[256], seqfile[256];
    snprintf(pub, sizeof(pub), "%s/pub.key", dir);
    snprintf(sec, sizeof(sec), "%s/sec.key", dir);
    snprintf(envfile, sizeof(envfile), "%s/test.env.kpqe", dir);
    snprintf(seqfile, sizeof(seqfile), "%s/test.env.kpqe.seq", dir);

    if (pq_env_keypair_generate(sec, pub) != 0) { printf("keypair gen FAIL\n"); return 1; }
    printf("keypair generated: OK\n");

    /* ── split/join 라운드트립 단독 테스트 ── */
    {
        PqEditBuf b; memset(&b, 0, sizeof(b));
        const char *text = "FOO=bar\nBAZ=qux\n";
        pq_edit_split_lines(&b, text, strlen(text));
        printf("split: numrows=%d (expect 2) row0='%s' row1='%s'\n",
               b.numrows, b.rows[0].chars, b.rows[1].chars);
        size_t jl;
        char *joined = pq_edit_join_lines(&b, &jl);
        printf("join roundtrip: %s (len=%zu)\n",
               (jl == strlen(text) && memcmp(joined, text, jl) == 0) ? "MATCH" : "MISMATCH", jl);
        free(joined);
        for (int i=0;i<b.numrows;i++) free(b.rows[i].chars);
        free(b.rows);
    }

    /* ── 신규 파일 열기 (파일 없음) ── */
    PqEditBuf buf;
    int r = pq_edit_open(&buf, envfile, pub, sec);
    printf("open (new file): r=%d (expect 1)\n", r);

    add_line(&buf, "OPENAI_API_KEY=sk-abc123");
    add_line(&buf, "DB_PASSWORD=hunter2");
    buf.dirty = 1;

    r = pq_edit_save(&buf);
    printf("save #1: r=%d (expect 0) seq=%llu\n", r, (unsigned long long)buf.seq);
    pq_edit_free(&buf);

    /* ── 재오픈 → 내용 확인 ── */
    PqEditBuf buf2;
    r = pq_edit_open(&buf2, envfile, pub, sec);
    printf("re-open: r=%d (expect 0) numrows=%d seq=%llu\n",
           r, buf2.numrows, (unsigned long long)buf2.seq);
    for (int i = 0; i < buf2.numrows; i++)
        printf("  row[%d]='%s'\n", i, buf2.rows[i].chars);

    /* ── 내용 수정 후 재저장 (seq 증가 확인) ── */
    free(buf2.rows[1].chars);
    buf2.rows[1].chars = strdup("DB_PASSWORD=hunter3");
    buf2.rows[1].len = (int)strlen(buf2.rows[1].chars);
    r = pq_edit_save(&buf2);
    printf("save #2: r=%d (expect 0) seq=%llu (expect 2)\n", r, (unsigned long long)buf2.seq);
    pq_edit_free(&buf2);

    /* ── 세 번째로 열어서 최신 내용/seq 확인 ── */
    PqEditBuf buf3;
    r = pq_edit_open(&buf3, envfile, pub, sec);
    printf("re-open #2: r=%d seq=%llu row1='%s' (expect hunter3)\n",
           r, (unsigned long long)buf3.seq, buf3.rows[1].chars);
    pq_edit_free(&buf3);

    /* 샌드박스 정리 — 키/암호문 흔적을 디스크에 남기지 않음 */
    unlink(pub); unlink(sec); unlink(envfile); unlink(seqfile);
    rmdir(dir);
    printf("sandbox cleaned up: %s\n", dir);

    return 0;
}
