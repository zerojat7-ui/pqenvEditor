/**
 * pq_env_editor_core.c — 암호화 .env 편집기 핵심 로직 구현
 * pqenvEditor
 */
#define _POSIX_C_SOURCE 200809L
#include "pq_env_editor_core.h"
#include "pq_env_crypto.h"
#include "pq_mlkem.h"
#include "pq_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* ================================================================
 * §1  평문 <-> 줄 배열
 * ================================================================ */

static void free_rows(PqEditBuf *buf)
{
    for (int i = 0; i < buf->numrows; i++) {
        if (buf->rows[i].chars) {
            /* 평문 잔존 방지 — 해제 전 0으로 지움 */
            memset(buf->rows[i].chars, 0, (size_t)buf->rows[i].len);
            free(buf->rows[i].chars);
        }
    }
    free(buf->rows);
    buf->rows = NULL;
    buf->numrows = 0;
}

void pq_edit_split_lines(PqEditBuf *buf, const char *text, size_t len)
{
    free_rows(buf);

    if (len == 0) { buf->rows = NULL; buf->numrows = 0; return; }

    /* 줄 수 세기 */
    int nlines = 1;
    for (size_t i = 0; i < len; i++) if (text[i] == '\n') nlines++;
    /* text가 '\n'으로 끝나면 마지막 "빈 줄"은 만들지 않음(트레일링 개행 처리) */
    if (text[len - 1] == '\n') nlines--;

    if (nlines <= 0) { buf->rows = NULL; buf->numrows = 0; return; }

    buf->rows = (PqEditRow *)calloc((size_t)nlines, sizeof(PqEditRow));
    buf->numrows = 0;

    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || text[i] == '\n') {
            if (i == len && start == i) break; /* 끝에서 빈 조각 스킵 */
            size_t linelen = i - start;
            PqEditRow *r = &buf->rows[buf->numrows++];
            r->len = (int)linelen;
            r->chars = (char *)malloc(linelen + 1);
            if (linelen) memcpy(r->chars, text + start, linelen);
            r->chars[linelen] = '\0';
            start = i + 1;
        }
    }
}

char *pq_edit_join_lines(const PqEditBuf *buf, size_t *out_len)
{
    size_t total = 0;
    for (int i = 0; i < buf->numrows; i++)
        total += (size_t)buf->rows[i].len + 1;   /* +1 = 줄마다 '\n' 부착 */

    char *out = (char *)malloc(total > 0 ? total : 1);
    size_t pos = 0;
    for (int i = 0; i < buf->numrows; i++) {
        memcpy(out + pos, buf->rows[i].chars, (size_t)buf->rows[i].len);
        pos += (size_t)buf->rows[i].len;
        out[pos++] = '\n';
    }
    if (out_len) *out_len = total;
    return out;
}

/* ================================================================
 * §2  seq 사이드카
 * ================================================================ */

uint64_t pq_edit_seq_load(const char *sidecar_path)
{
    FILE *f = fopen(sidecar_path, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return (uint64_t)v;
}

int pq_edit_seq_store(const char *sidecar_path, uint64_t seq)
{
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "%llu\n", (unsigned long long)seq);
    if (n < 0) return -1;
    int fd = open(sidecar_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    ssize_t w = write(fd, tmp, (size_t)n);
    close(fd);
    return (w == n) ? 0 : -1;
}

/* ================================================================
 * §3  키 로드
 * ================================================================ */

int pq_edit_load_keys(PqEditBuf *buf, const char *pubkey_path,
                       const char *seckey_path)
{
    if (pq_env_read_file_exact(pubkey_path, buf->pubkey, PQ_MLKEM768_EK_LEN) != 0)
        return -1;

    buf->have_seckey = 0;
    if (seckey_path) {
        if (pq_env_read_file_exact(seckey_path, buf->seckey, PQ_MLKEM768_DK_LEN) == 0)
            buf->have_seckey = 1;
    }
    return 0;
}

/* ================================================================
 * §4  파일 크기 조회 헬퍼
 * ================================================================ */
static long file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}


/* ================================================================
 * §5  열기
 * ================================================================ */
int pq_edit_open(PqEditBuf *buf, const char *path,
                  const char *pubkey_path, const char *seckey_path)
{
    memset(buf, 0, sizeof(*buf));
    buf->path = strdup(path);

    size_t plen = strlen(path);
    buf->seq_sidecar = (char *)malloc(plen + 5);
    memcpy(buf->seq_sidecar, path, plen);
    memcpy(buf->seq_sidecar + plen, ".seq", 5);

    if (pq_edit_load_keys(buf, pubkey_path, seckey_path) != 0)
        return -1;

    long fsz = file_size(path);
    if (fsz < 0) {
        /* 신규 파일 — 랜덤 file_id, seq=0, 빈 버퍼로 시작 */
        if (pq_random_bytes(buf->file_id, PQ_ENV_FILE_ID_LEN) != 0)
            return -5;   /* CSPRNG 없이는 파일 식별자도 못 만듦 — 조용히 넘어가지 않음 */
        buf->seq = 0;
        buf->numrows = 0;
        buf->rows = NULL;
        buf->dirty = 0;
        return 1;
    }

    if (!buf->have_seckey) return -1;   /* 기존 파일인데 비밀키가 없음 */

    uint8_t *filebuf = (uint8_t *)malloc((size_t)fsz);
    if (pq_env_read_file_exact(path, filebuf, (size_t)fsz) != 0) {
        free(filebuf);
        return -4;
    }

    uint64_t min_seq = pq_edit_seq_load(buf->seq_sidecar);

    size_t pt_len = (size_t)fsz - PQ_ENV_HDR_LEN;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len > 0 ? pt_len : 1);
    uint64_t got_seq = 0;

    int r = pq_env_decrypt_file(buf->seckey, filebuf, (size_t)fsz, min_seq,
                                 plaintext, &got_seq);

    if (r == 0) {
        pq_env_peek_file_id(filebuf, (size_t)fsz, buf->file_id, NULL);
        buf->seq = got_seq;
        pq_edit_split_lines(buf, (const char *)plaintext, pt_len);
        buf->dirty = 0;
    }

    /* 평문/암호문 임시 버퍼 잔존 방지 */
    memset(plaintext, 0, pt_len > 0 ? pt_len : 1);
    free(plaintext);
    memset(filebuf, 0, (size_t)fsz);
    free(filebuf);

    if (r == -2) return -2;   /* 변조 */
    if (r == -3) return -3;   /* 롤백 */
    if (r != 0)  return -4;

    return 0;
}

/* ================================================================
 * §6  저장
 * ================================================================ */
int pq_edit_save(PqEditBuf *buf)
{
    /* 공개키만으로도 암호화(재캡슐화)는 가능 — 비밀키는 "읽기"에만 필요.
     * 다만 seq 상태가 seckey로 검증된 적 없으면(신규 파일) 여기서부터 시작. */

    size_t pt_len = 0;
    char *plaintext = pq_edit_join_lines(buf, &pt_len);

    size_t out_len = PQ_ENV_HDR_LEN + pt_len;
    uint8_t *out = (uint8_t *)malloc(out_len);

    uint64_t new_seq = buf->seq + 1;

    int r = pq_env_encrypt_file(buf->pubkey, buf->file_id, new_seq,
                                 (const uint8_t *)plaintext, pt_len, out);

    int ret = -4;
    if (r == 0) {
        if (pq_env_write_file_0600(buf->path, out, out_len) == 0 &&
            pq_edit_seq_store(buf->seq_sidecar, new_seq) == 0) {
            buf->seq = new_seq;
            buf->dirty = 0;
            ret = 0;
        }
    }

    memset(plaintext, 0, pt_len > 0 ? pt_len : 1);
    free(plaintext);
    memset(out, 0, out_len);
    free(out);

    return ret;
}

/* ================================================================
 * §7  해제
 * ================================================================ */
void pq_edit_free(PqEditBuf *buf)
{
    free_rows(buf);
    memset(buf->seckey, 0, sizeof(buf->seckey));   /* 비밀키 메모리 소거 */
    memset(buf->pubkey, 0, sizeof(buf->pubkey));
    free(buf->path);
    free(buf->seq_sidecar);
    memset(buf, 0, sizeof(*buf));
}
