/**
 * pq_env_crypto.c — 양자내성 .env 암호화 포맷 구현
 * pqenvEditor
 */
#include "pq_env_crypto.h"
#include "pq_mlkem.h"
#include "pq_chacha20poly1305.h"
#include "pq_keccak.h"
#include "pq_random.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* ── 오프셋 상수 (헤더 §설명과 동일) ─────────────────────────── */
#define OFF_MAGIC     0
#define OFF_VERSION   4
#define OFF_RESERVED  5
#define OFF_MLKEM_CT  8
#define OFF_SEQ       (OFF_MLKEM_CT + PQ_MLKEM768_CT_LEN)   /* 8+1088=1096 */
#define OFF_FILE_ID   (OFF_SEQ + 8)                          /* 1104 */
#define OFF_NONCE     (OFF_FILE_ID + PQ_ENV_FILE_ID_LEN)     /* 1120 */
#define OFF_TAG       (OFF_NONCE + 12)                       /* 1132 */
#define OFF_CT        (OFF_TAG + 16)                         /* 1148 = PQ_ENV_HDR_LEN */
#define AAD_LEN       OFF_NONCE                              /* 1120 — nonce/tag 이전 전부 */

static void store64_be(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}
static uint64_t load64_be(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* ML-KEM 공유비밀 → ChaCha20 대칭키 (도메인 분리 KDF) */
static void derive_chacha_key(const uint8_t ss[32], uint8_t key[32])
{
    uint8_t in[16 + 32] = "KPQE-ENV-KEY-v1";  /* 16B 고정 문자열(널포함 15+1) */
    memcpy(in, "KPQE-ENV-KEY-v1", 15);
    memcpy(in + 15, ss, 32);
    pq_sha3_256(in, 15 + 32, key);
}

/* ================================================================
 * 키 관리
 * ================================================================ */
static int write_file_0600(const char *path, const uint8_t *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w <= 0) { close(fd); return -1; }
        off += (size_t)w;
    }
    close(fd);
    return 0;
}

static int read_file_exact(const char *path, uint8_t *data, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, data + off, len - off);
        if (r <= 0) { close(fd); return -1; }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}

int pq_env_keypair_generate(const char *seckey_path, const char *pubkey_path)
{
    uint8_t ek[PQ_MLKEM768_EK_LEN];
    uint8_t dk[PQ_MLKEM768_DK_LEN];
    if (pq_mlkem768_keygen(ek, dk) != 0) return -1;

    if (write_file_0600(seckey_path, dk, PQ_MLKEM768_DK_LEN) != 0) return -1;
    if (write_file_0600(pubkey_path, ek, PQ_MLKEM768_EK_LEN) != 0) return -1;
    return 0;
}

/* ================================================================
 * 암호화
 * ================================================================ */
int pq_env_encrypt_file(const uint8_t pubkey[PQ_MLKEM768_EK_LEN],
                         const uint8_t file_id[PQ_ENV_FILE_ID_LEN],
                         uint64_t seq,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *out)
{
    memcpy(out + OFF_MAGIC, PQ_ENV_MAGIC, 4);
    out[OFF_VERSION] = PQ_ENV_VERSION;
    memset(out + OFF_RESERVED, 0, 3);

    uint8_t ct_mlkem[PQ_MLKEM768_CT_LEN], ss[32];
    if (pq_mlkem768_encaps(pubkey, ct_mlkem, ss) != 0) return -1;
    memcpy(out + OFF_MLKEM_CT, ct_mlkem, PQ_MLKEM768_CT_LEN);

    store64_be(out + OFF_SEQ, seq);
    memcpy(out + OFF_FILE_ID, file_id, PQ_ENV_FILE_ID_LEN);

    uint8_t nonce[12];
    /* 매 저장시 새 KEM 캡슐(=새 ss)이라 nonce 재사용 위험은 낮지만,
     * 방어적으로 매번 새 난수 nonce도 사용 */
    if (pq_random_bytes(nonce, 12) != 0) return -1;
    memcpy(out + OFF_NONCE, nonce, 12);

    uint8_t chacha_key[32];
    derive_chacha_key(ss, chacha_key);

    uint8_t tag[16];
    pq_chacha20poly1305_encrypt(chacha_key, nonce,
                                 out /*AAD*/, AAD_LEN,
                                 plaintext, plaintext_len,
                                 out + OFF_CT, tag);
    memcpy(out + OFF_TAG, tag, 16);

    return 0;
}

/* ================================================================
 * 복호화 (+ 롤백 검사)
 * ================================================================ */
int pq_env_decrypt_file(const uint8_t seckey[PQ_MLKEM768_DK_LEN],
                         const uint8_t *in, size_t in_len,
                         uint64_t min_seq,
                         uint8_t *out_plaintext, uint64_t *out_seq)
{
    if (in_len < PQ_ENV_HDR_LEN) return -1;
    if (memcmp(in + OFF_MAGIC, PQ_ENV_MAGIC, 4) != 0) return -1;
    if (in[OFF_VERSION] != PQ_ENV_VERSION) return -1;

    uint64_t seq = load64_be(in + OFF_SEQ);
    if (seq < min_seq) return -3;   /* 롤백/재생 시도 (min_seq와 같으면 "변경 없음"으로 허용) */

    uint8_t ss[32];
    if (pq_mlkem768_decaps(seckey, in + OFF_MLKEM_CT, ss) != 0) return -1;

    uint8_t chacha_key[32];
    derive_chacha_key(ss, chacha_key);

    size_t ct_len = in_len - PQ_ENV_HDR_LEN;
    int r = pq_chacha20poly1305_decrypt(chacha_key, in + OFF_NONCE,
                                         in /*AAD*/, AAD_LEN,
                                         in + OFF_CT, ct_len,
                                         in + OFF_TAG, out_plaintext);
    if (r != 0) return -2;   /* 태그 불일치 = 변조 */

    if (out_seq) *out_seq = seq;
    return 0;
}

int pq_env_peek_file_id(const uint8_t *in, size_t in_len,
                         uint8_t file_id[PQ_ENV_FILE_ID_LEN], uint64_t *seq)
{
    if (in_len < PQ_ENV_HDR_LEN) return -1;
    if (memcmp(in + OFF_MAGIC, PQ_ENV_MAGIC, 4) != 0) return -1;
    memcpy(file_id, in + OFF_FILE_ID, PQ_ENV_FILE_ID_LEN);
    if (seq) *seq = load64_be(in + OFF_SEQ);
    return 0;
}

int pq_env_write_file_0600(const char *path, const uint8_t *data, size_t len)
{
    return write_file_0600(path, data, len);
}

int pq_env_read_file_exact(const char *path, uint8_t *data, size_t len)
{
    return read_file_exact(path, data, len);
}
