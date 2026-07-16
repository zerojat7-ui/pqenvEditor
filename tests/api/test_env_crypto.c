#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pq_env_crypto.h"
#include "pq_mlkem.h"

int main(void)
{
    /* 1. 키쌍 생성 */
    uint8_t ek[PQ_MLKEM768_EK_LEN], dk[PQ_MLKEM768_DK_LEN];
    extern int pq_mlkem768_keygen(uint8_t*, uint8_t*);
    pq_mlkem768_keygen(ek, dk);

    uint8_t file_id[16];
    for (int i = 0; i < 16; i++) file_id[i] = (uint8_t)(i * 7 + 1);

    const char *env_content =
        "OPENAI_API_KEY=sk-test-1234567890\n"
        "DB_PASSWORD=hunter2\n"
        "KACP_PORT=7070\n";
    size_t len = strlen(env_content);

    size_t buf_len = PQ_ENV_HDR_LEN + len;
    uint8_t *enc1 = malloc(buf_len);
    uint8_t *enc2 = malloc(buf_len);

    /* 2. 최초 저장 (seq=1) */
    int r = pq_env_encrypt_file(ek, file_id, 1, (const uint8_t*)env_content, len, enc1);
    printf("encrypt seq=1: %s\n", r == 0 ? "OK" : "FAIL");

    /* 3. 정상 복호화 (min_seq=0) */
    uint8_t *dec = malloc(len);
    uint64_t got_seq = 0;
    r = pq_env_decrypt_file(dk, enc1, buf_len, 0, dec, &got_seq);
    printf("decrypt: r=%d seq=%llu content_match=%s\n", r,
           (unsigned long long)got_seq,
           (r == 0 && memcmp(dec, env_content, len) == 0) ? "YES" : "NO");

    /* 4. 재저장 (seq=2, 새 KEM 캡슐/새 nonce) */
    const char *env_v2 = "OPENAI_API_KEY=sk-updated-999\nDB_PASSWORD=hunter3\n";
    size_t len2 = strlen(env_v2);
    size_t buf_len2 = PQ_ENV_HDR_LEN + len2;
    uint8_t *enc_v2 = malloc(buf_len2);
    pq_env_encrypt_file(ek, file_id, 2, (const uint8_t*)env_v2, len2, enc_v2);

    uint8_t *dec2 = malloc(len2);
    uint64_t seq2 = 0;
    r = pq_env_decrypt_file(dk, enc_v2, buf_len2, got_seq /* =1 */, dec2, &seq2);
    printf("decrypt v2 (min_seq=1): r=%d seq=%llu content_match=%s\n", r,
           (unsigned long long)seq2,
           (r == 0 && memcmp(dec2, env_v2, len2) == 0) ? "YES" : "NO");

    /* 5. 롤백 공격 시뮬레이션: v1 파일을 "최신인 척" 다시 복호화 시도
     *    (last_seen_seq=2 인 상태에서 seq=1짜리 파일을 줌) */
    uint8_t *dec_rollback = malloc(len);
    r = pq_env_decrypt_file(dk, enc1, buf_len, seq2 /* =2 */, dec_rollback, NULL);
    printf("rollback attack (give old v1 after seeing v2): r=%d (expect -3) %s\n",
           r, r == -3 ? "BLOCKED correctly" : "!!NOT BLOCKED!!");

    /* 6. 변조 공격: ciphertext 한 바이트 플립 */
    enc_v2[PQ_ENV_HDR_LEN] ^= 0xFF;
    uint8_t *dec_tamper = malloc(len2);
    r = pq_env_decrypt_file(dk, enc_v2, buf_len2, 1, dec_tamper, NULL);
    printf("tamper attack (flip ct byte): r=%d (expect -2) %s\n",
           r, r == -2 ? "BLOCKED correctly" : "!!NOT BLOCKED!!");

    free(enc1); free(enc2); free(dec); free(enc_v2); free(dec2);
    free(dec_rollback); free(dec_tamper);
    return 0;
}
