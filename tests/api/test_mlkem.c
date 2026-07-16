#include <stdio.h>
#include <string.h>
#include "pq_mlkem.h"

static void hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s: ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    uint8_t ek[PQ_MLKEM768_EK_LEN];
    uint8_t dk[PQ_MLKEM768_DK_LEN];
    uint8_t ct[PQ_MLKEM768_CT_LEN];
    uint8_t ss1[32], ss2[32];

    int trials = 200;
    int fail = 0;

    for (int t = 0; t < trials; t++) {
        if (pq_mlkem768_keygen(ek, dk) != 0) { printf("keygen fail\n"); return 1; }
        if (pq_mlkem768_encaps(ek, ct, ss1) != 0) { printf("encaps fail\n"); return 1; }
        if (pq_mlkem768_decaps(dk, ct, ss2) != 0) { printf("decaps fail\n"); return 1; }

        if (memcmp(ss1, ss2, 32) != 0) {
            fail++;
            if (fail <= 3) {
                printf("MISMATCH at trial %d\n", t);
                hex("  ss1 (encaps)", ss1, 32);
                hex("  ss2 (decaps)", ss2, 32);
            }
        }
    }

    printf("trials=%d, mismatches=%d\n", trials, fail);

    /* 위조 ciphertext 테스트: decaps가 크래시 없이 (다른) 값을 반환해야 함 */
    if (pq_mlkem768_keygen(ek, dk) == 0 &&
        pq_mlkem768_encaps(ek, ct, ss1) == 0) {
        ct[0] ^= 0xFF;  /* 변조 */
        pq_mlkem768_decaps(dk, ct, ss2);
        printf("tampered ct -> decaps did NOT crash, ss differs from original: %s\n",
               memcmp(ss1, ss2, 32) != 0 ? "YES (expected)" : "NO (unexpected!)");
    }

    return fail != 0;
}
