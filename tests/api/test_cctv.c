#include <stdio.h>
#include <string.h>
#include "pq_mlkem.h"
#include "pq_keccak.h"

/* pq_mlkem768_keygen_internal / encaps_internal / decaps 는 pq_mlkem.h에 이미 선언됨 */

int main(void)
{
    const int N = 10000;
    const char *expected = "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3";

    PqShakeCtx r, a;
    pq_shake128_init(&r);
    pq_shake_absorb(&r, (const uint8_t*)"", 0);
    pq_shake_finalize(&r);

    pq_shake128_init(&a);

    int encaps_decaps_mismatch = 0;

    for (int t = 0; t < N; t++) {
        uint8_t d[32], z[32], m[32], ct_rand[PQ_MLKEM768_CT_LEN];
        pq_shake_squeeze(&r, d, 32);
        pq_shake_squeeze(&r, z, 32);
        pq_shake_squeeze(&r, m, 32);
        pq_shake_squeeze(&r, ct_rand, PQ_MLKEM768_CT_LEN);

        uint8_t ek[PQ_MLKEM768_EK_LEN], dk[PQ_MLKEM768_DK_LEN];
        pq_mlkem768_keygen_internal(d, z, ek, dk);

        uint8_t ct[PQ_MLKEM768_CT_LEN], k[32];
        pq_mlkem768_encaps_internal(ek, m, ct, k);

        uint8_t k_check[32];
        pq_mlkem768_decaps(dk, ct, k_check);
        if (memcmp(k, k_check, 32) != 0) encaps_decaps_mismatch++;

        uint8_t k_reject[32];
        pq_mlkem768_decaps(dk, ct_rand, k_reject);

        pq_shake_absorb(&a, ek, PQ_MLKEM768_EK_LEN);
        pq_shake_absorb(&a, dk, PQ_MLKEM768_DK_LEN);
        pq_shake_absorb(&a, ct, PQ_MLKEM768_CT_LEN);
        pq_shake_absorb(&a, k, 32);
        pq_shake_absorb(&a, k_reject, 32);

        if ((t+1) % 1000 == 0) fprintf(stderr, "  ...%d/%d\n", t+1, N);
    }

    pq_shake_finalize(&a);
    uint8_t digest[32];
    pq_shake_squeeze(&a, digest, 32);

    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i*2, "%02x", digest[i]);
    hex[64] = 0;

    printf("encaps/decaps mismatches (should be 0): %d\n", encaps_decaps_mismatch);
    printf("computed : %s\n", hex);
    printf("expected : %s\n", expected);
    printf("MATCH: %s\n", strcmp(hex, expected) == 0 ? "YES  <-- FIPS203 KAT PASS" : "NO");

    return strcmp(hex, expected) == 0 ? 0 : 1;
}
