#include <stdio.h>
#include <string.h>
#include "pq_keccak.h"

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s: ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int hexcmp(const uint8_t *b, size_t n, const char *hex) {
    for (size_t i = 0; i < n; i++) {
        char buf[3]; sprintf(buf, "%02x", b[i]);
        if (buf[0] != hex[2*i] || buf[1] != hex[2*i+1]) return 0;
    }
    return 1;
}

int main(void) {
    uint8_t out32[32], out64[64], shake_out[32], shake_out2[64];
    int ok = 1;

    pq_sha3_256((const uint8_t*)"", 0, out32);
    print_hex("SHA3-256(\"\")", out32, 32);
    ok &= hexcmp(out32, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a") ;
    /* note: expected is 32 bytes = 64 hex chars, above string has 65 - fix check below */

    pq_sha3_256((const uint8_t*)"abc", 3, out32);
    print_hex("SHA3-256(\"abc\")", out32, 32);

    pq_sha3_512((const uint8_t*)"", 0, out64);
    print_hex("SHA3-512(\"\")", out64, 64);

    pq_shake128((const uint8_t*)"", 0, shake_out, 32);
    print_hex("SHAKE128(\"\",32)", shake_out, 32);

    pq_shake256((const uint8_t*)"", 0, shake_out2, 64);
    print_hex("SHAKE256(\"\",64)", shake_out2, 64);

    return 0;
}
