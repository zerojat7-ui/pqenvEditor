#include <stdio.h>
#include <string.h>
#include "pq_chacha20poly1305.h"

static int hex2bin(const char *hex, uint8_t *out) {
    int n = 0;
    while (*hex) {
        if (*hex == ' ' || *hex == '\n') { hex++; continue; }
        unsigned v;
        sscanf(hex, "%2x", &v);
        out[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

static void printhex(const char *label, const uint8_t *b, size_t n) {
    printf("%s: ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    /* RFC 8439 §2.8.2 공식 AEAD 테스트벡터 */
    const char *pt_str = "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    uint8_t key[32];
    hex2bin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);

    uint8_t nonce[12];
    hex2bin("070000004041424344454647", nonce);

    uint8_t aad_correct[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};

    uint8_t expected_ct[114];
    int ctlen = hex2bin(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116", expected_ct);

    uint8_t expected_tag[16];
    hex2bin("1ae10b594f09e26a7e902ecbd0600691", expected_tag);

    size_t pt_len = strlen(pt_str);
    printf("pt_len=%zu ctlen(from hex)=%d\n", pt_len, ctlen);

    uint8_t ct[200], tag[16];
    pq_chacha20poly1305_encrypt(key, nonce, aad_correct, sizeof(aad_correct),
                                 (const uint8_t*)pt_str, pt_len, ct, tag);

    printhex("computed ct ", ct, pt_len);
    printhex("expected ct ", expected_ct, (size_t)ctlen);
    printhex("computed tag", tag, 16);
    printhex("expected tag", expected_tag, 16);

    int ct_ok = (pt_len == (size_t)ctlen) && memcmp(ct, expected_ct, pt_len) == 0;
    int tag_ok = memcmp(tag, expected_tag, 16) == 0;
    printf("CIPHERTEXT MATCH: %s\n", ct_ok ? "YES" : "NO");
    printf("TAG MATCH: %s\n", tag_ok ? "YES" : "NO");

    /* 복호화 라운드트립 + 변조 탐지 테스트 */
    uint8_t pt2[200];
    int r = pq_chacha20poly1305_decrypt(key, nonce, aad_correct, sizeof(aad_correct),
                                         ct, pt_len, tag, pt2);
    int rt_ok = (r == 0) && memcmp(pt2, pt_str, pt_len) == 0;
    printf("DECRYPT ROUNDTRIP: %s\n", rt_ok ? "YES" : "NO");

    ct[0] ^= 0xFF;
    int r2 = pq_chacha20poly1305_decrypt(key, nonce, aad_correct, sizeof(aad_correct),
                                          ct, pt_len, tag, pt2);
    printf("TAMPER DETECTED (should be -1): %d\n", r2);

    return (ct_ok && tag_ok && rt_ok && r2 == -1) ? 0 : 1;
}
