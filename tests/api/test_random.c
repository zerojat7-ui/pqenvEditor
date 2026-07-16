#include <stdio.h>
#include <string.h>
#include "pq_random.h"

static int check(const char *name, int cond) {
    printf("[%s] %s\n", cond ? "PASS" : "FAIL", name);
    return cond;
}

int main(void) {
    int ok = 1;
    uint8_t a[32], b[32];

    ok &= check("32B 요청 성공", pq_random_bytes(a, sizeof(a)) == 0);
    ok &= check("두 번째 32B 요청도 성공", pq_random_bytes(b, sizeof(b)) == 0);
    ok &= check("두 호출 결과가 서로 다름", memcmp(a, b, sizeof(a)) != 0);

    /* getentropy() 1회 호출 한도(256B)를 넘는 요청 — 청크 분할 경로 확인 */
    uint8_t big[1024];
    memset(big, 0, sizeof(big));
    ok &= check("1024B 요청(청크 분할 경로) 성공", pq_random_bytes(big, sizeof(big)) == 0);

    int all_zero = 1;
    for (size_t i = 0; i < sizeof(big); i++) if (big[i] != 0) { all_zero = 0; break; }
    ok &= check("1024B 결과가 전부 0은 아님(실제로 채워짐)", !all_zero);

    ok &= check("잘못된 인자(NULL) 거부", pq_random_bytes(NULL, 16) == -1);
    ok &= check("잘못된 인자(len=0) 거부", pq_random_bytes(a, 0) == -1);

    printf("\n=== 전체 결과: %s ===\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
