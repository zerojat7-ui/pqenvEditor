/**
 * pq_random.c — pq_random_bytes() 구현
 * pqenvEditor
 */
#include "pq_random.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/random.h>   /* getentropy() — Linux glibc 2.25+ / macOS 10.12+ */
#else
#error "pq_random: 이 플랫폼용 CSPRNG 연동이 아직 없음 — getentropy()/getrandom()에 \
해당하는 API를 이 파일에 추가할 것. 예측 가능한 PRNG로 대체하지 말 것."
#endif

/* /dev/urandom 폴백 시 최대 대기 시간 — 임베디드/컨테이너에서 엔트로피
 * 풀이 아직 안 채워졌을 때 "영원히 블로킹" 대신 여기서 명확히 실패시킴 */
#define PQ_RANDOM_TIMEOUT_MS  5000

/* getentropy()는 호출당 최대 256B 제한 — 청크 단위로 반복 */
static int try_getentropy(uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        size_t chunk = (len - off > 256) ? 256 : (len - off);
        if (getentropy(buf + off, chunk) != 0)
            return -1;   /* ENOSYS(구형 커널)든 뭐든 폴백으로 넘김 */
        off += chunk;
    }
    return 0;
}

/* /dev/urandom + poll() 타임아웃 — 준비 안 된 엔트로피 풀에서 무한
 * 블로킹하지 않도록 방어. EINTR(시그널 핸들러 등록 후 흔해짐)도 재시도. */
static int try_urandom_timeout(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "pq_random: /dev/urandom을 열 수 없습니다 (%s)\n", strerror(errno));
        return -1;
    }

    size_t got = 0;
    while (got < len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, PQ_RANDOM_TIMEOUT_MS);

        if (pr < 0) {
            if (errno == EINTR) continue;   /* 시그널에 끊겼으면 재시도 */
            fprintf(stderr, "pq_random: poll() 오류 (%s)\n", strerror(errno));
            close(fd);
            return -1;
        }
        if (pr == 0) {
            /* 타임아웃 — 엔트로피 풀이 아직 안 채워진 임베디드/컨테이너 등 */
            fprintf(stderr,
                "pq_random: %dms 동안 /dev/urandom에서 엔트로피를 얻지 못했습니다.\n"
                "  임베디드 기기라면 하드웨어 RNG나 haveged/rngd 같은 엔트로피\n"
                "  데몬이 필요할 수 있습니다. 컨테이너라면 호스트의 /dev/urandom을\n"
                "  마운트했는지 확인하세요. 절대로 이 상태로 키를 생성하지 않습니다.\n",
                PQ_RANDOM_TIMEOUT_MS);
            close(fd);
            return -1;
        }

        ssize_t r = read(fd, buf + got, len - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) { close(fd); return -1; }  /* 있을 수 없지만 방어적으로 */
        got += (size_t)r;
    }

    close(fd);
    return 0;
}

int pq_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return -1;

    if (try_getentropy(buf, len) == 0)
        return 0;

    if (try_urandom_timeout(buf, len) == 0)
        return 0;

    /* 여기 도달 = 두 방법(getentropy, /dev/urandom) 다 실패. 절대로
     * 비암호학적 PRNG로 조용히 대체하지 않고 실패를 그대로 알린다 —
     * 안전한 키를 못 만드는 것이 예측 가능한 키를 만드는 것보다 낫다. */
    fprintf(stderr, "pq_random: 사용 가능한 CSPRNG 소스가 없습니다 — 키/난수를 생성할 수 없습니다.\n");
    memset(buf, 0, len);   /* 호출자가 실수로 반환값을 무시해도 이전 스택
                               잔여값이 재사용되는 것만은 막음 */
    return -1;
}
