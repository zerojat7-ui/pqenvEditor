#include <stdio.h>
#include "pq_env_crypto.h"

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <seckey_path> <pubkey_path>\n", argv[0]);
        return 1;
    }
    int r = pq_env_keypair_generate(argv[1], argv[2]);
    if (r != 0) { fprintf(stderr, "keypair generation failed\n"); return 1; }
    printf("OK: seckey=%s pubkey=%s\n", argv[1], argv[2]);
    return 0;
}
