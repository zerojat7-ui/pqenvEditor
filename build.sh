#!/bin/sh
# pqenvEditor 빌드 스크립트
#
# 폴더 구조:
#   build.sh
#   include/*.h
#   src/pq_*.c
#   tests/api/      알고리즘 레벨 (파일시스템 미사용, 공식 테스트벡터 대조)
#   tests/local/    통합 (실제 파일/키/터미널, 임시 디렉터리 격리)
#
# 사용법:
#   sh build.sh              프로그램 + 전체 테스트 빌드+실행
#   sh build.sh test-api     tests/api 만 빌드+실행 (CI에 넣기 가장 좋음)
#   sh build.sh test-local   tests/local 만 빌드+실행 (절대 ~/.atema/ 안 건드림)
set -e
CFLAGS="-O2 -std=c11 -Wall -Iinclude"
SRC=src
CORE="$SRC/pq_keccak.c $SRC/pq_mlkem.c $SRC/pq_chacha20poly1305.c $SRC/pq_env_crypto.c $SRC/pq_random.c"

build_programs() {
    echo "== pq_env_keygen =="
    gcc $CFLAGS $SRC/pq_env_keygen.c $CORE -o pq_env_keygen

    echo "== pq_env_editor =="
    gcc $CFLAGS $SRC/pq_env_editor.c $SRC/pq_env_editor_core.c $CORE -o pq_env_editor

    echo "== pq_env_encrypt_cli (비대화형 stdin 암호화) =="
    gcc $CFLAGS $SRC/pq_env_encrypt_cli.c $CORE -o pq_env_encrypt_cli

    echo "== pq_env_exec (다른 프로그램에 값 적용 — exec 래퍼) =="
    gcc $CFLAGS $SRC/pq_env_loader.c $SRC/pq_env_exec.c $CORE -o pq_env_exec

    echo "== pq_env_decrypt_cli (stdout 출력 — 언어 무관 프로그래밍적 사용) =="
    gcc $CFLAGS $SRC/pq_env_decrypt_cli.c $CORE -o pq_env_decrypt_cli
}

build_test_api() {
    echo "== tests/api (알고리즘 레벨 — 공식 테스트벡터 대조, 파일시스템 미사용) =="
    gcc $CFLAGS tests/api/test_keccak.c $SRC/pq_keccak.c -o tests/api/test_keccak
    gcc $CFLAGS tests/api/test_mlkem.c $SRC/pq_mlkem.c $SRC/pq_keccak.c $SRC/pq_random.c -o tests/api/test_mlkem
    gcc $CFLAGS tests/api/test_cctv.c $SRC/pq_mlkem.c $SRC/pq_keccak.c $SRC/pq_random.c -o tests/api/test_cctv
    gcc $CFLAGS tests/api/test_chacha.c $SRC/pq_chacha20poly1305.c -o tests/api/test_chacha
    gcc $CFLAGS tests/api/test_env_crypto.c $CORE -o tests/api/test_env_crypto
    gcc $CFLAGS tests/api/test_random.c $SRC/pq_random.c -o tests/api/test_random
}

build_test_local() {
    echo "== tests/local (통합 — 실제 파일/키/터미널, 임시 디렉터리에서 격리) =="
    gcc $CFLAGS tests/local/test_editor_core.c $SRC/pq_env_editor_core.c $CORE -o tests/local/test_editor_core
}

run_test_api() {
    echo "--- test-api 실행 ---"
    ./tests/api/test_keccak
    ./tests/api/test_mlkem
    ./tests/api/test_cctv
    ./tests/api/test_chacha
    ./tests/api/test_env_crypto
    ./tests/api/test_random
}

run_test_local() {
    echo "--- test-local 실행 ---"
    ./tests/local/test_editor_core
    if command -v python3 >/dev/null 2>&1; then
        python3 tests/local/test_editor_interactive.py ./pq_env_editor
        if [ $? -ne 0 ]; then echo "!! test_editor_interactive.py 실패"; exit 1; fi
        python3 tests/local/test_env_loader.py
        if [ $? -ne 0 ]; then echo "!! test_env_loader.py 실패"; exit 1; fi
        python3 tests/local/test_sigterm_restore.py
        if [ $? -ne 0 ]; then echo "!! test_sigterm_restore.py 실패"; exit 1; fi
    else
        echo "(python3 없음 — 파이썬 통합 테스트 스킵)"
    fi
}

case "${1:-all}" in
    test-api)
        build_test_api
        run_test_api
        ;;
    test-local)
        build_programs
        build_test_local
        run_test_local
        ;;
    all)
        build_programs
        build_test_api
        build_test_local
        run_test_api
        run_test_local
        echo
        echo "빌드+검증 완료. 사용법:"
        echo "  ./pq_env_keygen ~/.atema/pq_secret.key ~/.atema/pq_public.key"
        echo "  ./pq_env_editor ./.env.kpqe --pub ~/.atema/pq_public.key --sec ~/.atema/pq_secret.key"
        ;;
    *)
        echo "usage: sh build.sh [all|test-api|test-local]"
        exit 1
        ;;
esac
