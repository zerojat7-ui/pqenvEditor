#!/usr/bin/env python3
"""
tests/local/test_env_loader.py

pq_env_encrypt_cli(stdin 암호화) + pq_env_exec(다른 프로그램에 값 적용)
파이프라인 통합 테스트. 임시 디렉터리에서 격리 실행.
"""
import os, sys, subprocess, tempfile, shutil

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
KEYGEN = os.path.join(ROOT, "pq_env_keygen")
ENCRYPT_CLI = os.path.join(ROOT, "pq_env_encrypt_cli")
DECRYPT_CLI = os.path.join(ROOT, "pq_env_decrypt_cli")
EXEC_WRAPPER = os.path.join(ROOT, "pq_env_exec")

def check(name, cond):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    return cond

def main():
    for b in (KEYGEN, ENCRYPT_CLI, DECRYPT_CLI, EXEC_WRAPPER):
        if not os.path.exists(b):
            print(f"바이너리가 없습니다: {b}\n먼저 sh build.sh 를 실행하세요.")
            return 1

    sandbox = tempfile.mkdtemp(prefix="pqenv_loader_")
    print(f"sandbox: {sandbox}")
    pub = os.path.join(sandbox, "pub.key")
    sec = os.path.join(sandbox, "sec.key")
    envfile = os.path.join(sandbox, "app.env.kpqe")

    ok = True
    try:
        subprocess.run([KEYGEN, sec, pub], check=True, capture_output=True)

        # 1) stdin 파이프로 최초 암호화
        plaintext = b"OPENAI_API_KEY=sk-real-secret-abc\nDB_PASSWORD=hunter2\n# comment\nPORT=7070\n"
        r = subprocess.run([ENCRYPT_CLI, envfile, "--pub", pub],
                            input=plaintext, capture_output=True)
        ok &= check("stdin 암호화 성공", r.returncode == 0 and os.path.exists(envfile))

        # 2) exec 래퍼로 다른 프로그램(env)을 실행하며 값 주입
        r = subprocess.run([EXEC_WRAPPER, envfile, "--sec", sec, "--", "/usr/bin/env"],
                            capture_output=True, text=True)
        out = r.stdout
        ok &= check("OPENAI_API_KEY 정확히 주입됨", "OPENAI_API_KEY=sk-real-secret-abc" in out)
        ok &= check("DB_PASSWORD 정확히 주입됨", "DB_PASSWORD=hunter2" in out)
        ok &= check("PORT 정확히 주입됨", "PORT=7070" in out)
        ok &= check("주석 줄은 환경변수로 새지 않음", "comment" not in out)

        # 2b) decrypt_cli — stdout으로 그대로 복호화 출력되는지 (언어 무관 사용)
        r = subprocess.run([DECRYPT_CLI, envfile, "--sec", sec], capture_output=True, text=True)
        ok &= check("decrypt_cli stdout에 정확한 내용 출력", r.returncode == 0 and
                    "OPENAI_API_KEY=sk-real-secret-abc" in r.stdout and
                    "DB_PASSWORD=hunter2" in r.stdout)

        # 2c) --key 로 값 하나만 추출 (정확 일치 — 접두어 혼동 없어야 함)
        r = subprocess.run([DECRYPT_CLI, envfile, "--sec", sec, "--key", "OPENAI_API_KEY"],
                            capture_output=True, text=True)
        ok &= check("--key 단일 값 추출", r.returncode == 0 and
                    r.stdout.strip() == "sk-real-secret-abc")
        r = subprocess.run([DECRYPT_CLI, envfile, "--sec", sec, "--key", "NOT_A_REAL_KEY"],
                            capture_output=True, text=True)
        ok &= check("존재하지 않는 --key는 exit 2", r.returncode == 2 and r.stdout == "")

        # 2d) pq_env_exec --only — 여러 서비스 키를 한 파일에 저장해도
        #     프로그램마다 자기한테 필요한 키만 받는 최소 권한 시나리오
        multikey = os.path.join(sandbox, "multi.env.kpqe")
        subprocess.run([ENCRYPT_CLI, multikey, "--pub", pub],
                        input=b"OPENAI_API_KEY=sk-ai\nSTRIPE_KEY=sk-pay\nDB_PASSWORD=hunter2\n",
                        capture_output=True)

        r = subprocess.run([EXEC_WRAPPER, multikey, "--sec", sec, "--only", "OPENAI_API_KEY",
                             "--", "/usr/bin/env"], capture_output=True, text=True)
        ok &= check("--only: 지정한 키만 주입됨", "OPENAI_API_KEY=sk-ai" in r.stdout)
        ok &= check("--only: 지정 안 한 키는 안 새어나감",
                     "STRIPE_KEY" not in r.stdout and "DB_PASSWORD" not in r.stdout)

        r = subprocess.run([EXEC_WRAPPER, multikey, "--sec", sec,
                             "--only", "STRIPE_KEY,DB_PASSWORD",
                             "--", "/usr/bin/env"], capture_output=True, text=True)
        ok &= check("--only: 콤마로 여러 키 지정 가능",
                     "STRIPE_KEY=sk-pay" in r.stdout and "DB_PASSWORD=hunter2" in r.stdout and
                     "OPENAI_API_KEY" not in r.stdout)

        # 3) 값 갱신(rotate) 후 재암호화 -> exec에 새 값 반영되는지
        r = subprocess.run([ENCRYPT_CLI, envfile, "--pub", pub],
                            input=b"OPENAI_API_KEY=sk-rotated-999\n", capture_output=True)
        r = subprocess.run([EXEC_WRAPPER, envfile, "--sec", sec, "--", "/usr/bin/env"],
                            capture_output=True, text=True)
        ok &= check("로테이션 후 새 값 반영", "OPENAI_API_KEY=sk-rotated-999" in r.stdout)

        # 4) 변조된 파일 -> exec가 대상 프로그램을 아예 실행하지 않음
        with open(envfile, "r+b") as f:
            f.seek(1160)
            b = f.read(1)
            f.seek(1160)
            f.write(bytes([b[0] ^ 0xFF]))
        r = subprocess.run([EXEC_WRAPPER, envfile, "--sec", sec, "--",
                             "/bin/sh", "-c", "echo SHOULD_NOT_RUN"],
                            capture_output=True, text=True)
        ok &= check("변조 파일은 자식 프로세스 실행 자체를 거부", r.returncode != 0)
        ok &= check("변조 시 자식이 실행되지 않음(SHOULD_NOT_RUN 미출력)",
                     "SHOULD_NOT_RUN" not in r.stdout)

        r = subprocess.run([DECRYPT_CLI, envfile, "--sec", sec], capture_output=True, text=True)
        ok &= check("decrypt_cli도 변조된 파일은 출력 거부", r.returncode != 0 and r.stdout == "")

    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
        print(f"sandbox 정리 완료: {sandbox}")

    print("\n=== 전체 결과:", "PASS" if ok else "FAIL", "===")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
