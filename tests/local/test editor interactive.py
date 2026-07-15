#!/usr/bin/env python3
"""
tests/local/test_editor_interactive.py

pq_env_editor를 실제 pty(가상 터미널)로 띄워 진짜 키 입력을 흉내내는
상호작용 테스트. 고정 sleep() 대신 "기대하는 텍스트가 화면에 나타날
때까지 폴링"하는 방식이라 느린/바쁜 CI 머신에서도 타이밍에 흔들리지
않는다 (초기 버전은 고정 sleep 기반이라 시스템이 바쁠 때 간헐적으로
실패하는 게 발견되어 이렇게 다시 씀).

사전조건: build.sh로 pq_env_editor, pq_env_keygen 빌드가 끝나 있어야 함.
사용법:   python3 tests/local/test_editor_interactive.py [경로/to/pq_env_editor]
"""
import pty, os, sys, time, tempfile, shutil, subprocess, select, fcntl, termios, struct

EDITOR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "pq_env_editor")
KEYGEN = os.path.join(os.path.dirname(EDITOR), "pq_env_keygen")

def set_winsize(fd, rows=24, cols=80):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

class Session:
    """pty로 띄운 프로세스와 상호작용. sleep 대신 '기대 텍스트 등장'을 폴링한다.

    주의: pty.fork()(=os.forkpty())는 fork와 pty 생성이 한 syscall로
    묶여 있어서, 자식이 exec되기 '전에' 터미널 크기를 설정할 방법이
    없다 — 자식의 ioctl(TIOCGWINSZ)이 부모의 TIOCSWINSZ보다 먼저
    스케줄되면 ws_col==0으로 읽혀 프로그램이 즉시 die()하는 진짜
    레이스 컨디션이 있었다(간헐적 실패의 원인). 그래서 pty.openpty()로
    먼저 pty를 만들고, 크기를 미리 설정한 뒤에 fork()하는 방식으로
    바꿔 이 레이스를 원천 차단한다.
    """
    def __init__(self, args):
        master_fd, slave_fd = pty.openpty()
        set_winsize(slave_fd)   # fork 전에 미리 설정 — 레이스 없음
        set_winsize(master_fd)

        pid = os.fork()
        if pid == 0:
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if slave_fd > 2:
                os.close(slave_fd)
            os.execvp(args[0], args)
            os._exit(127)  # execvp 실패시

        os.close(slave_fd)
        self.pid = pid
        self.fd = master_fd
        self.out = b''

    def _pump(self, timeout):
        """timeout 초 동안(또는 EOF까지) 읽을 수 있는 만큼 읽어 self.out에 누적."""
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if self.fd in r:
                try:
                    chunk = os.read(self.fd, 65536)
                    if not chunk:
                        break
                    self.out += chunk
                except OSError:
                    break

    def wait_for(self, substr, timeout=3.0):
        """substr이 누적 출력에 나타날 때까지 폴링. 나타나면 즉시 반환(True)."""
        end = time.time() + timeout
        needle = substr.encode()
        while time.time() < end:
            if needle in self.out:
                return True
            self._pump(0.1)
        return needle in self.out

    def send(self, data):
        os.write(self.fd, data)
        self._pump(0.05)  # 최소한의 처리 시간

    def drain(self, timeout=0.5):
        self._pump(timeout)

    def text(self):
        return self.out.decode(errors="replace")

    def close(self):
        try:
            os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            pass

def check(name, cond):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    return cond

def main():
    if not os.path.exists(EDITOR):
        print(f"에디터 바이너리가 없습니다: {EDITOR}\n먼저 sh build.sh 를 실행하세요.")
        return 1

    sandbox = tempfile.mkdtemp(prefix="pqenv_interactive_")
    print(f"sandbox: {sandbox}")
    pub = os.path.join(sandbox, "pub.key")
    sec = os.path.join(sandbox, "sec.key")
    envfile = os.path.join(sandbox, "test.env.kpqe")

    ok = True
    try:
        subprocess.run([KEYGEN, sec, pub], check=True, capture_output=True)

        # 1) 신규 작성 -> Ctrl-X(저장+종료)
        s = Session([EDITOR, envfile, "--pub", pub, "--sec", sec])
        s.wait_for("새 파일", timeout=5.0)   # 초기 화면 렌더 대기
        s.send(b"OPENAI_API_KEY=sk-test-999\r")
        s.wait_for("OPENAI_API_KEY", timeout=4.0)
        s.send(b"DB_PASSWORD=hunter2\r")
        s.wait_for("DB_PASSWORD", timeout=4.0)
        s.send(b"PORT=7070")
        s.wait_for("PORT=7070", timeout=4.0)
        s.send(bytes([24]))  # Ctrl-X 저장+종료
        s.drain(1.0)
        s.close()
        ok &= check("최초 작성 후 파일 생성됨", os.path.exists(envfile))

        # 2) 재오픈 -> 복호화된 내용이 화면에 정확히 보이는지 확인 후 Ctrl-Q 종료
        s = Session([EDITOR, envfile, "--pub", pub, "--sec", sec])
        got_content = s.wait_for("OPENAI_API_KEY=sk-test-999", timeout=5.0)
        ok &= check("재오픈시 내용 표시(API 키)", got_content)
        ok &= check("재오픈시 내용 표시(비밀번호)", "DB_PASSWORD=hunter2" in s.text())
        ok &= check("재오픈시 seq=1 표시", "seq=1" in s.text())
        s.send(bytes([17]))  # Ctrl-Q (수정 없었으니 한 번에 종료)
        s.drain(0.5)
        s.close()

        # 3) 편집 후 저장 -> seq 증가 확인
        s = Session([EDITOR, envfile, "--pub", pub, "--sec", sec])
        s.wait_for("seq=1", timeout=5.0)
        DOWN = b"\x1bOB"
        s.send(DOWN); s.send(DOWN)
        s.send(b"XYZ")
        s.wait_for("XYZ", timeout=4.0)
        s.send(bytes([19]))  # Ctrl-S 저장
        s.wait_for("seq=2", timeout=5.0)
        ok &= check("편집 후 저장시 seq=2로 증가", "seq=2" in s.text())
        s.send(bytes([17]))  # Ctrl-Q 종료
        s.drain(0.5)
        s.close()

        # 4) 변조된 파일은 편집기 시작 전에 거부
        backup = envfile + ".bak"
        shutil.copy(envfile, backup)
        with open(envfile, "r+b") as f:
            f.seek(1160)
            b = f.read(1)
            f.seek(1160)
            f.write(bytes([b[0] ^ 0xFF]))
        r = subprocess.run([EDITOR, envfile, "--pub", pub, "--sec", sec],
                            capture_output=True, timeout=5)
        ok &= check("변조 탐지시 실행 거부(exit!=0)", r.returncode != 0)
        ok &= check("변조 탐지 메시지 출력", "변조" in r.stderr.decode(errors="replace"))
        shutil.copy(backup, envfile)  # 원복

        # 5) 롤백된 seq는 편집기 시작 전에 거부
        with open(envfile + ".seq", "w") as f:
            f.write("999\n")
        r2 = subprocess.run([EDITOR, envfile, "--pub", pub, "--sec", sec],
                             capture_output=True, timeout=5)
        ok &= check("롤백 탐지시 실행 거부(exit!=0)", r2.returncode != 0)
        ok &= check("롤백 탐지 메시지 출력", "롤백" in r2.stderr.decode(errors="replace"))

    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
        print(f"sandbox 정리 완료: {sandbox}")

    print("\n=== 전체 결과:", "PASS" if ok else "FAIL", "===")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
