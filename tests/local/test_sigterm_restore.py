import pty, os, time, fcntl, termios, struct, signal, subprocess, tempfile, shutil, select

def set_winsize(fd, rows=24, cols=80):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

import os as _os
ROOT = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..")
EDITOR = _os.path.join(ROOT, "pq_env_editor")
KEYGEN = _os.path.join(ROOT, "pq_env_keygen")

sandbox = tempfile.mkdtemp(prefix="sigtest_")
pub = os.path.join(sandbox, "pub.key")
sec = os.path.join(sandbox, "sec.key")
envfile = os.path.join(sandbox, "t.env.kpqe")

if not (os.path.exists(EDITOR) and os.path.exists(KEYGEN)):
    print(f"바이너리가 없습니다 (EDITOR={EDITOR}, KEYGEN={KEYGEN})\n먼저 sh build.sh 를 실행하세요.")
    raise SystemExit(1)
subprocess.run([KEYGEN, sec, pub], check=True, capture_output=True)

master_fd, slave_fd = pty.openpty()
set_winsize(slave_fd)

# 자식이 뜨기 전, pty의 termios 초기 상태(정상 cooked 모드) 기록
before = termios.tcgetattr(slave_fd)

pid = os.fork()
if pid == 0:
    os.close(master_fd)
    os.setsid()
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
    os.dup2(slave_fd, 0); os.dup2(slave_fd, 1); os.dup2(slave_fd, 2)
    if slave_fd > 2: os.close(slave_fd)
    os.execvp(EDITOR, [EDITOR, envfile, "--pub", pub, "--sec", sec])
    os._exit(127)

os.close(slave_fd)

# 편집기가 raw mode로 들어갈 시간을 줌
time.sleep(0.8)
raw_state = termios.tcgetattr(master_fd)
echo_on_during_edit = bool(raw_state[3] & termios.ECHO)
print("편집기 raw mode 진입 확인 (ECHO 꺼져 있어야 정상):",
      "FAIL(echo 안 꺼짐)" if echo_on_during_edit else "OK(echo 꺼짐)")

# 외부에서 SIGTERM 전송 (kill <pid> 시뮬레이션)
os.kill(pid, signal.SIGTERM)
time.sleep(0.5)

# 프로세스가 실제로 종료됐는지, 그리고 터미널 상태가 복원됐는지 확인
try:
    wpid, status = os.waitpid(pid, os.WNOHANG)
    terminated = (wpid == pid)
except ChildProcessError:
    terminated = True

after = termios.tcgetattr(master_fd)
restored = (after[3] & (termios.ECHO | termios.ICANON)) == (before[3] & (termios.ECHO | termios.ICANON))

print("SIGTERM 후 프로세스 종료:", "OK" if terminated else "FAIL(안 죽음)")
print("SIGTERM 후 터미널 상태(ECHO/ICANON) 복원:", "OK" if restored else "FAIL(여전히 raw 상태)")

shutil.rmtree(sandbox, ignore_errors=True)
print("\n결과:", "PASS" if (terminated and restored and not echo_on_during_edit) else "FAIL")


import sys as _sys
_sys.exit(0 if (terminated and restored and not echo_on_during_edit) else 1)
