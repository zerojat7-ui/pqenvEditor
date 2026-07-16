/**
 * pq_env_editor.c — 양자내성 .env 편집기 (터미널 UI)
 * pqenvEditor
 *
 * .env.kpqe 파일을 열면 즉시 메모리에서 복호화해 편집하고,
 * 저장하면 다시 암호화해서 씀. 디스크에 평문이 닿는 순간이 없음
 * (tmpfs조차 안 씀 — 순수 프로세스 메모리 내 편집).
 *
 * 조작법:
 *   화살표/Home/End/PageUp/PageDown  이동
 *   그냥 타이핑                       삽입
 *   Backspace / Delete                삭제
 *   Enter                             줄바꿈
 *   Ctrl-S                            저장 (재암호화)
 *   Ctrl-Q                            종료 (미저장 변경 있으면 확인 필요)
 *   Ctrl-X                            저장 후 종료
 *
 * 사용법:
 *   pq_env_editor <path.env.kpqe> [--pub PATH] [--sec PATH]
 *   기본 키 경로: ~/.atema/pq_public.key, ~/.atema/pq_secret.key
 */
#define _POSIX_C_SOURCE 200809L
#include "pq_env_editor_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>

/* ================================================================
 * §1  전역 에디터 상태
 * ================================================================ */
typedef struct {
    int cx, cy;             /* 커서 (열, 행) — 파일 좌표 */
    int rowoff, coloff;     /* 스크롤 오프셋 */
    int screenrows, screencols;
    struct termios orig_termios;
    char statusmsg[80];
    PqEditBuf buf;
} EditorState;

static EditorState E;

/* ================================================================
 * §2  터미널 raw mode
 * ================================================================ */
static void die(const char *s)
{
    write(STDOUT_FILENO, "\x1b[2J\x1b[H", 7);
    perror(s);
    exit(1);
}

static void disable_raw_mode(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &E.orig_termios);
}

/* raw mode 중 ISIG를 꺼놨기 때문에 Ctrl-C/Ctrl-\/Ctrl-Z는 애초에 시그널이
 * 안 됨(그냥 원문 바이트로 들어와 무시됨). 하지만 외부 kill(SIGTERM),
 * 터미널/SSH 연결 끊김(SIGHUP), 외부에서 보낸 SIGQUIT은 여전히 올 수
 * 있고, atexit() 핸들러는 이런 시그널로 죽을 때 실행되지 않는다 —
 * 그대로면 터미널이 echo-off raw 상태로 남아 reset이 필요해진다.
 * 그래서 여기서 명시적으로 잡아 tcsetattr로 복원한 뒤, 시그널을 기본
 * 동작으로 되돌려 재발생시킨다(정확한 종료 코드/쉘 규약 유지). */
static void handle_fatal_signal(int sig)
{
    disable_raw_mode();
    write(STDOUT_FILENO, "\x1b[2J\x1b[H", 7);
    signal(sig, SIG_DFL);
    raise(sig);
}

static void enable_raw_mode(void)
{
    if (tcgetattr(STDIN_FILENO, &E.orig_termios) == -1) die("tcgetattr");
    atexit(disable_raw_mode);
    signal(SIGTERM, handle_fatal_signal);
    signal(SIGHUP,  handle_fatal_signal);
    signal(SIGQUIT, handle_fatal_signal);

    struct termios raw = E.orig_termios;
    raw.c_iflag &= (tcflag_t)~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= (tcflag_t)~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) die("tcsetattr");
}

static int get_window_size(int *rows, int *cols)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) {
        return -1;
    }
    *cols = ws.ws_col;
    *rows = ws.ws_row;
    return 0;
}

/* ================================================================
 * §3  키 입력
 * ================================================================ */
enum EditorKey {
    BACKSPACE = 127,
    ARROW_LEFT = 1000, ARROW_RIGHT, ARROW_UP, ARROW_DOWN,
    DEL_KEY, HOME_KEY, END_KEY, PAGE_UP, PAGE_DOWN
};

static int editor_read_key(void)
{
    char c;
    ssize_t nread;
    while ((nread = read(STDIN_FILENO, &c, 1)) != 1) {
        if (nread == -1 && errno != EAGAIN) die("read");
    }

    if (c == '\x1b') {
        char seq[3];
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return '\x1b';
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return '\x1b';

        if (seq[0] == '[') {
            if (seq[1] >= '0' && seq[1] <= '9') {
                if (read(STDIN_FILENO, &seq[2], 1) != 1) return '\x1b';
                if (seq[2] == '~') {
                    switch (seq[1]) {
                        case '1': return HOME_KEY;
                        case '3': return DEL_KEY;
                        case '4': return END_KEY;
                        case '5': return PAGE_UP;
                        case '6': return PAGE_DOWN;
                        case '7': return HOME_KEY;
                        case '8': return END_KEY;
                    }
                }
            } else {
                switch (seq[1]) {
                    case 'A': return ARROW_UP;
                    case 'B': return ARROW_DOWN;
                    case 'C': return ARROW_RIGHT;
                    case 'D': return ARROW_LEFT;
                    case 'H': return HOME_KEY;
                    case 'F': return END_KEY;
                }
            }
        } else if (seq[0] == 'O') {
            switch (seq[1]) {
                case 'H': return HOME_KEY;
                case 'F': return END_KEY;
            }
        }
        return '\x1b';
    }
    return c;
}

/* ================================================================
 * §4  행 편집 연산 (buf.rows 직접 조작)
 * ================================================================ */
static void row_insert_char(PqEditRow *row, int at, int c)
{
    if (at < 0 || at > row->len) at = row->len;
    row->chars = realloc(row->chars, (size_t)row->len + 2);
    memmove(&row->chars[at + 1], &row->chars[at], (size_t)(row->len - at + 1));
    row->chars[at] = (char)c;
    row->len++;
}

static void row_del_char(PqEditRow *row, int at)
{
    if (at < 0 || at >= row->len) return;
    memmove(&row->chars[at], &row->chars[at + 1], (size_t)(row->len - at));
    row->len--;
}

static void buf_insert_row(int at, const char *s, size_t len)
{
    PqEditBuf *b = &E.buf;
    if (at < 0 || at > b->numrows) at = b->numrows;
    b->rows = realloc(b->rows, sizeof(PqEditRow) * (size_t)(b->numrows + 1));
    memmove(&b->rows[at + 1], &b->rows[at],
            sizeof(PqEditRow) * (size_t)(b->numrows - at));
    b->rows[at].len = (int)len;
    b->rows[at].chars = malloc(len + 1);
    if (len) memcpy(b->rows[at].chars, s, len);
    b->rows[at].chars[len] = '\0';
    b->numrows++;
}

static void buf_del_row(int at)
{
    PqEditBuf *b = &E.buf;
    if (at < 0 || at >= b->numrows) return;
    free(b->rows[at].chars);
    memmove(&b->rows[at], &b->rows[at + 1],
            sizeof(PqEditRow) * (size_t)(b->numrows - at - 1));
    b->numrows--;
}

static void row_append_string(PqEditRow *row, const char *s, size_t len)
{
    row->chars = realloc(row->chars, (size_t)row->len + len + 1);
    memcpy(&row->chars[row->len], s, len);
    row->len += (int)len;
    row->chars[row->len] = '\0';
}

static void editor_insert_char(int c)
{
    if (E.cy == E.buf.numrows) buf_insert_row(E.buf.numrows, "", 0);
    row_insert_char(&E.buf.rows[E.cy], E.cx, c);
    E.cx++;
    E.buf.dirty = 1;
}

static void editor_insert_newline(void)
{
    if (E.cx == 0) {
        buf_insert_row(E.cy, "", 0);
    } else {
        PqEditRow *row = &E.buf.rows[E.cy];
        buf_insert_row(E.cy + 1, &row->chars[E.cx], (size_t)(row->len - E.cx));
        row = &E.buf.rows[E.cy];   /* realloc 가능성 있어 재참조 */
        row->len = E.cx;
        row->chars[row->len] = '\0';
    }
    E.cy++;
    E.cx = 0;
    E.buf.dirty = 1;
}

static void editor_del_char(void)
{
    if (E.cy == E.buf.numrows) return;
    if (E.cx == 0 && E.cy == 0) return;

    PqEditRow *row = &E.buf.rows[E.cy];
    if (E.cx > 0) {
        row_del_char(row, E.cx - 1);
        E.cx--;
    } else {
        PqEditRow *prev = &E.buf.rows[E.cy - 1];
        int prevlen = prev->len;
        row_append_string(prev, row->chars, (size_t)row->len);
        buf_del_row(E.cy);
        E.cy--;
        E.cx = prevlen;
    }
    E.buf.dirty = 1;
}

/* ================================================================
 * §5  출력 버퍼 (한 번에 write) + 렌더링
 * ================================================================ */
typedef struct { char *b; int len; } Abuf;
#define ABUF_INIT {NULL, 0}

static void ab_append(Abuf *ab, const char *s, int len)
{
    char *new = realloc(ab->b, (size_t)(ab->len + len));
    if (!new) return;
    memcpy(&new[ab->len], s, (size_t)len);
    ab->b = new;
    ab->len += len;
}
static void ab_free(Abuf *ab) { free(ab->b); }

static void editor_scroll(void)
{
    if (E.cy < E.rowoff) E.rowoff = E.cy;
    if (E.cy >= E.rowoff + E.screenrows) E.rowoff = E.cy - E.screenrows + 1;
    if (E.cx < E.coloff) E.coloff = E.cx;
    if (E.cx >= E.coloff + E.screencols) E.coloff = E.cx - E.screencols + 1;
}

static void editor_draw_rows(Abuf *ab)
{
    for (int y = 0; y < E.screenrows; y++) {
        int filerow = y + E.rowoff;
        if (filerow >= E.buf.numrows) {
            ab_append(ab, "~", 1);
        } else {
            PqEditRow *row = &E.buf.rows[filerow];
            int len = row->len - E.coloff;
            if (len < 0) len = 0;
            if (len > E.screencols) len = E.screencols;
            if (len > 0) ab_append(ab, &row->chars[E.coloff], len);
        }
        ab_append(ab, "\x1b[K", 3);
        ab_append(ab, "\r\n", 2);
    }
}

static void editor_draw_status_bar(Abuf *ab)
{
    ab_append(ab, "\x1b[7m", 4);
    char status[128], rstatus[64];
    int len = snprintf(status, sizeof(status), " %.30s%s  seq=%llu",
        E.buf.path ? E.buf.path : "[no name]",
        E.buf.dirty ? " [수정됨]" : "",
        (unsigned long long)E.buf.seq);
    int rlen = snprintf(rstatus, sizeof(rstatus), "%d,%d ", E.cy + 1, E.cx + 1);
    if (len > E.screencols) len = E.screencols;
    ab_append(ab, status, len);
    while (len < E.screencols) {
        if (E.screencols - len == rlen) {
            ab_append(ab, rstatus, rlen);
            break;
        }
        ab_append(ab, " ", 1);
        len++;
    }
    ab_append(ab, "\x1b[m", 3);
    ab_append(ab, "\r\n", 2);
}

static void editor_draw_message_bar(Abuf *ab)
{
    ab_append(ab, "\x1b[K", 3);
    int msglen = (int)strlen(E.statusmsg);
    if (msglen > E.screencols) msglen = E.screencols;
    if (msglen) ab_append(ab, E.statusmsg, msglen);
}

static void editor_set_status(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(E.statusmsg, sizeof(E.statusmsg), fmt, ap);
    va_end(ap);
}

static void editor_refresh_screen(void)
{
    editor_scroll();

    Abuf ab = ABUF_INIT;
    ab_append(&ab, "\x1b[?25l", 6);
    ab_append(&ab, "\x1b[H", 3);

    editor_draw_rows(&ab);
    editor_draw_status_bar(&ab);
    editor_draw_message_bar(&ab);

    char buf[32];
    int n = snprintf(buf, sizeof(buf), "\x1b[%d;%dH",
                      (E.cy - E.rowoff) + 1, (E.cx - E.coloff) + 1);
    ab_append(&ab, buf, n);

    ab_append(&ab, "\x1b[?25h", 6);

    write(STDOUT_FILENO, ab.b, (size_t)ab.len);
    ab_free(&ab);
}

/* ================================================================
 * §6  키 처리
 * ================================================================ */
static void editor_move_cursor(int key)
{
    PqEditRow *row = (E.cy >= E.buf.numrows) ? NULL : &E.buf.rows[E.cy];

    switch (key) {
        case ARROW_LEFT:
            if (E.cx != 0) E.cx--;
            else if (E.cy > 0) { E.cy--; E.cx = E.buf.rows[E.cy].len; }
            break;
        case ARROW_RIGHT:
            if (row && E.cx < row->len) E.cx++;
            else if (row && E.cx == row->len && E.cy < E.buf.numrows - 1) { E.cy++; E.cx = 0; }
            break;
        case ARROW_UP:
            if (E.cy != 0) E.cy--;
            break;
        case ARROW_DOWN:
            if (E.cy < E.buf.numrows - 1) E.cy++;
            break;
    }

    row = (E.cy >= E.buf.numrows) ? NULL : &E.buf.rows[E.cy];
    int rowlen = row ? row->len : 0;
    if (E.cx > rowlen) E.cx = rowlen;
}

/* Ctrl-Q 두 번 눌러야 미저장 종료 확인 */
static int quit_confirm_pending = 0;

static int editor_process_keypress(void)
{
    int c = editor_read_key();

    switch (c) {
        case '\r':
            editor_insert_newline();
            break;

        case 17: /* Ctrl-Q */
            if (E.buf.dirty && !quit_confirm_pending) {
                editor_set_status("저장 안 된 변경사항 있음 — 한 번 더 Ctrl-Q로 무시하고 종료");
                quit_confirm_pending = 1;
                return 1;
            }
            write(STDOUT_FILENO, "\x1b[2J\x1b[H", 7);
            return 0;   /* 종료 신호 */

        case 19: /* Ctrl-S */
        case 24: /* Ctrl-X (저장+종료) */
        {
            int r = pq_edit_save(&E.buf);
            if (r == 0) {
                editor_set_status("저장됨 (양자내성 재암호화 완료, seq=%llu)",
                                   (unsigned long long)E.buf.seq);
                if (c == 24) {
                    write(STDOUT_FILENO, "\x1b[2J\x1b[H", 7);
                    return 0;
                }
            } else {
                editor_set_status("저장 실패 (r=%d)", r);
            }
            break;
        }

        case HOME_KEY: E.cx = 0; break;
        case END_KEY:
            if (E.cy < E.buf.numrows) E.cx = E.buf.rows[E.cy].len;
            break;

        case BACKSPACE:
        case 8:
            editor_del_char();
            break;
        case DEL_KEY:
            editor_move_cursor(ARROW_RIGHT);
            editor_del_char();
            break;

        case PAGE_UP:
        case PAGE_DOWN: {
            if (c == PAGE_UP) E.cy = E.rowoff;
            else E.cy = E.rowoff + E.screenrows - 1;
            int times = E.screenrows;
            while (times--)
                editor_move_cursor(c == PAGE_UP ? ARROW_UP : ARROW_DOWN);
            break;
        }

        case ARROW_UP: case ARROW_DOWN: case ARROW_LEFT: case ARROW_RIGHT:
            editor_move_cursor(c);
            break;

        case '\x1b':
        case 0:
            break;

        default:
            if (!iscntrl(c)) editor_insert_char(c);
            break;
    }

    if (c != 17) quit_confirm_pending = 0;
    return 1;
}

/* ================================================================
 * §7  main
 * ================================================================ */
static void expand_home(char *out, size_t outsz, const char *rel)
{
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(out, outsz, "%s/%s", home, rel);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <path.env.kpqe> [--pub PATH] [--sec PATH]\n", argv[0]);
        return 1;
    }

    char pub_default[512], sec_default[512];
    expand_home(pub_default, sizeof(pub_default), ".atema/pq_public.key");
    expand_home(sec_default, sizeof(sec_default), ".atema/pq_secret.key");

    const char *path = argv[1];
    const char *pub = pub_default;
    const char *sec = sec_default;

    for (int i = 2; i < argc - 1; i++) {
        if (strcmp(argv[i], "--pub") == 0) pub = argv[++i];
        else if (strcmp(argv[i], "--sec") == 0) sec = argv[++i];
    }

    memset(&E, 0, sizeof(E));

    int r = pq_edit_open(&E.buf, path, pub, sec);
    if (r == -1) {
        fprintf(stderr, "키를 읽을 수 없습니다. 'atema env init' 먼저 실행하세요.\n"
                         "  공개키: %s\n  비밀키: %s\n", pub, sec);
        return 1;
    } else if (r == -2) {
        fprintf(stderr, "!! 변조 감지: AEAD 태그가 일치하지 않습니다. 파일이 손상됐거나\n"
                         "   비밀키 없이 위조되었을 수 있습니다. 편집을 거부합니다.\n");
        return 1;
    } else if (r == -3) {
        fprintf(stderr, "!! 롤백 감지: 이 파일은 이전에 확인한 버전보다 오래됐습니다.\n"
                         "   되돌려치기(replay) 공격 가능성 — 편집을 거부합니다.\n");
        return 1;
    } else if (r == -4) {
        fprintf(stderr, "IO 오류로 파일을 열 수 없습니다: %s\n", path);
        return 1;
    } else if (r == -5) {
        fprintf(stderr, "새 파일을 만들려면 안전한 난수가 필요한데 이 시스템에서 구할 수\n"
                         "없었습니다 (자세한 원인은 위 pq_random 메시지 참고). 예측 가능한\n"
                         "값으로 대체하지 않고 그대로 중단합니다.\n");
        return 1;
    } else if (r == 1) {
        editor_set_status("새 파일 — Ctrl-S로 저장하면 최초 암호화됩니다");
    } else {
        editor_set_status("HELP: Ctrl-S 저장 | Ctrl-Q 종료 | Ctrl-X 저장+종료");
    }

    enable_raw_mode();
    if (get_window_size(&E.screenrows, &E.screencols) == -1) die("get_window_size");
    E.screenrows -= 2; /* 상태바 + 메시지바 */

    while (1) {
        editor_refresh_screen();
        if (!editor_process_keypress()) break;
    }

    pq_edit_free(&E.buf);
    return 0;
}
