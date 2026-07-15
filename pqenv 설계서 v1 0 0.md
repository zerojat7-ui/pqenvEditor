# kc_pqenv 설계서
# 양자내성(Post-Quantum) .env 암호화 / 편집 도구

> Kcode Project / zerojat7
> 버전: v1.0.0 | 2026-07-10
> 상위: kc_cli 설계서 v1.0.0 (atema)

---

## 1. 개요

`.env`(환경변수 파일)에 담긴 API 키/DB 비밀번호 등을 평문으로 디스크에 두지 않고,
**ML-KEM-768(격자암호) + ChaCha20-Poly1305(AEAD)** 하이브리드로 암호화 보관한다.

목표 3가지:
1. **평문 노출 방지** — 디스크에 절대 평문 `.env`가 상주하지 않음
2. **AI/제3자 변조 방지** — 비밀키 없이는 유효한 수정이 불가능 (AEAD 인증)
3. **롤백/재생 방지** — "예전의 유효했던 암호문으로 되돌려치기" 탐지

## 2. 검증 상태 (직접 구현이라 특히 중요)

이 프로젝트는 격자암호 수학(NTT/CBD 등)까지 전부 자체 구현했다. 리스크가 큰 만큼
**공식 테스트벡터로 실제 컴파일·실행하여 검증**했다.

| 컴포넌트 | 검증 방법 | 결과 |
|----------|-----------|------|
| Keccak/SHA3/SHAKE (kc_keccak.c) | NIST 알려진 벡터 (SHA3-256/512, SHAKE128/256 각 "" 입력) | ✅ 전부 바이트 단위 일치 |
| ML-KEM-768 (kc_mlkem.c) | **C2SP/CCTV 공식 누적 KAT** — 10,000회 keygen/encaps/decaps 반복 후 SHAKE128 누적해시 비교 | ✅ `f7db260e...548d3` 완전 일치 |
| ChaCha20-Poly1305 (kc_chacha20poly1305.c) | RFC 8439 §2.8.2 공식 AEAD 테스트벡터 (평문/AAD/키/nonce 고정, 암호문+태그 비교) | ✅ 완전 일치 |
| 전체 파이프라인 (kc_env_crypto.c) | 자체 통합테스트 — 암호화→복호화, 변조탐지, 롤백탐지 | ✅ 전부 의도대로 차단 |

**중요한 한계**: ML-KEM-768 구현은 FIPS 203 ipd(초안) + Â-fix(Kyber round-3 호환)
컨벤션으로 검증됐다. 만약 나중에 다른 조직의 "FIPS 203 최종본" 구현체와 상호운용이
필요해지면 (예: 외부 서비스와 키 교환) 그 라이브러리의 컨벤션과 다시 대조해야 한다.
지금은 kc_pqenv 혼자 암호화/복호화를 모두 담당하는 **폐쇄형 로컬 도구**라 문제없다.

또한 NTT/CBD 등 다항식 연산은 **상수시간(constant-time)이 보장되지 않는다.**
로컬 단일 사용자 파일 암호화(공격자가 같은 머신에서 사이클 단위 타이밍을 측정할 수
없는 threat model)로 범위를 한정한다. 원격 서비스의 키 교환용으로 이 코드를 그대로
전용하면 안 된다.

## 3. 파일 구성

```
kc_keccak.h/c              Keccak-f[1600], SHA3-256/512, SHAKE128/256
kc_mlkem.h/c                ML-KEM-768 (FIPS 203, 격자암호)
kc_chacha20poly1305.h/c     ChaCha20-Poly1305 AEAD (RFC 8439)
kc_env_crypto.h/c           .env 파일 포맷 조립/해체 + 키관리 + 롤백검사
kc_env_editor_core.h/c      편집기 핵심로직 (줄버퍼<->평문, 열기/저장, seq사이드카) — UI와 분리해 유닛테스트 가능
kc_env_editor.c             터미널 raw-mode 편집기 본체 (nano/kilo 스타일)
kc_env_keygen.c             키쌍 생성 CLI 도구
```

## 4. .env.kpqe 파일 포맷

```
[4B]    magic "KPQE"
[1B]    version (=1)
[3B]    reserved
[1088B] mlkem_ct   — 이 저장 시점의 fresh ML-KEM-768 캡슐 (저장할 때마다 재캡슐화)
[8B]    seq        — 빅엔디안 단조증가 카운터
[16B]   file_id    — 최초 생성시 난수 고정
[12B]   nonce      — ChaCha20 nonce
[16B]   tag        — Poly1305 인증 태그
[N]     ciphertext — .env 평문 암호문
```
AAD(인증 대상, 암호화는 안 됨) = `magic ~ file_id` 전체 1120B — 헤더 필드가 섞이거나
바뀌면 태그 검증에서 바로 걸림.

## 5. 키 관리

```
kc_env_keypair_generate()
    ↓
~/.atema/pq_secret.key  (2400B, 0600)   ← ML-KEM-768 비밀키
~/.atema/pq_public.key  (1184B)         ← 공개키 (암호화만 할 땐 이것만 있어도 됨)
```

`kc_cli 설계서`의 firstrun 크레덴셜 발급과 같은 시점(`kc_firstrun_kbank_init()` 완료
직후)에 함께 생성하는 걸 권장.

## 6. 저장/롤백 방지 흐름

```
.env 편집 완료
    ↓
last_seen_seq 읽기 (~/.atema/env.seq, 0600 — 로컬 상태파일)
    ↓
kc_env_encrypt_file(ek, file_id, last_seen_seq + 1, plaintext, ...)
    ↓
.env.kpqe 로 저장
~/.atema/env.seq 를 새 seq로 갱신
```

```
.env 로드
    ↓
last_seen_seq 읽기
    ↓
kc_env_decrypt_file(dk, file_bytes, last_seen_seq, ...)
    ↓
  0  → 정상, out_seq로 last_seen_seq 갱신
 -1  → 포맷 오류 (손상/다른 파일)
 -2  → AEAD 태그 불일치 → "변조 감지" 알림, 로드 거부
 -3  → seq 롤백 → "예전 버전으로 되돌리기 시도 감지" 알림, 로드 거부
```

**AI 변조 방지가 실제로 성립하는 이유**: AI 에이전트가 파일시스템 쓰기 권한이
있어도, `~/.atema/pq_secret.key`(0600, 소유자만) 없이는 ChaCha 키를 유도할 수 없어
"그럴듯한" 위조 암호문을 만들 수 없다. 할 수 있는 건 파일을 훼손하거나(→ -2로 즉시
탐지) 예전 버전으로 되돌리는 것(→ -3으로 즉시 탐지)뿐이며 둘 다 침묵 실패가 아니라
로드 자체를 거부하는 시끄러운 실패다.

## 7. 내장형 편집기 (kc_env_editor) — tmpfs조차 안 씀

당초 §7 초안은 "tmpfs에 짧게 평문을 쓰고 $EDITOR 실행" 방식이었는데, 그보다 더
안전하게 **디스크 어디에도 평문이 닿지 않는 전용 터미널 편집기**로 구현을 바꿨다.

```
kc_env_editor <path.env.kpqe> [--pub PATH] [--sec PATH]
```

```
열기 → kc_edit_open()
  ├─ 파일 없음           → 새 문서로 시작 (seq=0, file_id 새로 생성)
  ├─ 정상                → 복호화된 내용이 즉시 화면에 표시됨 (평문은 heap 메모리에만 존재)
  ├─ AEAD 태그 불일치     → "변조 감지" 메시지 후 편집 자체를 거부하고 종료
  └─ seq 롤백 감지        → "롤백 감지" 메시지 후 편집 자체를 거부하고 종료

편집 중 → 화살표/Home/End/PageUp/PageDown 이동, 타이핑/Backspace/Delete/Enter
        → Ctrl-S 저장 (재캡슐화 — 매 저장마다 새 ML-KEM 캡슐+새 nonce)
        → Ctrl-Q 종료 (미저장 변경 있으면 한 번 더 눌러야 확인됨)
        → Ctrl-X 저장 후 종료

종료 → kc_edit_free() 가 rows/키 메모리를 memset(0)으로 지운 뒤 해제
```

**검증**: Python `pty` 모듈로 실제 키 입력을 흉내내 상호작용 테스트를 돌렸다 —
신규 파일 생성→3줄 입력→저장/종료, 재오픈시 정확한 복호화 내용/seq 표시,
재편집→저장시 seq 증가, 그리고 **변조된 파일과 롤백된 상태 양쪽 다 편집기
레벨에서 정확히 거부**되는 것까지 전부 확인됨.

이 과정에서 실제 버그를 하나 잡았다: `kc_env_decrypt_file()`의 롤백 검사가
`seq <= min_seq`로 되어 있어서, **방금 저장한 파일을 곧바로 다시 열면 자기
자신을 롤백 공격으로 오탐**하는 문제가 있었다. `seq < min_seq`로 수정 —
"이전에 본 것과 같은 버전"은 정상 허용하고 "그보다 오래된 버전"만 롤백으로
간주하도록 고쳤다.

## 8. atema CLI 연동 (kc_cli 설계서 domain 추가)

| verb | 동작 |
|------|------|
| `atema env init` | 키쌍 생성 (§5, kc_env_keygen과 동일 로직) |
| `atema env edit` | kc_env_editor 실행 (§7) |
| `atema env status` | seq/file_id/최근 수정 시각 등 메타정보 (평문 노출 없이) |

`atema env encrypt/decrypt` 같은 1회성 변환 서브커맨드는 필요성이 낮아졌다 —
편집기 자체가 열기=복호화, 저장=암호화라 별도 변환 명령 없이도 워크플로우가
끝난다.

## 9. 미결 사항

| 항목 | 상태 |
|------|------|
| env.seq 상태파일 자체의 무결성 보호 (현재는 0600 권한에만 의존) | 검토 필요 |
| ML-KEM-768 상수시간 강화 필요성 재검토 (위협모델 변경 시) | 재검토 필요 |
| 다중 기기 간 .env 동기화 시나리오 (공개키만 공유하면 되므로 설계상 가능하나 미검증) | 추후 |
| 에디터 크래시(SIGKILL 등) 시 heap 평문의 스왑아웃 가능성 — mlock() 적용 검토 | 검토 필요 |
| 큰 .env(수천 줄) 성능 — 현재 O(n) 줄 재배열, 실사용 규모론 충분하지만 미벤치마크 | 낮은 우선순위 |
| atema CLI 본체(kc_cli 설계서 §6)와의 실제 배선 (지금은 별도 바이너리로 독립 실행) | 예정 |

## 10. 작업 단계

- [x] 1단계: Keccak/SHA3/SHAKE 구현 + NIST 벡터 검증
- [x] 2단계: ML-KEM-768 구현 + CCTV 공식 KAT 검증 (10,000회 누적해시 일치)
- [x] 3단계: ChaCha20-Poly1305 구현 + RFC 8439 공식벡터 검증
- [x] 4단계: .kpqe 파일 포맷 + 롤백방지 설계/구현
- [x] 5단계: 통합 테스트 (암호화→복호화, 변조탐지, 롤백탐지 전부 통과)
- [x] 6단계: kc_env_editor_core 구현 + 유닛테스트 (신규생성/재오픈/재편집 seq증가)
- [x] 7단계: 터미널 편집기(kc_env_editor) 구현 + PTY 상호작용 테스트 통과
- [x] 8단계: 롤백검사 off-by-one 버그 발견 및 수정
- [ ] 9단계: atema CLI 본체와 배선 (`atema env edit` → kc_env_editor exec)
- [ ] 10단계: kc_firstrun.c 연동 (키쌍 자동 생성 시점)
- [ ] 11단계: mlock() 등 평문 메모리 스왑 방지 강화 검토

---

*kc_pqenv Design v1.0.0 — 2026-07-10*
*신규 소스 4쌍 (kc_keccak, kc_mlkem, kc_chacha20poly1305, kc_env_crypto)*
*Kcode Project / zerojat7*
