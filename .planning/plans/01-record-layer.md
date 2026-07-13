# Plan 01: 프로젝트 골격과 TLS 레코드 층

## 목표

TCP 연결 위에서 평문 TLS 레코드를 읽고 쓰고, 레코드 경계와 무관하게 핸드셰이크 메시지를 재조립하는 층을 만든다. SPEC R1 담당.

## 컨텍스트

- 그린필드. `/Users/yunho/project/tls-handshake`에는 README.md만 있음
- 이 plan이 저장소 구조를 처음 만든다. 이후 plan들이 이 구조 위에 쌓임
- 읽을 것: RFC 8446 5.1절 (Record Layer), 5.4절 (Record Padding은 개념만)
- 핵심 개념: TLS 레코드는 `type(1) + legacy_version(2) + length(2) + fragment` 구조. 핸드셰이크 메시지는 `msg_type(1) + length(3) + body` 구조이며, 레코드 경계와 메시지 경계는 서로 독립적이다. Certificate처럼 큰 메시지는 실사이트에서 반드시 여러 레코드에 걸쳐 온다

## 작업

1. 디렉토리 골격: `src/`, `tests/`, `docs/`, `Makefile`. libsodium 링크 확인용 최소 main
2. `src/net.c` - TCP 연결 (getaddrinfo + connect), 정확히 n바이트 읽는 `read_full` 류 헬퍼. 부분 read를 반드시 루프로 처리
3. `src/record.c` - 레코드 읽기: 헤더 5바이트 → length 검사 (2^14 + 256 초과 거부) → 본문. 레코드 쓰기: 헤더 조립 + 본문
4. `src/handshake_buf.c` (이름 자유) - 재조립 버퍼: 레코드 본문을 누적하고, 4바이트 핸드셰이크 헤더의 length가 채워질 때까지 기다렸다가 메시지 단위로 꺼내는 API
5. `tests/` - 소켓 없이 메모리 버퍼로 단편화 케이스를 검증하는 단위 테스트. 테스트 러너는 assert 기반의 단순한 C 파일이면 충분
6. 빅엔디언 정수 읽기/쓰기 헬퍼 (u8/u16/u24/u32) - 이후 모든 plan이 사용

## must-haves

- 부분 read 처리 (TCP는 임의 경계에서 끊긴다)
- 레코드 길이 상한 검사
- 재조립 버퍼가 "메시지 1개 = 레코드 여러 개"와 "레코드 1개 = 메시지 여러 개"를 모두 처리
- 프로그램 시작 시 "교육용 - 실서비스 사용 금지" 배너 (SPEC N1)

## 검증

- [ ] `make && make test` 통과
- [ ] 레코드 헤더 파싱과 length만큼의 정확한 읽기 (단위 테스트)
- [ ] 본문 길이 2^14 + 256 초과 레코드 거부 (단위 테스트)
- [ ] 메시지 1개가 레코드 2개에 걸친 입력 재조립 통과 (단위 테스트)
- [ ] 레코드 1개에 메시지 2개가 담긴 입력 분리 통과 (단위 테스트)
- [ ] google.com:443에 TCP 연결 성공 (아무 바이트나 보내지 않아도 됨)
