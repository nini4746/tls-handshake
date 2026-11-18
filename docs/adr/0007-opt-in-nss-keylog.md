# 0007. 키 로그는 `--keylog`일 때만, NSS 형식

- 상태: 채택
- 날짜: 2026-07-13

## 맥락
Wireshark로 애플리케이션 데이터를 복호화해 구현을 검증하려면 트래픽 시크릿이 필요하다.
비밀 값은 기본 동작으로 로그에 남기면 안 된다(N5).

## 결정
`--keylog <file>`을 준 경우에만 client_random 기준 NSS(SSLKEYLOGFILE) 형식으로 `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`을 기록한다.

## 대안
- 항상 출력: 비밀 값이 기본으로 노출된다.
- 환경 변수: 명시적 옵션일 때만 출력하는 쪽을 택했다.

## 결과
- 장점: Wireshark가 바로 읽는 형식이다. `docs/wireshark-comparison.md`에 복호화 화면이 있다.
- 단점/감수한 점: 키 로그 파일 자체는 비밀 값이므로 사용자가 관리해야 한다.
