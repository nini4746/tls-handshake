# Plan 06: 애플리케이션 데이터와 Wireshark 비교 문서

## 목표

핸드셰이크 완료 후 GET 요청을 보내 응답을 출력하고, SSLKEYLOGFILE 키 로그 옵션을 붙인 뒤, 내 클라이언트와 curl의 핸드셰이크를 Wireshark로 비교한 문서를 작성한다. SPEC R6, R7 담당.

## 컨텍스트

- Plan 01~05가 만든 것: 인증서 검증까지 포함한 완전한 핸드셰이크, application traffic secret (plan 04에서 유도)
- 읽을 것: RFC 8446 6.1절 (close_notify), SSLKEYLOGFILE 형식 (NSS Key Log Format - `CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random hex> <secret hex>` 형식의 줄들)
- Wireshark 설정: Preferences → Protocols → TLS → (Pre)-Master-Secret log filename에 키 로그 파일 지정
- 이 plan이 끝나면 SPEC의 모든 수용 기준이 닫힌다

## 작업

1. 애플리케이션 데이터 송신: application traffic key로 `GET / HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\n\r\n` 암호화 송신. HTTP 파싱은 하지 않음 (범위 외)
2. 수신 루프: application_data 복호화 → stdout 그대로 출력. 서버 close_notify 또는 EOF에서 종료. 종료 시 내 close_notify 송신
3. CLI 마무리: `./tls-client <host> [port] [--cafile <pem>] [--keylog <file>]`. keylog 기본 꺼짐 (SPEC N5)
4. 키 로그 출력: CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0 네 줄
5. 캡처: `tcpdump -i any -w mine.pcap host google.com`으로 내 클라이언트 실행분, 같은 방식으로 `curl -v https://google.com` 실행분
6. `docs/wireshark-comparison.md` 작성: 두 캡처 스크린샷, ClientHello 필드 비교표 (버전, 암호군 목록, 확장 목록), 차이점 3가지 이상과 이유 (curl의 다중 암호군, ALPN, GREASE 등이 자연스러운 소재), 키 로그로 복호화된 애플리케이션 데이터 화면
7. README 갱신: 완료 조건 체크, 빌드/실행 방법, "교육용 - 실서비스 사용 금지" 문구 확인, ML-KEM 하이브리드 확장 후보 유지
8. 최종 스모크: google.com과 다른 실사이트 1곳 (예: cloudflare.com) 에서 전 과정 성공. ASan 빌드로 한 번 실행해 클린 확인

## must-haves

- keylog는 명시적 옵션일 때만 파일 출력, 그 외 어디에도 비밀 값 미출력
- close_notify 송신 후 소켓 정리
- 문서의 비교표는 실제 캡처 값 기준 (지어내지 않기)

## 검증

- [ ] google.com에서 `HTTP/1.1`로 시작하는 응답이 stdout에 출력된다
- [ ] cloudflare.com 등 두 번째 실사이트에서도 성공한다
- [ ] close_notify를 보내고 연결을 정리한다
- [ ] `--keylog` 없이 실행하면 키 로그 파일이 생기지 않고 비밀 값이 출력되지 않는다
- [ ] `--keylog`로 만든 파일로 Wireshark에서 애플리케이션 데이터 복호화 성공, 화면이 문서에 포함된다
- [ ] docs/wireshark-comparison.md에 내 클라이언트/curl 캡처 스크린샷 각 1장 이상
- [ ] ClientHello 필드 비교표 존재
- [ ] 차이점과 이유 3가지 이상 서술
- [ ] README와 시작 배너에 "교육용 - 실서비스 사용 금지" 문구 존재 (SPEC N1 최종 확인)
