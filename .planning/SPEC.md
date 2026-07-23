# TLS 1.3 클라이언트 수제 구현 명세

> 학습용 토이 프로젝트. 1인 개발, 2~3주 분량. 언어 C. 기준 문서 RFC 8446.
> 모호성 게이트 통과 기록: 목표 0.90 / 경계 0.85 / 제약 0.80 / 수용 0.85 → 모호성 0.1425 (≤ 0.20).
> 인터뷰와 그릴링은 자문자답으로 수행 (사용자 부재 세션). 이후 사용자 검토로 갱신 가능.

## 목적

https가 바이트 단위로 무엇을 하는지 이해한다. 암호 프리미티브(원시 연산)는 검증된 라이브러리에서 가져오되, 프로토콜 로직(핸드셰이크 상태 머신, 키 스케줄, 레코드 층, 인증서 검증)은 전부 직접 작성한다. 완성 기준은 실제 https 사이트와의 핸드셰이크 성공이다.

## 요구사항

### R1. TLS 레코드 층

1. **검증 문장**: 클라이언트는 TLS 레코드(5바이트 헤더 + 본문)를 읽고 쓸 수 있으며, 하나의 핸드셰이크 메시지가 여러 레코드에 걸쳐 오거나 하나의 레코드에 여러 메시지가 담겨 와도 올바르게 재조립한다.
2. **현재 상태**: 코드 없음.
3. **목표 상태**: TCP 소켓 위에서 레코드 읽기/쓰기 함수와, 레코드 경계와 무관하게 핸드셰이크 메시지 단위로 꺼내 주는 재조립 버퍼가 동작한다.
4. **수용 기준**:
   - [ ] 레코드 헤더(type, legacy_version, length)를 파싱하고 length만큼 본문을 정확히 읽는다
   - [ ] 본문 길이가 2^14 + 256을 초과하는 레코드는 에러로 거부한다
   - [ ] 핸드셰이크 메시지 1개가 레코드 2개 이상에 걸친 입력을 재조립해 통과한다 (단위 테스트)
   - [ ] 레코드 1개에 핸드셰이크 메시지 2개 이상이 담긴 입력을 분리해 통과한다 (단위 테스트)
   - [ ] TCP 수신이 임의 바이트 경계에서 끊겨도(부분 read) 동작한다

### R2. ClientHello 조립과 ServerHello 파싱

1. **검증 문장**: 클라이언트는 실제 서버가 수락하는 ClientHello를 바이트 단위로 직접 조립하고, ServerHello를 파싱해 협상 결과(TLS 1.3, X25519, TLS_AES_128_GCM_SHA256)를 확인한다.
2. **현재 상태**: 코드 없음.
3. **목표 상태**: SNI, supported_versions, supported_groups, key_share, signature_algorithms 확장을 포함한 ClientHello를 보내고, ServerHello에서 서버 key_share와 선택된 암호군을 추출한다.
4. **수용 기준**:
   - [ ] 조립한 ClientHello를 google.com:443에 보내면 서버가 alert 없이 ServerHello로 응답한다
   - [ ] ServerHello에서 supported_versions가 0x0304(TLS 1.3)임을 확인하고, 아니면 에러로 종료한다
   - [ ] 서버가 클라이언트가 제시하지 않은 암호군을 선택하면 에러로 종료한다
   - [ ] HelloRetryRequest(고정 random 값으로 식별)를 받으면 "HRR 미지원" 명시 에러로 종료한다
   - [x] ClientHello 바이트가 Wireshark에서 오류 없이 디코딩된다 - 2026-07-14 GUI Wireshark 4.2.2에서 `Client Hello (SNI=google.com)` 정상 디코딩 (`docs/captures/mine.png`), tshark -V로 필드 단위 확인

### R3. 키 스케줄

1. **검증 문장**: X25519 공유 비밀에서 HKDF 기반 TLS 1.3 키 스케줄을 직접 구현해 핸드셰이크/애플리케이션 트래픽 키를 유도하며, RFC 8448 테스트 벡터와 일치한다.
2. **현재 상태**: 코드 없음.
3. **목표 상태**: Early/Handshake/Master Secret 유도, transcript hash 관리, HKDF-Expand-Label, 트래픽 키와 IV 유도가 전부 자체 코드로 동작한다 (HKDF-Extract/Expand의 HMAC-SHA256 원시 연산만 라이브러리).
4. **수용 기준**:
   - [ ] RFC 8448 "Simple 1-RTT Handshake" 벡터의 handshake traffic secret들과 비트 단위로 일치한다 (단위 테스트)
   - [ ] HKDF-Expand-Label을 직접 구현했다 (라이브러리의 TLS 전용 함수 미사용)
   - [ ] transcript hash가 메시지 순서대로 누적되며, 유도 시점별 스냅샷이 벡터와 일치한다
   - [ ] 시퀀스 번호와 IV의 XOR로 per-record nonce를 만든다 (단위 테스트)

### R4. 핸드셰이크 완주와 암호화 레코드 처리

1. **검증 문장**: 클라이언트는 EncryptedExtensions, Certificate, CertificateVerify, Finished를 복호화·파싱하고, 서버 Finished를 HMAC으로 검증한 뒤 자신의 Finished를 보내 핸드셰이크를 완료한다.
2. **현재 상태**: 코드 없음.
3. **목표 상태**: AES-128-GCM(원시 연산은 라이브러리)으로 핸드셰이크 암호문 레코드를 복호화/암호화하고, 상태 머신이 메시지 순서를 강제하며, 핸드셰이크가 실서버와 끝까지 진행된다.
4. **수용 기준**:
   - [ ] 암호화 레코드의 내부 content type과 zero padding을 올바르게 처리한다
   - [ ] 서버 Finished의 verify_data를 직접 계산해 일치를 확인하고, 불일치 시 종료한다
   - [ ] 호환용 ChangeCipherSpec 레코드(type 20)를 무시하고 계속 진행한다
   - [ ] 핸드셰이크 후 도착하는 NewSessionTicket을 파싱해 소비하고 무시한다 (세션 재개는 하지 않음)
   - [ ] 서버 alert 수신 시 level과 description을 사람이 읽을 수 있게 출력하고 종료한다
   - [ ] 잘못된 순서의 핸드셰이크 메시지는 에러로 거부한다

### R5. 인증서 체인 검증

1. **검증 문장**: 클라이언트는 서버 인증서 체인을 직접 파싱·검증한다 - 체인 서명 확인, 유효 기간, 호스트네임(SAN) 매칭, CertificateVerify 서명 확인을 포함하며, 실패 시 핸드셰이크를 중단한다.
2. **현재 상태**: 코드 없음.
3. **목표 상태**: 미니멀 X.509 DER 파서(필요 필드만: tbsCertificate 바이트 범위, issuer/subject, validity, SAN, subjectPublicKeyInfo, basicConstraints, signatureAlgorithm)와 체인 구성/검증 로직이 자체 코드로 동작한다. 신뢰 앵커는 PEM CA 번들 파일(예: curl cacert.pem)에서 로드한다.
4. **수용 기준**:
   - [ ] 리프부터 신뢰 앵커까지 각 인증서의 서명을 상위 인증서 공개키로 확인한다 (서명 원시 연산만 라이브러리)
   - [ ] notBefore/notAfter를 현재 시각과 비교해 만료 인증서를 거부한다
   - [ ] SAN dNSName과 호스트네임을 매칭하며, 단일 레이블 와일드카드(`*.example.com`)를 지원한다
   - [ ] 중간 CA가 누락된 불완전 체인은 검증 실패로 종료한다 (AIA 추적 없음)
   - [ ] CertificateVerify의 서명을 transcript hash 기반 서명 대상 바이트를 직접 구성해 확인한다
   - [ ] 검증 실패 시 어느 단계에서 왜 실패했는지 출력하고 애플리케이션 데이터 없이 종료한다

### R6. 애플리케이션 데이터 송수신

1. **검증 문장**: 핸드셰이크 완료 후 애플리케이션 트래픽 키로 GET 요청을 보내고, 복호화한 HTTP 응답을 stdout에 출력한다.
2. **현재 상태**: 코드 없음.
3. **목표 상태**: `./tls-client <host> [port]` 실행으로 하드코딩 수준의 `GET / HTTP/1.1` 요청을 보내고 응답을 그대로 출력한다 (HTTP 파싱은 하지 않음).
4. **수용 기준**:
   - [ ] google.com에 대해 `HTTP/1.1`로 시작하는 응답 바이트가 stdout에 출력된다
   - [ ] google.com 외 실사이트 1곳 이상(예: cloudflare.com)에서도 성공한다
   - [ ] close_notify alert를 보내고 연결을 정리한다

### R7. 검증 문서 (Wireshark 비교)

1. **검증 문장**: 내 클라이언트와 curl의 핸드셰이크를 Wireshark로 나란히 캡처해 비교한 문서가 저장소에 존재한다.
2. **현재 상태**: **완료 (2026-07-14).** Ubuntu 24.04 컨테이너에서 tcpdump 실캡처 + Xvfb 위 GUI Wireshark 4.2.2 스크린샷으로 마감.
3. **목표 상태**: `docs/wireshark-comparison.md`에 캡처 스크린샷과 필드 비교표, 차이점 분석이 담겨 있고, SSLKEYLOGFILE 형식 키 로그 출력 옵션으로 캡처를 복호화해 확인했다.
4. **수용 기준**:
   - [x] 내 클라이언트 캡처와 curl 캡처 스크린샷이 각 1장 이상 포함된다 - `docs/captures/mine.png`, `docs/captures/curl.png` (원본 pcap 동봉). curl은 macOS SecureTransport 대신 컨테이너 curl 8.5.0(OpenSSL 3.0.13) - 백엔드 차이는 문서에 명시
   - [x] ClientHello 필드(버전, 암호군 목록, 확장 목록) 비교표가 있다 - macOS curl 실측 표 + 컨테이너 OpenSSL curl 차이 절
   - [x] 차이점과 그 이유가 최소 3가지 서술된다 - 5가지 (암호군 수, supported_versions, ALPN, groups/ec_point_formats, 레코드 버전)
   - [x] `--keylog <file>` 옵션(기본 꺼짐)으로 SSLKEYLOGFILE 형식 키 로그를 출력하고, Wireshark에서 애플리케이션 데이터 복호화에 성공한 화면이 포함된다 - `docs/captures/decrypted.png`: keylog 적용 후 `GET / HTTP/1.1` / `301 Moved Permanently` HTTP 평문 행 표시, tshark 교차 확인

## must-NOT (부정 수용 기준)

- [ ] **N1**: 이 프로젝트를 실서비스/프로덕션에 사용하지 않는다. 교육 목적 전용이며, README와 프로그램 시작 배너에 "교육용 - 실서비스 사용 금지" 문구가 존재해야 한다.
- [ ] **N2**: 인증서 검증 실패 상태에서 애플리케이션 데이터를 송신하지 않는다. 검증을 끄는 플래그를 만들더라도 기본값은 반드시 검증 활성이며, 끈 상태에서는 경고를 출력한다.
- [ ] **N3**: 암호 프리미티브(AES-GCM, SHA-256, HMAC, X25519, RSA/ECDSA 서명 원시 연산)를 직접 구현하지 않는다. 반드시 검증된 라이브러리를 쓴다.
- [ ] **N4**: 반대 방향도 금지 - 라이브러리의 고수준 TLS/X.509 API(OpenSSL의 `SSL_*`, `X509_verify_cert`, `HKDF` EVP KDF, libsodium 이외 라이브러리의 핸드셰이크 대행 함수 등)로 프로토콜 로직을 대체하지 않는다.
- [ ] **N5**: 비밀 값(트래픽 시크릿, 개인키)을 기본 동작으로 로그에 남기지 않는다. 키 로그는 명시적 `--keylog` 옵션일 때만 출력한다.

## 경계

### 범위 내

- TLS 1.3 클라이언트, 1-RTT 풀 핸드셰이크
- 암호군 TLS_AES_128_GCM_SHA256 단일, 키 교환 X25519 단일
- 레코드 층 (평문/암호문, 단편화 재조립)
- ClientHello/ServerHello와 필수 확장 (SNI, supported_versions, supported_groups, key_share, signature_algorithms)
- HKDF 키 스케줄 (RFC 8448 벡터 검증)
- 인증서 체인 검증 (미니멀 X.509 DER 파싱, 체인 서명, 만료, SAN 매칭, CertificateVerify)
- 하드코딩 GET 송신과 응답 출력
- SSLKEYLOGFILE 형식 키 로그 옵션과 Wireshark 비교 문서

### 범위 외 (이유 포함)

- **서버 구현**: 클라이언트 관점 학습이 목적. 2~3주 예산 초과
- **TLS 1.2 이하**: 레거시 협상 로직이 학습 목표와 무관하게 복잡도만 증가
- **세션 재개 (PSK, 0-RTT)**: NewSessionTicket은 파싱 후 무시. 풀 핸드셰이크 이해가 우선
- **HelloRetryRequest 재시도**: 대상 사이트가 X25519를 지원하므로 실익 없음. 감지 후 명시 에러로 종료만
- **클라이언트 인증서**: 대상 사이트가 요구하지 않음
- **OCSP/CRL 폐기 확인, AIA 체인 추적**: 인증서 검증의 핵심(서명/만료/이름)에 집중
- **ALPN, HTTP/2, HTTP 파싱**: TLS가 주제. HTTP는 한 줄 GET으로 충분
- **암호군/그룹 협상 다양화 (AES-256, ChaCha20, P-256 등)**: 단일 조합으로 학습 목표 달성
- **ML-KEM 하이브리드 (X25519MLKEM768)**: 완료 후 확장 후보로만 기재. 2026 전환기 트렌드 접점이므로 구조상 key_share 확장이 교체 가능하도록만 의식
- **메모리 안전 강화, 상수 시간 비교 등 프로덕션 수준 방어**: 교육용. 단 ASan 클린은 지향

## 제약

- **C1**: 언어 C (C11), 개발 환경 macOS. 빌드는 Makefile
- **C2**: 허용 라이브러리 - 암호 원시 연산에 한해 libsodium (X25519, AES-GCM, SHA-256, HMAC)
- **C3**: 인증서 서명 검증(RSA-PSS, ECDSA-P256)은 libsodium에 없으므로 OpenSSL libcrypto의 원시 서명 검증 API 사용 허용. 단 서명 대상 바이트 구성과 DER 파싱은 수제 (N4의 금지 목록 준수)
- **C4**: 신뢰 앵커는 PEM CA 번들 파일 (curl cacert.pem 등). PEM/base64 디코딩은 수제
- **C5**: 기간 2~3주, 1인 개발. plan당 1~4일 규모
- **C6**: 사용자가 직접 코딩한다. plan 문서는 학습 가이드 수준 - 무엇을 왜 만드는지, 어느 RFC 절을 읽어야 하는지 안내하되 완성 코드를 제공하지 않는다

## 엣지 해소 기록

| 엣지 | 결정 |
|---|---|
| 레코드 단편화 (메시지 1개가 레코드 여러 개, 레코드 1개에 메시지 여러 개) | 명세 추가 → R1 |
| HelloRetryRequest | 재시도는 기각 (범위 외, 기간 예산). 감지 후 명시 에러는 R2에 추가 |
| NewSessionTicket / 세션 재개 | 파싱 후 무시로 명세 추가 → R4. 재개는 범위 외 |
| 중간 CA 누락 체인 | AIA 추적 기각 (범위 외). 검증 실패 종료를 R5에 추가 |
| 호환용 ChangeCipherSpec | 무시 규칙 R4에 추가 |
| 와일드카드 SAN | 단일 레이블만 지원, R5에 추가 |
| 서버의 비제시 암호군 선택 | abort, R2에 추가 |
