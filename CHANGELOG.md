# 변경 이력

이 프로젝트의 주요 변경 사항을 기록합니다. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따릅니다.

## 2026-11-18
### 문서
- README를 구조도와 흐름도 중심으로 다시 썼습니다.
- 요구사항 명세(SRS)와 설계 명세(SDS)를 추가했습니다.

## 2026-07-23
### 문서
- Wireshark 비교 문서에 내 클라이언트와 curl의 ClientHello 캡처, 키 로그 복호화 화면과 원본 pcap을 추가했습니다.

## 2026-07-13
### 추가
- TLS 레코드 층과 핸드셰이크 메시지 재조립 버퍼.
- ClientHello 조립(SNI, supported_versions, supported_groups, key_share, signature_algorithms)과 ServerHello 파싱. 제시하지 않은 값 선택과 HelloRetryRequest를 감지해 중단합니다.
- HKDF와 TLS 1.3 키 스케줄. RFC 5869/8448 테스트 벡터를 통과합니다.
- AES-128-GCM 레코드 보호와 핸드셰이크 완주까지의 상태 머신.
- 인증서 검증: 미니멀 X.509/DER 파서, PEM CA 번들 로더(`--cafile`), 체인 서명, 만료, SAN, CertificateVerify 검증. 검증을 끄는 `--insecure`는 경고를 출력합니다.
- 애플리케이션 데이터 송수신과 close_notify.
- `--keylog <file>` 옵션으로 SSLKEYLOGFILE 형식 키 로그를 기록합니다.
### 문서
- curl과 ClientHello를 비교하고 키 로그로 복호화하는 Wireshark 비교 문서를 추가했습니다.
