# Plan 03: HKDF 키 스케줄

## 목표

X25519 공유 비밀에서 TLS 1.3 키 스케줄을 직접 구현해 핸드셰이크 트래픽 키를 유도하고, RFC 8448 테스트 벡터와 비트 단위로 일치시킨다. SPEC R3 담당.

## 컨텍스트

- Plan 02가 만든 것: 클라이언트 X25519 키쌍, 서버 공개키, ClientHello/ServerHello 원본 바이트
- 읽을 것: RFC 8446 7.1절 (Key Schedule), RFC 5869 (HKDF), RFC 8448 3절 (Simple 1-RTT Handshake - 테스트 벡터의 원천)
- libsodium 허용 범위: `crypto_auth_hmacsha256` (HMAC), `crypto_hash_sha256` (해시), `crypto_scalarmult` (X25519 공유 비밀). HKDF 자체와 HKDF-Expand-Label은 반드시 수제 (SPEC N4)
- 이 plan은 네트워크 없이 완결 가능 - RFC 8448 벡터만으로 개발/검증하고, 실서버 적용은 plan 04에서

## 작업

1. `src/hkdf.c` - HKDF-Extract (HMAC 한 번), HKDF-Expand (RFC 5869의 카운터 루프). RFC 5869 부록 A 테스트 벡터로 먼저 확인
2. HKDF-Expand-Label - HkdfLabel 구조체 직렬화 (length + "tls13 " 접두 label + context). Derive-Secret은 transcript hash를 context로 넣는 래퍼
3. `src/keysched.c` - 키 스케줄 상태: Early Secret (PSK 없음 → 0으로 Extract) → Derive-Secret("derived") → Handshake Secret (ECDHE 주입) → client/server_handshake_traffic_secret → Master Secret → application traffic secret
4. transcript hash 관리 - 핸드셰이크 메시지(레코드 헤더 제외)를 순서대로 SHA-256에 누적. 유도 시점별 스냅샷이 필요하므로 스트리밍 해시 상태 복사 가능하게
5. 트래픽 키 유도 - secret → key (16바이트), iv (12바이트). per-record nonce는 iv XOR 시퀀스 번호 (RFC 8446 5.3절)
6. `tests/test_rfc8448.c` - RFC 8448 3절의 값들을 하드코딩해 각 단계 출력과 비교. 최소한 client/server_handshake_traffic_secret, 트래픽 key/iv까지

## must-haves

- RFC 8448 벡터 일치가 이 plan의 존재 이유 - 실서버 대상 디버깅은 벡터 불일치 상태에서는 불가능에 가깝다
- HKDF-Expand-Label의 label 앞 "tls13 " 접두사 (공백 포함 7바이트) - 가장 흔한 불일치 원인
- transcript hash에 레코드 헤더가 섞이지 않을 것
- 비밀 값을 stdout에 상시 출력하지 않을 것 (SPEC N5 - 테스트 코드 내부는 예외)

## 검증

- [ ] RFC 5869 부록 A 벡터 통과 (단위 테스트)
- [ ] RFC 8448 client_handshake_traffic_secret / server_handshake_traffic_secret 일치 (단위 테스트)
- [ ] RFC 8448 트래픽 key/iv 일치 (단위 테스트)
- [ ] transcript hash 유도 시점별 스냅샷이 벡터와 일치 (단위 테스트)
- [ ] iv XOR 시퀀스 번호 nonce 계산 (단위 테스트)
- [ ] HKDF-Expand-Label이 수제임 (라이브러리 TLS 전용 KDF 미사용 - 코드 검토로 확인)
