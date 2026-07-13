# Plan 04: 암호화 레코드와 핸드셰이크 완주

## 목표

AES-128-GCM으로 암호화 레코드를 복호화/암호화해 EncryptedExtensions부터 Finished까지 진행하고, 서버 Finished를 검증한 뒤 내 Finished를 보내 실서버와 핸드셰이크를 완료한다. SPEC R4 담당.

## 컨텍스트

- Plan 01~03이 만든 것: 레코드 층, ClientHello/ServerHello, 핸드셰이크 트래픽 키
- 읽을 것: RFC 8446 5.2절 (Record Payload Protection), 5.3절 (nonce), 4.4절 (Authentication Messages, 특히 4.4.4 Finished), 4.6.1절 (NewSessionTicket), 6절 (Alert), D.4절 (middlebox 호환 - CCS)
- libsodium: `crypto_aead_aes256gcm`는 256비트 전용이므로 AES-128-GCM은 다른 원천 필요 - OpenSSL libcrypto의 `EVP_aes_128_gcm` (원시 AEAD 연산이므로 SPEC C3/N3 허용 범위) 또는 다른 검증된 구현. 결정을 문서화할 것
- 이 시점에는 인증서 검증이 아직 없다 - Certificate/CertificateVerify는 파싱만 하고 통과시키되, "인증서 미검증 - plan 05 전까지 신뢰 불가" 경고를 반드시 출력 (SPEC N2는 최종 산출물 기준)

## 작업

1. `src/aead.c` - AEAD 레코드 복호화: AAD는 레코드 헤더 5바이트, nonce는 plan 03의 계산, 복호화 후 뒤에서부터 zero padding을 건너뛰고 마지막 non-zero 바이트가 실제 content type (RFC 8446 5.2절 TLSInnerPlaintext)
2. 암호화 방향도 동일 구조로. 송신/수신 시퀀스 번호는 독립 카운터
3. 레코드 디스패치 확장: type 20 (CCS)은 무시, type 21 (alert)은 level/description을 이름으로 출력 후 종료, type 23 (application_data)은 복호화 후 내부 type으로 재분기
4. `src/handshake.c` - 상태 머신: ServerHello 후 EncryptedExtensions → Certificate → CertificateVerify → Finished 순서를 강제. 어긋나면 에러. 각 메시지는 transcript hash에 누적
5. 서버 Finished 검증: finished_key 유도 → transcript hash에 대한 HMAC == verify_data 확인
6. 클라이언트 Finished 조립·암호화·송신. 이후 application traffic secret 유도 (Master Secret 단계, plan 03 코드 재사용)
7. 핸드셰이크 후 수신 루프에서 NewSessionTicket 파싱 후 무시
8. Certificate 메시지에서 DER 인증서 목록을 추출해 파일로 저장하는 디버그 경로 (plan 05의 입력 재료)

## must-haves

- AAD에 암호문 길이가 반영된 레코드 헤더가 들어갈 것 (평문 길이 아님)
- 서버 Finished 검증 실패 시 진행 중단
- 클라이언트 Finished의 transcript 범위 (서버 Finished까지 포함)
- 인증서 미검증 경고 출력
- google.com의 Certificate는 레코드 단편화를 실제로 유발 - plan 01 재조립 버퍼가 암호화 층 위에서도 동작해야 함

## 검증

- [ ] google.com과 핸드셰이크 완료 (서버 Finished 검증 통과 + 내 Finished 송신 후 서버가 연결을 끊거나 alert를 보내지 않음)
- [ ] 암호화 레코드의 내부 content type과 zero padding 처리 (단위 테스트 - RFC 8448 벡터의 암호문 레코드 복호화로 확인 가능)
- [ ] 서버 Finished verify_data 불일치 시 종료 (조작된 입력 단위 테스트)
- [ ] CCS 레코드 무시 (실서버 트래픽으로 확인)
- [ ] NewSessionTicket 파싱 후 무시 (실서버 트래픽으로 확인 - google은 보통 2장 보냄)
- [ ] alert 수신 시 이름 출력 후 종료 (잘못된 ClientHello를 일부러 보내 확인 가능)
- [ ] 잘못된 순서의 핸드셰이크 메시지 거부 (단위 테스트)
- [ ] "인증서 미검증" 경고가 출력된다
