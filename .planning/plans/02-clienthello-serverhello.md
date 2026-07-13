# Plan 02: ClientHello 조립과 ServerHello 파싱

## 목표

실서버가 수락하는 ClientHello를 바이트 단위로 조립해 보내고, ServerHello를 파싱해 협상 결과를 확인한다. SPEC R2 담당.

## 컨텍스트

- Plan 01이 만든 것: TCP 연결, 레코드 읽기/쓰기, 핸드셰이크 메시지 재조립 버퍼, 정수 헬퍼
- 읽을 것: RFC 8446 4.1.2절 (ClientHello), 4.1.3절 (ServerHello), 4.2절 (Extensions 중 사용하는 것만), 4.1.4절 (HelloRetryRequest - 감지용 고정 random 값)
- libsodium: `crypto_kx` 말고 저수준 `crypto_scalarmult_base`로 X25519 키쌍 생성 (공유 비밀 계산은 plan 03)
- 협상 고정값: 버전 TLS 1.3 (supported_versions 0x0304), 그룹 x25519 (0x001d), 암호군 TLS_AES_128_GCM_SHA256 (0x1301)

## 작업

1. `src/hello.c` - ClientHello 조립: legacy_version 0x0303, random 32바이트 (libsodium randombytes), legacy_session_id는 호환용 32바이트 랜덤 권장, 암호군 목록 {0x1301}, 확장 조립
2. 확장 5종: server_name (SNI), supported_versions, supported_groups, key_share (X25519 공개키 32바이트), signature_algorithms (서버 인증서 검증에 대비해 rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256 등 실사이트가 쓰는 것 포함 - RFC 8446 4.2.3절)
3. ServerHello 파싱: 선택된 암호군, key_share 확장에서 서버 공개키 32바이트, supported_versions 확인
4. 방어 로직: 0x0304 아니면 종료, 제시 안 한 암호군 선택 시 종료, ServerHello.random이 HRR 고정 상수와 같으면 "HRR 미지원" 에러로 종료
5. main에서 연결 → ClientHello 송신 → ServerHello 파싱 결과 출력 (협상된 값, 서버 공개키 hex)
6. Wireshark로 자기 ClientHello가 정상 디코딩되는지 확인 (tcpdump로 캡처 후 열기)

## must-haves

- 확장 길이 필드들의 중첩 구조를 정확히 (전체 확장 블록 길이 → 개별 확장 길이 → 내부 리스트 길이. 오프바이원이 가장 흔한 함정)
- ClientHello 원본 바이트 보관 (plan 03의 transcript hash에 필요 - 레코드 헤더 제외, 핸드셰이크 메시지 전체)
- HRR 감지 (random == 특정 SHA-256 상수, RFC 8446 4.1.3절)

## 검증

- [ ] google.com:443에 ClientHello를 보내면 alert 없이 ServerHello가 돌아온다
- [ ] ServerHello의 supported_versions가 0x0304임을 확인하고, 아니면 에러 종료 (코드 경로 존재)
- [ ] 서버가 0x1301 외 암호군을 선택하면 에러 종료 (코드 경로 존재, 단위 테스트로 확인)
- [ ] HRR random 상수 감지 시 명시 에러 종료 (단위 테스트로 확인)
- [ ] Wireshark에서 내 ClientHello가 오류 없이 "Client Hello"로 디코딩된다
