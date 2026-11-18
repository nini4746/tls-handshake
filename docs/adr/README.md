# 설계 결정 기록 (ADR)

| 번호 | 결정 | 상태 | 날짜 |
|------|------|------|------|
| [0001](0001-crypto-primitives-from-library-protocol-by-hand.md) | 암호 원시 연산만 라이브러리, 프로토콜 로직은 직접 구현 | 채택 | 2026-07-13 |
| [0002](0002-separate-record-layer-and-handshake-buffer.md) | 레코드 층과 핸드셰이크 재조립 버퍼 분리 | 채택 | 2026-07-13 |
| [0003](0003-single-negotiation-profile.md) | 협상 조합 1개 고정 (TLS 1.3, X25519, TLS_AES_128_GCM_SHA256) | 채택 | 2026-07-13 |
| [0004](0004-aes-gcm-via-openssl.md) | AES-128-GCM은 OpenSSL `EVP_aes_128_gcm` | 채택 | 2026-07-13 |
| [0005](0005-minimal-x509-with-raw-der-ranges.md) | 미니멀 X.509 파서: 원본 DER 범위 보관, 원시 서명 검증 | 채택 | 2026-07-13 |
| [0006](0006-verify-gate-before-server-finished.md) | 인증서 검증 게이트를 서버 Finished 처리 전에 둠, 기본값은 검증 활성 | 채택 | 2026-07-13 |
| [0007](0007-opt-in-nss-keylog.md) | 키 로그는 `--keylog`일 때만, NSS 형식 | 채택 | 2026-07-13 |
