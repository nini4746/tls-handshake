# 0004. AES-128-GCM은 OpenSSL `EVP_aes_128_gcm`

- 상태: 채택
- 날짜: 2026-07-13

## 맥락
SPEC 제약 C2는 AES-GCM을 libsodium으로 하도록 적었다. 그런데 libsodium의 AES-GCM은 256비트 전용이라 `TLS_AES_128_GCM_SHA256`에 쓸 수 없다.

## 결정
레코드 보호(`aead.c`)는 OpenSSL libcrypto의 `EVP_aes_128_gcm`으로 한다. 5바이트 레코드 헤더를 AAD로 넣고 nonce는 키 스케줄에서 유도한 IV와 레코드 시퀀스 번호로 만든다(`ks_nonce`).

## 대안
- libsodium: 256비트 전용이라 이 암호군에 쓸 수 없다.

## 결과
- 장점: 고정한 암호군(0003)을 그대로 구현한다. OpenSSL은 원시 암호 연산으로만 쓰므로 N4를 지킨다.
- 단점/감수한 점: libsodium과 OpenSSL 두 라이브러리에 의존한다.
