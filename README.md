# TLS 핸드셰이크 수제 구현

> 토이 6번. 언어: C. 암호 프리미티브만 라이브러리, 프로토콜은 수제.
> **교육용 - 실서비스 사용 금지 / educational - not for production use.**
> 자작 TLS/암호 코드의 정석 주의: 이 구현을 실서비스/프로덕션에 쓰지 말 것 (SPEC N1).

`google.com` 같은 실제 https 사이트와 TLS 1.3 핸드셰이크를 끝까지 진행하고, 인증서 체인을
검증한 뒤 `GET /` 응답을 받아 출력한다. "https가 바이트 단위로 무엇을 하는지" 학습이 목적.

## 무엇이 수제인가

- TLS 레코드 층 (평문/암호문, 단편화 재조립)
- ClientHello 조립 / ServerHello 파싱, 협상 방어
- HKDF 키 스케줄 (HKDF-Expand-Label, Derive-Secret, 트래픽 키/IV/nonce) - RFC 8448 벡터 일치
- AES-128-GCM 레코드 보호의 TLS 프레이밍 (AAD, nonce, TLSInnerPlaintext)
- 핸드셰이크 상태 머신, 서버/클라 Finished HMAC 검증
- 미니멀 X.509/DER 파서, PEM/base64 디코딩, 체인 구성/서명 검증, SAN 매칭, CertificateVerify

## 무엇이 라이브러리인가 (프리미티브만, SPEC N3/C2/C3)

- **libsodium**: X25519(`crypto_scalarmult`), SHA-256, HMAC-SHA256
- **OpenSSL libcrypto**: AES-128-GCM 원시 AEAD, RSA-PSS/PKCS1·ECDSA 원시 서명 검증
  (`X509_*`, `SSL_*`, EVP HKDF 등 고수준 API는 사용 안 함 - SPEC N4)

## 빌드

macOS + Homebrew. 의존성: `brew install libsodium openssl@3`.

```
make            # tls-client 빌드
make test       # 단위 테스트 (RFC 5869 / RFC 8448 / X.509 벡터, 소켓 불필요)
make SAN=1 test # ASan/UBSan 빌드로 테스트
make clean
```

## 실행

```
./tls-client <host> [port] [--cafile <pem>] [--keylog <file>] [--insecure] [--dump-certs]

# 신뢰 앵커 번들 받기 (수제 PEM 로더가 읽음)
curl -sL https://curl.se/ca/cacert.pem -o cacert.pem

# 인증서 검증까지 포함한 정상 실행 (응답 본문은 stdout, 진행 로그는 stderr)
./tls-client google.com 443 --cafile cacert.pem

# 키 로그(기본 꺼짐, SPEC N5)로 Wireshark 복호화용 시크릿 출력
./tls-client google.com 443 --cafile cacert.pem --keylog keylog.txt
```

- `--cafile`이 없으면 검증 불가로 종료한다 (기본값은 검증 활성, SPEC N2).
- `--insecure`는 검증을 끄되 경고를 출력한다. 기본값이 절대 아니다 (SPEC N2).
- 시작 시 "교육용 - 실서비스 사용 금지" 배너를 항상 출력한다 (SPEC N1).

## 완료 조건 체크

- [x] 실제 https 서버(google.com, cloudflare.com)와 1-RTT 풀 핸드셰이크 성공
- [x] 서버/클라이언트 Finished 검증, application traffic key로 GET 송신·응답 수신
- [x] 인증서 체인 서명(ECDSA 리프 + RSA 경로) / 만료 / SAN / CertificateVerify 검증
- [x] RFC 8448 "Simple 1-RTT Handshake" 키 스케줄 벡터 비트 단위 일치 (단위 테스트)
- [x] 레코드 단편화 양방향 재조립, ChangeCipherSpec 무시, NewSessionTicket 파싱 후 무시
- [x] `--keylog`로 SSLKEYLOGFILE 형식 출력, close_notify 송신 후 정리
- [x] `docs/wireshark-comparison.md`: 내 클라이언트 vs curl ClientHello 비교

## 구조

```
src/int.h,buf,reader   빅엔디언 정수 / 가변 버퍼 / 커서 파서
src/net,record         TCP, 레코드 읽기·쓰기, 재조립 버퍼(handshake_buf)
src/hello              ClientHello/ServerHello
src/hkdf,keysched      HKDF, 키 스케줄, 트래픽 키/nonce/Finished
src/aead               AES-128-GCM 레코드 보호
src/handshake          상태 머신 (핸드셰이크 완주)
src/der,x509,pem,verify 인증서 검증
src/appdata            애플리케이션 데이터, keylog, close_notify
tests/                 단위 테스트 + RFC 8448 벡터(vec_aead.h)
docs/                  Wireshark 비교 문서
```

## 확장 후보 (범위 외)

- **ML-KEM 하이브리드 (X25519MLKEM768)**: 2026 전환기 양자내성 하이브리드 키 교환.
  `key_share` 확장이 그룹 교체 가능하도록 짜여 있어, 하이브리드 그룹과 공유 비밀 결합만
  추가하면 붙는다. 완료 후 확장 후보로만 기재 (SPEC 경계).
