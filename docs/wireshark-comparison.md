# Wireshark 비교: 내 클라이언트 vs curl

이 문서는 이 저장소의 `tls-client`와 시스템 `curl`이 보내는 TLS 1.3 ClientHello를
바이트 단위로 실제 캡처해 비교한다. 모든 표의 값은 지어낸 것이 아니라 아래 "캡처 방법"으로
실제 수집한 바이트를 디코딩한 결과다.

> 교육용 - 실서비스 사용 금지 / educational - not for production use

## 캡처 방법

이 개발 환경은 헤드리스라 GUI Wireshark 실행과 root 권한 `tcpdump`/`tshark`가 불가능하다
(BPF 장치 접근 거부). 그래서 두 클라이언트의 **첫 TCP 세그먼트(=평문 ClientHello 레코드)**
를 로컬 리스너로 그대로 받아 저장한 뒤 디코딩했다. ClientHello는 핸드셰이크 첫 메시지이자
암호화 이전이므로, 이 캡처는 Wireshark가 "Client Hello"로 보여주는 바이트와 동일하다.

```
# 127.0.0.1:9443 에서 한 연결의 ClientHello 바이트를 파일로 저장하는 리스너를 띄우고
python3 capture.py curl_ch.bin &   ; curl -sk https://127.0.0.1:9443/
python3 capture.py mine_ch.bin &   ; ./tls-client 127.0.0.1 9443
```

- 내 클라이언트 캡처: 173바이트 (레코드 헤더 5 + ClientHello 168)
- curl 캡처: 301바이트
- curl 백엔드: `curl 8.7.1 ... (SecureTransport) LibreSSL/3.3.6` (macOS 기본)

## Wireshark 스크린샷 (실캡처, 2026-07-14)

위 로컬 리스너 방식과 별개로, Ubuntu 24.04 컨테이너(aarch64)에서 root `tcpdump`로
google.com:443 대상 **전체 세션**을 캡처하고 Xvfb 가상 디스플레이 위에 GUI Wireshark
4.2.2를 띄워 스크린샷을 떴다. 파일은 `captures/`에 있다:

- `captures/mine.png` - `mine.pcap`(내 클라이언트, `./tls-client google.com 443
  --cafile cacert.pem --keylog ...`)의 패킷 리스트. Client Hello(SNI=google.com,
  레코드 241B) → Server Hello/CCS → Application Data 흐름과 1-RTT 완료가 보인다.
- `captures/curl.png` - `curl.pcap`(컨테이너 curl 8.5.0, OpenSSL 3.0.13 백엔드)의
  패킷 리스트. Client Hello가 589B 프레임으로 훨씬 크다.
- `captures/decrypted.png` - `mine.pcap`을 `tls.keylog_file`에 키 로그를 지정해 연
  화면. 필터 `http || tls.handshake` 아래 **`GET / HTTP/1.1`과
  `HTTP/1.1 301 Moved Permanently`가 HTTP 평문 행으로 디코딩**되고, Encrypted
  Extensions / Certificate / Finished도 풀려 있다 = 복호화 성공 증거.
- 원본 pcap 2개도 `captures/`에 포함 (키 로그 파일은 저장소에 넣지 않는다 - pcap과
  키 로그가 함께 있으면 세션이 통째로 복호화되므로).

tshark 교차 확인: `tshark -r mine.pcap -o tls.keylog_file:... `에서
`Encrypted Extensions, Certificate, Certificate Verify, Finished`(#10),
`GET / HTTP/1.1`(#14), `301 Moved Permanently (text/html)`(#16), Close Notify(#18).

### 컨테이너 curl(OpenSSL)과 위 표(macOS SecureTransport)의 차이

위 비교표는 macOS `curl`(SecureTransport/LibreSSL 백엔드) 실측이다. 스크린샷의
컨테이너 curl은 OpenSSL 3.0.13 백엔드라 ClientHello가 또 다르다 (curl.pcap의
tshark 실측): 암호군 31개(TLS 1.3 3종 + ECDHE/DHE/RSA CBC·GCM 레거시 + SCSV),
확장 12개, **ALPN `h2, http/1.1` 포함 → 서버와 HTTP/2 협상** (decrypted 확인 시
HTTP2 SETTINGS/HEADERS 프레임), ec_point_formats 있음, GREASE 없음, 레코드 버전
0x0301. 클라이언트 구현마다 지문이 다르다는 점 자체가 이 문서의 비교 포인트다 -
내 클라이언트(1 암호군/5 확장/ALPN 없음)는 그중 최소 지문이다.

## ClientHello 필드 비교표

| 필드 | 내 `tls-client` | `curl` (SecureTransport) |
|---|---|---|
| record layer version | 0x0303 | 0x0301 |
| legacy_version | 0x0303 | 0x0303 |
| legacy_session_id | 32바이트 (미들박스 호환) | 32바이트 |
| cipher suites | **1개**: `TLS_AES_128_GCM_SHA256` (0x1301) | **49개**: TLS 1.3 3종(0x1301/1302/1303) + TLS 1.2/레거시 46종(ECDHE, RSA, 3DES 등) + SCSV(0x00ff) |
| compression | null(0) | null(0) |
| 확장 개수 | 5 | 6 |
| server_name (SNI) | 있음 | 있음 |
| supported_versions | TLS 1.3(0x0304) **단일** | 0x0304, 0x0303, 0x0302, 0x0301 (1.3~1.0) |
| supported_groups | x25519 **단일** | x25519, secp256r1, secp384r1, secp521r1 |
| signature_algorithms | 있음 (검증 가능한 4종만) | 있음 (다수) |
| key_share | x25519 1개 | x25519 1개 |
| ec_point_formats | 없음 | 있음 |
| ALPN | 없음 | `h2, http/1.1` |
| GREASE | 없음 | 없음 (이 curl 빌드는 미사용) |

내 ClientHello 원본 바이트 (레코드 헤더 포함, 173바이트):

```
16 03 03 00 a8 01 00 00 a4 03 03 <32B random> 20 <32B session_id>
00 02 13 01 01 00 00 79 ...확장...
```
(전체 hex는 `./tls-client <host> 443`을 로컬 리스너로 캡처하거나 소스의 `hello.c` 참고.)

## 차이점과 이유 (3가지 이상)

1. **암호군 개수 1 vs 49**. 내 클라이언트는 학습 목표대로 `TLS_AES_128_GCM_SHA256` 단일
   조합만 제시한다(명세 경계: 단일 암호군/단일 그룹). curl은 서버 호환성을 위해 TLS 1.3
   3종에 더해 TLS 1.2 ECDHE/RSA, 심지어 3DES까지 폭넓게 제시한다. 학습용은 상태 머신과 키
   유도의 정확성이 목적이라 협상 다양성을 의도적으로 뺐다.

2. **supported_versions 1.3 단독 vs 1.3~1.0**. 내 클라이언트는 0x0304만 보내 TLS 1.3이
   아니면 즉시 종료한다(다운그레이드 여지 없음). curl은 1.0까지 하위 버전을 함께 제시해
   구형 서버와도 붙는다. 단일 버전만 보내는 쪽이 코드와 공격 표면이 단순하다.

3. **ALPN 유무**. curl은 `h2, http/1.1`로 HTTP/2를 협상하려 ALPN을 넣는다. 내 클라이언트는
   HTTP를 한 줄 GET으로만 다루고 ALPN은 범위 외라 넣지 않는다. 그래서 서버는 내 연결에서
   HTTP/1.1로 응답한다.

4. **supported_groups / ec_point_formats 범위**. curl은 x25519 외 P-256/384/521과
   ec_point_formats까지 제시한다. 내 클라이언트는 X25519 단일 키 교환만 지원하므로
   supported_groups도 x25519 하나이고 ec_point_formats는 TLS 1.3에서 불필요해 생략한다.

5. **record layer version 0x0301 vs 0x0303**. 두 클라이언트 모두 legacy_version은
   0x0303이지만, 바깥 레코드 헤더의 legacy_record_version을 curl(SecureTransport)은
   0x0301로, 내 클라이언트는 0x0303으로 쓴다. TLS 1.3에서 이 필드는 무시되며 어떤 값이든
   서버가 수용한다(RFC 8446 5.1).

## 키 로그로 복호화 (SSLKEYLOGFILE)

`--keylog <file>` 옵션을 주면(기본 꺼짐, SPEC N5) 핸드셰이크 완료 후 NSS Key Log 형식으로
네 줄을 append 한다:

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random hex> <secret hex>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random hex> <secret hex>
CLIENT_TRAFFIC_SECRET_0        <client_random hex> <secret hex>
SERVER_TRAFFIC_SECRET_0        <client_random hex> <secret hex>
```

실제 출력 예 (값은 세션마다 바뀜):

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 9b5a05d5...5c381c96 485172267994a5c8...61d1c9b4
SERVER_HANDSHAKE_TRAFFIC_SECRET 9b5a05d5...5c381c96 718a682879...ec789176
CLIENT_TRAFFIC_SECRET_0        9b5a05d5...5c381c96 6ecf910593...a53afcbb
SERVER_TRAFFIC_SECRET_0        9b5a05d5...5c381c96 ab4cc8d30c...7d63cc52
```

GUI Wireshark에서 복호화하는 절차:

1. 트래픽 캡처: `sudo tcpdump -i any -w mine.pcap host <target>` 를 켠 상태에서
   `./tls-client <target> 443 --cafile cacert.pem --keylog keylog.txt` 실행.
2. Wireshark → Preferences → Protocols → TLS → **(Pre)-Master-Secret log filename**에
   `keylog.txt` 지정.
3. `mine.pcap`을 열면 ClientHello/ServerHello는 물론 EncryptedExtensions, Certificate,
   CertificateVerify, Finished, 그리고 애플리케이션 데이터(HTTP 응답)까지 평문으로 디코딩된다.
4. curl 비교분은 `SSLKEYLOGFILE=keylog_curl.txt curl ...`로 같은 절차를 반복.

> 이 저장소의 키 로그 4줄은 Wireshark의 TLS 1.3 복호화에 필요한 그대로의 라벨/형식이다.
> 위 절차를 실제 수행한 결과가 `captures/decrypted.png`다 (2026-07-14, Wireshark 4.2.2 + Xvfb).
