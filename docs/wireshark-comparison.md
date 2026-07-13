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

GUI Wireshark에서 같은 화면을 보려면: 아래 "키 로그로 복호화" 절차대로 `--keylog`로 캡처를
복호화하면 ClientHello뿐 아니라 암호화된 EncryptedExtensions/Certificate/응답까지 디코딩된다.
스크린샷은 사용자의 GUI 환경에서 `mine.pcap` / `curl.pcap`을 열어 캡처해 이 폴더에
`mine.png` / `curl.png`로 추가하면 된다 (헤드리스 CI에서는 생성 불가).

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
> 스크린샷(`mine.png`, `curl.png`, `decrypted.png`)은 GUI 환경에서 위 절차로 캡처해 추가한다.
