# Plan 05: 인증서 체인 검증

## 목표

미니멀 X.509 DER 파서와 체인 검증 로직을 직접 만들어 서버 인증서의 서명 체인, 유효 기간, 호스트네임을 확인하고, CertificateVerify 서명을 검증한다. 실패 시 핸드셰이크를 중단한다. SPEC R5 담당.

> ⚠ 위험 플래그: 6개 plan 중 가장 큰 덩어리. X.509 파싱이 늘어지면 "필요 필드만" 원칙으로 계속 쳐낼 것. 필요하면 05a (파싱) / 05b (검증) 로 쪼개도 됨.

## 컨텍스트

- Plan 04가 만든 것: 핸드셰이크 완주, Certificate 메시지의 DER 목록 추출 (디버그 저장 경로 포함 - 파서 개발 시 네트워크 없이 파일로 반복 가능)
- 읽을 것: RFC 5280 4.1절 (Certificate 구조), 4.2.1.6절 (SAN), 4.2.1.9절 (basicConstraints), RFC 8446 4.4.3절 (CertificateVerify), RFC 6125 6.4절 (호스트네임 매칭)
- ASN.1 DER은 TLV (tag, length, value) 재귀 구조 - 토이 3~5의 바이너리 파싱 감각이 그대로 쓰인다. 범용 ASN.1 라이브러리를 만들지 말고, 인증서 구조를 따라가는 커서형 파서면 충분
- 서명 원시 검증은 OpenSSL libcrypto 허용 (SPEC C3): RSA-PSS(rsae)와 ECDSA-P256. 단 `X509_*` 계열 API는 금지 (SPEC N4) - 서명 대상 바이트(tbsCertificate 원본 범위)를 직접 잘라 원시 verify에 넣는다
- 신뢰 앵커: curl cacert.pem을 받아 `--cafile` 인자로 전달. PEM(base64) 디코딩은 수제 (SPEC C4)

## 작업

1. `src/der.c` - TLV 커서 파서: tag 확인, 길이 디코딩 (short/long form), 자식으로 진입, 다음 형제로 이동, 원본 바이트 범위 기록
2. `src/x509.c` - 인증서에서 필요 필드만 추출: tbsCertificate 전체 바이트 범위, signatureAlgorithm OID, issuer/subject (DER 바이트 그대로 보관해 바이트 비교), validity (UTCTime/GeneralizedTime 파싱), subjectPublicKeyInfo, SAN dNSName 목록, basicConstraints cA 플래그
3. `src/pem.c` - PEM 경계 파싱 + base64 디코딩 수제, CA 번들에서 인증서 배열 로드
4. `src/verify.c` - 체인 구성: 리프의 issuer와 일치하는 subject를 서버 제공 체인에서, 마지막은 CA 번들에서 찾기 (바이트 비교). 각 단계에서 서명 알고리즘 판별 → tbs 바이트를 원시 verify. 중간 인증서의 cA 플래그 확인
5. 유효 기간: notBefore ≤ 현재 ≤ notAfter
6. 호스트네임: SAN dNSName 대소문자 무시 비교, 좌측 첫 레이블에 한한 `*` 와일드카드 (`*.example.com`은 `a.example.com` 일치, `a.b.example.com` 불일치)
7. CertificateVerify: RFC 8446 4.4.3의 서명 대상 구성 (0x20 64개 + 컨텍스트 문자열 + 0x00 + transcript hash) 후 리프 공개키로 원시 verify
8. 통합: plan 04의 상태 머신에서 Finished 진행 전에 검증 게이트. 실패 시 단계와 이유 출력 후 종료. "인증서 미검증" 경고 제거

## must-haves

- tbsCertificate는 재직렬화하지 말고 원본 바이트 범위를 그대로 서명 검증에 사용 (재직렬화 불일치가 고전적 함정)
- 검증 실패 시 애플리케이션 데이터 없이 종료 (SPEC N2)
- 불완전 체인 (중간 CA 누락) 은 실패 - AIA 추적하지 않음
- 검증 우회 플래그를 만들 경우 기본값은 검증 활성 + 우회 시 경고

## 검증

- [ ] google.com 체인이 검증 통과하고 핸드셰이크가 완료된다
- [ ] 각 인증서 서명이 상위 공개키로 확인된다 (google 리프는 ECDSA, 중간/루트 경로에 RSA 존재 - 두 알고리즘 모두 동작)
- [ ] 만료 인증서 거부 (저장한 DER의 validity를 조작하거나 시계를 속이는 단위 테스트)
- [ ] SAN 매칭: 정확 일치, 단일 레이블 와일드카드 일치, 다중 레이블 불일치 (단위 테스트)
- [ ] 호스트네임 불일치 시 실패 (예: google.com IP에 다른 SNI/호스트네임으로 검증 시도)
- [ ] 중간 CA를 뺀 체인은 검증 실패로 종료 (단위 테스트)
- [ ] CertificateVerify 서명 검증 통과, transcript 1바이트 조작 시 실패 (단위 테스트)
- [ ] 검증 실패 시 단계와 이유가 출력된다
