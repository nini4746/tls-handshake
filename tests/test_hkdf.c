/* Plan 03 verification: HKDF (RFC 5869 A.1) and the TLS 1.3 key schedule
 * (RFC 8448 "Simple 1-RTT Handshake"). All expected values are copied verbatim
 * from the RFCs. from_hex() ignores whitespace so hex blocks are pasted as-is. */
#include "test_util.h"

#include "../src/hkdf.h"
#include "../src/keysched.h"
#include "../src/util.h"

#include <string.h>

/* ClientHello and ServerHello handshake messages (with 4-byte headers) from
 * RFC 8448 section 3, used to reproduce the ClientHello..ServerHello transcript
 * hash snapshot. */
static const char *CH_HEX =
    "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a"
    "8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00"
    "91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14"
    "00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00"
    "33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe"
    "b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d"
    "00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
    "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

static const char *SH_HEX =
    "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a"
    "c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d"
    "00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d"
    "f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

/* Compare a computed buffer against an expected hex string. */
static void check_hex(const char *what, const uint8_t *got, size_t n,
                      const char *expect_hex) {
    uint8_t exp[64];
    size_t elen = from_hex(exp, sizeof exp, expect_hex);
    (void)what;
    CHECK(elen == n);
    if (elen == n)
        CHECK_MEM(got, exp, n);
}

static void test_rfc5869_a1(void) {
    uint8_t ikm[22], salt[13], info[10];
    memset(ikm, 0x0b, sizeof ikm);
    from_hex(salt, sizeof salt, "000102030405060708090a0b0c");
    from_hex(info, sizeof info, "f0f1f2f3f4f5f6f7f8f9");

    uint8_t prk[HASH_LEN];
    hkdf_extract(prk, salt, sizeof salt, ikm, sizeof ikm);
    check_hex("prk", prk, sizeof prk,
              "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    uint8_t okm[42];
    hkdf_expand(okm, sizeof okm, prk, info, sizeof info);
    check_hex("okm", okm, sizeof okm,
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865");
}

static void test_key_schedule(void) {
    uint8_t ecdhe[32], th_ch_sh[HASH_LEN], th_ch_sf[HASH_LEN];
    from_hex(ecdhe, sizeof ecdhe,
             "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    from_hex(th_ch_sh, sizeof th_ch_sh,
             "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    from_hex(th_ch_sf, sizeof th_ch_sf,
             "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

    key_schedule_t ks;
    ks_derive_handshake(&ks, ecdhe, th_ch_sh);

    check_hex("early", ks.early_secret, HASH_LEN,
              "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    check_hex("handshake", ks.handshake_secret, HASH_LEN,
              "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    check_hex("c hs traffic", ks.client_hs_traffic, HASH_LEN,
              "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    check_hex("s hs traffic", ks.server_hs_traffic, HASH_LEN,
              "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

    /* Server handshake write key/iv. */
    uint8_t key[AEAD_KEY_LEN], iv[AEAD_IV_LEN];
    ks_traffic_keys(ks.server_hs_traffic, key, iv);
    check_hex("s hs key", key, AEAD_KEY_LEN, "3fce516009c21727d0f2e4e86ee403bc");
    check_hex("s hs iv", iv, AEAD_IV_LEN, "5d313eb2671276ee13000b30");

    /* Server Finished key. */
    uint8_t fk[HASH_LEN];
    ks_finished_key(ks.server_hs_traffic, fk);
    check_hex("s finished key", fk, HASH_LEN,
              "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8");

    /* Master + application traffic secrets. */
    ks_derive_master(&ks, th_ch_sf);
    check_hex("master", ks.master_secret, HASH_LEN,
              "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
    check_hex("c ap traffic", ks.client_ap_traffic, HASH_LEN,
              "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    check_hex("s ap traffic", ks.server_ap_traffic, HASH_LEN,
              "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");

    /* Server application write key/iv. */
    ks_traffic_keys(ks.server_ap_traffic, key, iv);
    check_hex("s ap key", key, AEAD_KEY_LEN, "9f02283b6c9c07efc26bb9f2ac92e356");
    check_hex("s ap iv", iv, AEAD_IV_LEN, "cf782b88dd83549aadf1e984");
}

static void test_transcript_hash(void) {
    /* Empty-string hash snapshot (used for Derive-Secret "derived"). */
    uint8_t h[HASH_LEN];
    sha256(h, (const uint8_t *)"", 0);
    check_hex("empty", h, HASH_LEN,
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    /* SHA-256(ClientHello || ServerHello) must match the transcript hash the
     * RFC uses to derive the handshake traffic secrets. */
    uint8_t buf[512];
    size_t chn = from_hex(buf, sizeof buf, CH_HEX);
    CHECK(chn == 196);
    size_t shn = from_hex(buf + chn, sizeof buf - chn, SH_HEX);
    CHECK(shn == 90);
    sha256(h, buf, chn + shn);
    check_hex("ch..sh", h, HASH_LEN,
              "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
}

static void test_nonce(void) {
    uint8_t iv[AEAD_IV_LEN];
    from_hex(iv, sizeof iv, "5d313eb2671276ee13000b30");
    uint8_t nonce[AEAD_IV_LEN];

    /* seq 0 -> nonce == iv */
    ks_nonce(iv, 0, nonce);
    check_hex("nonce0", nonce, AEAD_IV_LEN, "5d313eb2671276ee13000b30");

    /* seq 1 -> XOR into the last byte */
    ks_nonce(iv, 1, nonce);
    check_hex("nonce1", nonce, AEAD_IV_LEN, "5d313eb2671276ee13000b31");

    /* seq 0x0102 -> XOR into the last two bytes: 0b30 ^ 0102 = 0a32 */
    ks_nonce(iv, 0x0102, nonce);
    check_hex("nonce258", nonce, AEAD_IV_LEN, "5d313eb2671276ee13000a32");
}

int main(void) {
    printf("test_hkdf\n");
    test_rfc5869_a1();
    test_key_schedule();
    test_transcript_hash();
    test_nonce();
    TEST_REPORT();
}
