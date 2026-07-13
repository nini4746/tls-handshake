#include "hkdf.h"
#include "int.h"

#include <sodium.h>
#include <string.h>

void sha256(uint8_t out[HASH_LEN], const uint8_t *data, size_t len) {
    crypto_hash_sha256(out, data, len);
}

void hmac_sha256(uint8_t out[HASH_LEN], const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, keylen);
    crypto_auth_hmacsha256_update(&st, msg, msglen);
    crypto_auth_hmacsha256_final(&st, out);
}

void hkdf_extract(uint8_t prk[HASH_LEN], const uint8_t *salt, size_t saltlen,
                  const uint8_t *ikm, size_t ikmlen) {
    uint8_t zeros[HASH_LEN] = {0};
    if (salt == NULL || saltlen == 0) {
        salt = zeros;
        saltlen = HASH_LEN;
    }
    /* PRK = HMAC-Hash(salt as key, IKM as message). */
    hmac_sha256(prk, salt, saltlen, ikm, ikmlen);
}

void hkdf_expand(uint8_t *okm, size_t L, const uint8_t prk[HASH_LEN],
                 const uint8_t *info, size_t infolen) {
    uint8_t t[HASH_LEN];
    size_t tlen = 0;
    size_t done = 0;
    uint8_t counter = 1;
    while (done < L) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, HASH_LEN);
        if (tlen)
            crypto_auth_hmacsha256_update(&st, t, tlen); /* T(i-1) */
        if (infolen)
            crypto_auth_hmacsha256_update(&st, info, infolen);
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t);
        tlen = HASH_LEN;
        size_t n = (L - done < HASH_LEN) ? (L - done) : HASH_LEN;
        memcpy(okm + done, t, n);
        done += n;
        counter++;
    }
}

void hkdf_expand_label(uint8_t *out, size_t L, const uint8_t secret[HASH_LEN],
                       const char *label, const uint8_t *context,
                       size_t ctxlen) {
    /* HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>
     * where the wire label is "tls13 " + label. */
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t pos = 0;
    put_u16(info + pos, (uint16_t)L);
    pos += 2;

    size_t labellen = 6 + strlen(label); /* "tls13 " is 6 bytes */
    info[pos++] = (uint8_t)labellen;
    memcpy(info + pos, "tls13 ", 6);
    pos += 6;
    memcpy(info + pos, label, strlen(label));
    pos += strlen(label);

    info[pos++] = (uint8_t)ctxlen;
    if (ctxlen) {
        memcpy(info + pos, context, ctxlen);
        pos += ctxlen;
    }

    hkdf_expand(out, L, secret, info, pos);
}

void derive_secret(uint8_t out[HASH_LEN], const uint8_t secret[HASH_LEN],
                   const char *label, const uint8_t transcript_hash[HASH_LEN]) {
    hkdf_expand_label(out, HASH_LEN, secret, label, transcript_hash, HASH_LEN);
}
