/* HKDF (RFC 5869) and the TLS 1.3 HKDF-Expand-Label / Derive-Secret wrappers
 * (RFC 8446 section 7.1), hand-written on top of libsodium's HMAC-SHA256 and
 * SHA-256 primitives only (SPEC N4: no library TLS-specific KDF). */
#ifndef TLS_HKDF_H
#define TLS_HKDF_H

#include <stdint.h>
#include <stddef.h>

#define HASH_LEN 32 /* SHA-256 */

void sha256(uint8_t out[HASH_LEN], const uint8_t *data, size_t len);
void hmac_sha256(uint8_t out[HASH_LEN], const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen);

/* HKDF-Extract: PRK = HMAC(salt, IKM). salt==NULL/saltlen==0 uses HashLen zeros. */
void hkdf_extract(uint8_t prk[HASH_LEN], const uint8_t *salt, size_t saltlen,
                  const uint8_t *ikm, size_t ikmlen);

/* HKDF-Expand: expand PRK into L bytes of output using info. */
void hkdf_expand(uint8_t *okm, size_t L, const uint8_t prk[HASH_LEN],
                 const uint8_t *info, size_t infolen);

/* HKDF-Expand-Label(secret, label, context, L). The label is prefixed with
 * "tls13 " internally. context may be NULL when ctxlen==0. */
void hkdf_expand_label(uint8_t *out, size_t L, const uint8_t secret[HASH_LEN],
                       const char *label, const uint8_t *context,
                       size_t ctxlen);

/* Derive-Secret(secret, label, transcript_hash): Expand-Label with the
 * transcript hash as context and output length HASH_LEN. */
void derive_secret(uint8_t out[HASH_LEN], const uint8_t secret[HASH_LEN],
                   const char *label, const uint8_t transcript_hash[HASH_LEN]);

#endif /* TLS_HKDF_H */
