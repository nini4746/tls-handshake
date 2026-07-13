/* Record payload protection: AES-128-GCM (RFC 8446 sections 5.2 / 5.3).
 *
 * The AEAD primitive is OpenSSL libcrypto's EVP_aes_128_gcm (SPEC C3/N3:
 * primitive only). All TLS framing - AAD = the 5-byte record header carrying
 * the *ciphertext* length, per-record nonce = iv XOR seq, and the
 * TLSInnerPlaintext content-type/zero-padding handling - is hand-written. */
#ifndef TLS_AEAD_H
#define TLS_AEAD_H

#include <stdint.h>
#include <stddef.h>

#include "buf.h"
#include "keysched.h"

typedef struct {
    uint8_t key[AEAD_KEY_LEN];
    uint8_t iv[AEAD_IV_LEN];
    uint64_t seq; /* per-direction record sequence number */
} aead_ctx_t;

/* Initialise from a traffic secret (derives key + iv, resets seq to 0). */
void aead_ctx_init(aead_ctx_t *c, const uint8_t secret[HASH_LEN]);

/* Decrypt one application_data record body (ciphertext || 16-byte tag).
 * hdr5 is the 5-byte record header actually received (used as AAD).
 * On success writes the inner plaintext to out (caller provides >= ctlen bytes),
 * sets *outlen to the plaintext length after stripping the content-type byte
 * and zero padding, and *inner_type to the recovered content type.
 * Advances seq. Returns 0 on success, -1 on auth failure / malformed input. */
int aead_open(aead_ctx_t *c, const uint8_t hdr5[5], const uint8_t *body,
              size_t bodylen, uint8_t *out, size_t *outlen, uint8_t *inner_type);

/* Encrypt plaintext as an application_data record with the given inner content
 * type. Appends the full record (header + ciphertext + tag) to rec_out.
 * Advances seq. Returns 0 on success, -1 on error. */
int aead_seal(aead_ctx_t *c, uint8_t inner_type, const uint8_t *plaintext,
              size_t ptlen, buf_t *rec_out);

#endif /* TLS_AEAD_H */
