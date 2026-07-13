/* TLS 1.3 key schedule (RFC 8446 section 7.1) and per-record nonce (5.3).
 * Secrets flow: Early -> Handshake -> Master, with traffic secrets branched
 * off at each stage from the running transcript hash. */
#ifndef TLS_KEYSCHED_H
#define TLS_KEYSCHED_H

#include <stdint.h>
#include <stddef.h>

#include "hkdf.h"

#define AEAD_KEY_LEN 16 /* AES-128 */
#define AEAD_IV_LEN 12

typedef struct {
    uint8_t early_secret[HASH_LEN];
    uint8_t handshake_secret[HASH_LEN];
    uint8_t master_secret[HASH_LEN];
    uint8_t client_hs_traffic[HASH_LEN];
    uint8_t server_hs_traffic[HASH_LEN];
    uint8_t client_ap_traffic[HASH_LEN];
    uint8_t server_ap_traffic[HASH_LEN];
} key_schedule_t;

/* Derive Early + Handshake secrets and the handshake traffic secrets.
 * transcript_hash_ch_sh = SHA-256(ClientHello || ServerHello).
 * ecdhe = X25519 shared secret (32 bytes). */
void ks_derive_handshake(key_schedule_t *ks, const uint8_t ecdhe[32],
                         const uint8_t transcript_hash_ch_sh[HASH_LEN]);

/* Derive Master secret and application traffic secrets.
 * transcript_hash_ch_sf = SHA-256(ClientHello .. server Finished). */
void ks_derive_master(key_schedule_t *ks,
                      const uint8_t transcript_hash_ch_sf[HASH_LEN]);

/* Traffic key + IV from a traffic secret. */
void ks_traffic_keys(const uint8_t secret[HASH_LEN], uint8_t key[AEAD_KEY_LEN],
                     uint8_t iv[AEAD_IV_LEN]);

/* finished_key = HKDF-Expand-Label(secret, "finished", "", HASH_LEN). */
void ks_finished_key(const uint8_t secret[HASH_LEN], uint8_t out[HASH_LEN]);

/* Per-record nonce: iv XOR seq, seq as a big-endian 64-bit value right-aligned
 * in the 12-byte nonce (RFC 8446 section 5.3). */
void ks_nonce(const uint8_t iv[AEAD_IV_LEN], uint64_t seq,
              uint8_t nonce[AEAD_IV_LEN]);

/* Verify a Finished message (RFC 8446 4.4.4):
 * expected = HMAC(HKDF-Expand-Label(secret,"finished","",HashLen), transcript_hash).
 * Returns 0 if verify_data matches expected (constant-time), -1 otherwise. */
int finished_verify(const uint8_t secret[HASH_LEN],
                    const uint8_t transcript_hash[HASH_LEN],
                    const uint8_t *verify_data, size_t vd_len);

#endif /* TLS_KEYSCHED_H */
