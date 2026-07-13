#include "keysched.h"
#include "int.h"

#include <string.h>

void ks_derive_handshake(key_schedule_t *ks, const uint8_t ecdhe[32],
                         const uint8_t transcript_hash_ch_sh[HASH_LEN]) {
    uint8_t zeros[HASH_LEN] = {0};
    uint8_t empty_hash[HASH_LEN];
    uint8_t derived[HASH_LEN];

    sha256(empty_hash, (const uint8_t *)"", 0);

    /* Early Secret = HKDF-Extract(salt=0, IKM=PSK=0). */
    hkdf_extract(ks->early_secret, NULL, 0, zeros, HASH_LEN);

    /* Handshake Secret = HKDF-Extract(salt=Derive-Secret(Early,"derived",""),
     *                                 IKM=ECDHE). */
    derive_secret(derived, ks->early_secret, "derived", empty_hash);
    hkdf_extract(ks->handshake_secret, derived, HASH_LEN, ecdhe, 32);

    derive_secret(ks->client_hs_traffic, ks->handshake_secret, "c hs traffic",
                  transcript_hash_ch_sh);
    derive_secret(ks->server_hs_traffic, ks->handshake_secret, "s hs traffic",
                  transcript_hash_ch_sh);
}

void ks_derive_master(key_schedule_t *ks,
                      const uint8_t transcript_hash_ch_sf[HASH_LEN]) {
    uint8_t zeros[HASH_LEN] = {0};
    uint8_t empty_hash[HASH_LEN];
    uint8_t derived[HASH_LEN];

    sha256(empty_hash, (const uint8_t *)"", 0);

    /* Master Secret = HKDF-Extract(salt=Derive-Secret(Handshake,"derived",""),
     *                              IKM=0). */
    derive_secret(derived, ks->handshake_secret, "derived", empty_hash);
    hkdf_extract(ks->master_secret, derived, HASH_LEN, zeros, HASH_LEN);

    derive_secret(ks->client_ap_traffic, ks->master_secret, "c ap traffic",
                  transcript_hash_ch_sf);
    derive_secret(ks->server_ap_traffic, ks->master_secret, "s ap traffic",
                  transcript_hash_ch_sf);
}

void ks_traffic_keys(const uint8_t secret[HASH_LEN], uint8_t key[AEAD_KEY_LEN],
                     uint8_t iv[AEAD_IV_LEN]) {
    hkdf_expand_label(key, AEAD_KEY_LEN, secret, "key", NULL, 0);
    hkdf_expand_label(iv, AEAD_IV_LEN, secret, "iv", NULL, 0);
}

void ks_finished_key(const uint8_t secret[HASH_LEN], uint8_t out[HASH_LEN]) {
    hkdf_expand_label(out, HASH_LEN, secret, "finished", NULL, 0);
}

void ks_nonce(const uint8_t iv[AEAD_IV_LEN], uint64_t seq,
              uint8_t nonce[AEAD_IV_LEN]) {
    memcpy(nonce, iv, AEAD_IV_LEN);
    /* XOR the 64-bit sequence number into the trailing 8 bytes (big-endian). */
    for (int i = 0; i < 8; i++)
        nonce[AEAD_IV_LEN - 1 - i] ^= (uint8_t)(seq >> (8 * i));
}
