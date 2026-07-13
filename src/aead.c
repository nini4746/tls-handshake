#include "aead.h"
#include "int.h"
#include "record.h"

#include <openssl/evp.h>
#include <string.h>

#define GCM_TAG_LEN 16

void aead_ctx_init(aead_ctx_t *c, const uint8_t secret[HASH_LEN]) {
    ks_traffic_keys(secret, c->key, c->iv);
    c->seq = 0;
}

int aead_open(aead_ctx_t *c, const uint8_t hdr5[5], const uint8_t *body,
              size_t bodylen, uint8_t *out, size_t *outlen,
              uint8_t *inner_type) {
    if (bodylen < GCM_TAG_LEN)
        return -1;
    size_t ctlen = bodylen - GCM_TAG_LEN;
    const uint8_t *tag = body + ctlen;

    uint8_t nonce[AEAD_IV_LEN];
    ks_nonce(c->iv, c->seq, nonce);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int ok = 0;
    int len = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_IV_LEN,
                                NULL) != 1)
            break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, c->key, nonce) != 1)
            break;
        /* AAD = the record header, which encodes the ciphertext length. */
        if (EVP_DecryptUpdate(ctx, NULL, &len, hdr5, 5) != 1)
            break;
        if (ctlen > 0 &&
            EVP_DecryptUpdate(ctx, out, &len, body, (int)ctlen) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                                (void *)tag) != 1)
            break;
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, out + len, &final_len) != 1)
            break; /* authentication failed */
        ok = 1;
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
        return -1;

    c->seq++;

    /* TLSInnerPlaintext: strip trailing zero padding; the last non-zero byte is
     * the real content type. */
    size_t n = ctlen;
    while (n > 0 && out[n - 1] == 0)
        n--;
    if (n == 0)
        return -1; /* all zeros: no content type */
    *inner_type = out[n - 1];
    *outlen = n - 1;
    return 0;
}

int aead_seal(aead_ctx_t *c, uint8_t inner_type, const uint8_t *plaintext,
              size_t ptlen, buf_t *rec_out) {
    /* TLSInnerPlaintext = content || content_type || zeros. We add no padding. */
    size_t inner_len = ptlen + 1;
    size_t rec_body_len = inner_len + GCM_TAG_LEN;
    if (rec_body_len > TLS_RECORD_MAX_FRAGMENT)
        return -1;

    uint8_t hdr[5];
    put_u8(hdr, TLS_CT_APPLICATION_DATA);
    put_u16(hdr + 1, 0x0303);
    put_u16(hdr + 3, (uint16_t)rec_body_len);

    uint8_t nonce[AEAD_IV_LEN];
    ks_nonce(c->iv, c->seq, nonce);

    /* Build the inner plaintext contiguously. */
    buf_t inner;
    buf_init(&inner);
    buf_append(&inner, plaintext, ptlen);
    buf_u8(&inner, inner_type);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        buf_free(&inner);
        return -1;
    }

    uint8_t *ciphertext = malloc(inner.len);
    uint8_t tag[GCM_TAG_LEN];
    int ok = 0;
    int len = 0;
    if (ciphertext) {
        do {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
                break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_IV_LEN,
                                    NULL) != 1)
                break;
            if (EVP_EncryptInit_ex(ctx, NULL, NULL, c->key, nonce) != 1)
                break;
            if (EVP_EncryptUpdate(ctx, NULL, &len, hdr, 5) != 1)
                break;
            if (EVP_EncryptUpdate(ctx, ciphertext, &len, inner.data,
                                  (int)inner.len) != 1)
                break;
            int final_len = 0;
            if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1)
                break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                                    tag) != 1)
                break;
            ok = 1;
        } while (0);
    }
    EVP_CIPHER_CTX_free(ctx);

    if (ok) {
        buf_append(rec_out, hdr, 5);
        buf_append(rec_out, ciphertext, inner.len);
        buf_append(rec_out, tag, GCM_TAG_LEN);
        c->seq++;
    }
    free(ciphertext);
    buf_free(&inner);
    return ok ? 0 : -1;
}
