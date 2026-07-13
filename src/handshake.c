#include "handshake.h"
#include "alert.h"
#include "hello.h"
#include "hkdf.h"
#include "int.h"
#include "net.h"
#include "reader.h"
#include "record.h"
#include "util.h"
#include "verify.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read the next handshake message, transparently decrypting application_data
 * records with rd (NULL before handshake keys exist). Ignores ChangeCipherSpec,
 * aborts on alerts. Returns 0 with type + full message (header included) in msg,
 * or -1 on error/close. */
static int next_handshake(tls_conn_t *c, hs_buf_t *hb, aead_ctx_t *rd,
                          uint8_t *type, buf_t *msg) {
    for (;;) {
        const uint8_t *body;
        size_t len;
        if (hsbuf_next(hb, type, &body, &len)) {
            buf_reset(msg);
            buf_append(msg, body - 4, len + 4); /* include 4-byte header */
            return 0;
        }

        record_t rec;
        if (record_read(c->fd, &rec) != 0)
            return -1;

        if (rec.type == TLS_CT_CHANGE_CIPHER_SPEC) {
            record_free(&rec); /* middlebox-compat CCS: ignore (RFC 8446 D.4) */
            continue;
        }
        if (rec.type == TLS_CT_ALERT) {
            alert_print(rec.body, rec.len);
            record_free(&rec);
            return -1;
        }
        if (rec.type == TLS_CT_HANDSHAKE) {
            hsbuf_push(hb, rec.body, rec.len);
            record_free(&rec);
            continue;
        }
        if (rec.type == TLS_CT_APPLICATION_DATA) {
            if (!rd) {
                warn("encrypted record before handshake keys established");
                record_free(&rec);
                return -1;
            }
            uint8_t *plain = malloc(rec.len ? rec.len : 1);
            size_t plen;
            uint8_t inner;
            if (aead_open(rd, rec.hdr, rec.body, rec.len, plain, &plen,
                          &inner) != 0) {
                warn("AEAD decryption/authentication failed");
                free(plain);
                record_free(&rec);
                return -1;
            }
            if (inner == TLS_CT_HANDSHAKE) {
                hsbuf_push(hb, plain, plen);
            } else if (inner == TLS_CT_ALERT) {
                alert_print(plain, plen);
                free(plain);
                record_free(&rec);
                return -1;
            } else {
                warn("unexpected inner content type %u during handshake", inner);
            }
            free(plain);
            record_free(&rec);
            continue;
        }
        record_free(&rec);
    }
}

int certificate_list_parse(const uint8_t *body, size_t len,
                           const uint8_t **der_out, size_t *der_len_out,
                           int max_out) {
    rd_t r;
    rd_init(&r, body, len);
    uint8_t ctx_len = rd_u8(&r);
    rd_bytes(&r, ctx_len); /* certificate_request_context (empty for server) */
    uint32_t list_len = rd_u24(&r);
    const uint8_t *list = rd_bytes(&r, list_len);
    if (!rd_ok(&r))
        return -1;

    rd_t lr;
    rd_init(&lr, list, list_len);
    int n = 0;
    while (rd_remaining(&lr) > 0) {
        uint32_t clen = rd_u24(&lr);
        const uint8_t *cert = rd_bytes(&lr, clen);
        uint16_t ext_len = rd_u16(&lr);
        rd_bytes(&lr, ext_len); /* per-certificate extensions: ignored */
        if (!rd_ok(&lr))
            return -1;
        if (n < max_out) {
            der_out[n] = cert;
            der_len_out[n] = clen;
        }
        n++;
    }
    return n;
}

static void dump_certificate_list(const uint8_t *body, size_t len) {
    const uint8_t *der[16];
    size_t dlen[16];
    int n = certificate_list_parse(body, len, der, dlen, 16);
    if (n < 0) {
        warn("could not parse Certificate for dump");
        return;
    }
    for (int i = 0; i < n && i < 16; i++) {
        char path[32];
        snprintf(path, sizeof path, "cert_%d.der", i);
        FILE *f = fopen(path, "wb");
        if (f) {
            fwrite(der[i], 1, dlen[i], f);
            fclose(f);
            fprintf(stderr, "dumped %s (%zu bytes)\n", path, dlen[i]);
        }
    }
}

/* Verify the server Finished: HMAC(finished_key, Transcript-Hash(CH..CertVerify))
 * must equal the received verify_data. */
static int verify_server_finished(tls_conn_t *c, const uint8_t *verify_data,
                                  size_t vd_len) {
    uint8_t th[HASH_LEN];
    sha256(th, c->transcript.data, c->transcript.len); /* CH..CertificateVerify */
    return finished_verify(c->ks.server_hs_traffic, th, verify_data, vd_len);
}

/* Certificate verification gate (plan 05). Default is verify-active (SPEC N2);
 * --insecure disables it but prints a warning and must never be the default. */
static int verify_certificate_chain(tls_conn_t *c) {
    if (c->insecure) {
        warn("certificate verification DISABLED (--insecure) - server identity "
             "NOT checked; do not trust this connection");
        return 0;
    }
    if (!c->cafile) {
        warn("no --cafile trust anchors given; cannot verify the certificate "
             "chain");
        return -1;
    }
    return verify_server_certificate(c);
}

static int expect_message(tls_conn_t *c, hs_buf_t *hb, uint8_t want,
                          buf_t *msg) {
    uint8_t type;
    if (next_handshake(c, hb, &c->rd_hs, &type, msg) != 0)
        return -1;
    if (type != want) {
        warn("handshake out of order: expected type %u, got %u", want, type);
        return -1;
    }
    return 0;
}

int handshake_do_hello(tls_conn_t *c) {
    hello_gen_keys(c);

    buf_t ch;
    buf_init(&ch);
    hello_build_clienthello(c, &ch); /* also appends ClientHello to transcript */
    int wrote = record_write(c->fd, TLS_CT_HANDSHAKE, ch.data, ch.len);
    buf_free(&ch);
    if (wrote != 0) {
        warn("failed to send ClientHello");
        return -1;
    }

    hs_buf_t hb;
    hsbuf_init(&hb);
    buf_t msg;
    buf_init(&msg);
    uint8_t type;
    int rc = -1;

    if (next_handshake(c, &hb, NULL, &type, &msg) == 0 &&
        type == HS_SERVER_HELLO) {
        buf_append(&c->transcript, msg.data, msg.len);
        int p = hello_parse_serverhello(c, msg.data + 4, msg.len - 4);
        if (p == -2)
            warn("HelloRetryRequest is not supported");
        else if (p == 0)
            rc = 0;
    } else {
        warn("did not receive a valid ServerHello");
    }

    hsbuf_free(&hb);
    buf_free(&msg);
    return rc;
}

int handshake_run(tls_conn_t *c) {
    /* 1. X25519 shared secret. */
    uint8_t shared[32];
    if (crypto_scalarmult(shared, c->client_priv, c->server_pub) != 0) {
        warn("X25519 shared secret computation failed");
        return -1;
    }

    /* 2. Handshake secrets from Transcript-Hash(ClientHello || ServerHello). */
    uint8_t th_ch_sh[HASH_LEN];
    sha256(th_ch_sh, c->transcript.data, c->transcript.len);
    ks_derive_handshake(&c->ks, shared, th_ch_sh);
    sodium_memzero(shared, sizeof shared);
    aead_ctx_init(&c->rd_hs, c->ks.server_hs_traffic);
    aead_ctx_init(&c->wr_hs, c->ks.client_hs_traffic);

    hs_buf_t hb;
    hsbuf_init(&hb);
    buf_t msg;
    buf_init(&msg);
    int rc = -1;

    /* 3. EncryptedExtensions. */
    if (expect_message(c, &hb, HS_ENCRYPTED_EXTENSIONS, &msg) != 0)
        goto out;
    buf_append(&c->transcript, msg.data, msg.len);

    /* 4. Certificate. */
    if (expect_message(c, &hb, HS_CERTIFICATE, &msg) != 0)
        goto out;
    buf_reset(&c->cert_msg);
    buf_append(&c->cert_msg, msg.data + 4, msg.len - 4);
    if (c->dump_certs)
        dump_certificate_list(c->cert_msg.data, c->cert_msg.len);
    buf_append(&c->transcript, msg.data, msg.len);
    /* Snapshot Transcript-Hash(CH..Certificate) for CertificateVerify (plan 05). */
    sha256(c->th_cert, c->transcript.data, c->transcript.len);
    c->have_th_cert = 1;

    /* 5. CertificateVerify. */
    if (expect_message(c, &hb, HS_CERTIFICATE_VERIFY, &msg) != 0)
        goto out;
    buf_reset(&c->cert_verify);
    buf_append(&c->cert_verify, msg.data + 4, msg.len - 4);
    buf_append(&c->transcript, msg.data, msg.len);

    /* Certificate chain + CertificateVerify signature gate (plan 05). */
    if (verify_certificate_chain(c) != 0) {
        warn("certificate verification failed - aborting before application data");
        goto out;
    }

    /* 6. Server Finished (verified over CH..CertificateVerify). */
    if (expect_message(c, &hb, HS_FINISHED, &msg) != 0)
        goto out;
    if (verify_server_finished(c, msg.data + 4, msg.len - 4) != 0) {
        warn("server Finished verify_data mismatch");
        goto out;
    }
    buf_append(&c->transcript, msg.data, msg.len);

    /* 7. Application traffic secrets from Transcript-Hash(CH..server Finished). */
    uint8_t th_ch_sf[HASH_LEN];
    sha256(th_ch_sf, c->transcript.data, c->transcript.len);
    ks_derive_master(&c->ks, th_ch_sf);

    /* 8. Client Finished over CH..server Finished, sent under handshake keys. */
    uint8_t fk[HASH_LEN], vd[HASH_LEN];
    ks_finished_key(c->ks.client_hs_traffic, fk);
    hmac_sha256(vd, fk, HASH_LEN, th_ch_sf, HASH_LEN);

    buf_t fin;
    buf_init(&fin);
    buf_u8(&fin, HS_FINISHED);
    buf_u24(&fin, HASH_LEN);
    buf_append(&fin, vd, HASH_LEN);

    buf_t rec;
    buf_init(&rec);
    if (aead_seal(&c->wr_hs, TLS_CT_HANDSHAKE, fin.data, fin.len, &rec) != 0) {
        warn("failed to encrypt client Finished");
        buf_free(&fin);
        buf_free(&rec);
        goto out;
    }
    if (write_full(c->fd, rec.data, rec.len) != 0) {
        warn("failed to send client Finished");
        buf_free(&fin);
        buf_free(&rec);
        goto out;
    }
    buf_append(&c->transcript, fin.data, fin.len);
    buf_free(&fin);
    buf_free(&rec);

    /* 9. Application record protection. */
    aead_ctx_init(&c->rd_app, c->ks.server_ap_traffic);
    aead_ctx_init(&c->wr_app, c->ks.client_ap_traffic);
    c->handshake_done = 1;
    rc = 0;

out:
    hsbuf_free(&hb);
    buf_free(&msg);
    return rc;
}

void handshake_drain_tickets(tls_conn_t *c) {
    net_set_recv_timeout(c->fd, 2);
    int tickets = 0;
    for (;;) {
        record_t rec;
        if (record_read(c->fd, &rec) != 0)
            break; /* timeout or close: done */
        if (rec.type == TLS_CT_CHANGE_CIPHER_SPEC) {
            record_free(&rec);
            continue;
        }
        if (rec.type == TLS_CT_APPLICATION_DATA) {
            uint8_t *plain = malloc(rec.len ? rec.len : 1);
            size_t plen;
            uint8_t inner;
            if (aead_open(&c->rd_app, rec.hdr, rec.body, rec.len, plain, &plen,
                          &inner) == 0 &&
                inner == TLS_CT_HANDSHAKE) {
                hsbuf_push(&c->app_hsbuf, plain, plen);
                uint8_t t;
                const uint8_t *b;
                size_t l;
                while (hsbuf_next(&c->app_hsbuf, &t, &b, &l)) {
                    if (t == HS_NEW_SESSION_TICKET) {
                        tickets++;
                        fprintf(stderr,
                                "received NewSessionTicket (%zu bytes) - "
                                "parsed and ignored\n",
                                l);
                    }
                }
            }
            free(plain);
            record_free(&rec);
            if (tickets >= 2)
                break; /* google typically sends two */
            continue;
        }
        record_free(&rec);
        break;
    }
    net_set_recv_timeout(c->fd, 0);
}
