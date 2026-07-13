/* Shared TLS 1.3 client connection state, grown plan by plan. */
#ifndef TLS_TLS_H
#define TLS_TLS_H

#include <stdint.h>
#include <stddef.h>

#include "buf.h"
#include "handshake_buf.h"
#include "keysched.h"
#include "aead.h"

/* Negotiated fixed parameters (single supported combination). */
#define TLS13_VERSION 0x0304
#define TLS_GROUP_X25519 0x001d
#define TLS_AES_128_GCM_SHA256 0x1301

/* Handshake message types (RFC 8446 section 4). */
#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_NEW_SESSION_TICKET 4
#define HS_ENCRYPTED_EXTENSIONS 8
#define HS_CERTIFICATE 11
#define HS_CERTIFICATE_VERIFY 15
#define HS_FINISHED 20

#define X25519_LEN 32
#define TLS_RANDOM_LEN 32

typedef struct {
    int fd;
    const char *host;   /* SNI / hostname to verify */

    /* X25519 ephemeral key pair and the peer's public key. */
    uint8_t client_priv[X25519_LEN];
    uint8_t client_pub[X25519_LEN];
    uint8_t server_pub[X25519_LEN];
    int have_server_pub;

    uint8_t session_id[32]; /* legacy_session_id (middlebox compat) */
    uint8_t session_id_len;

    uint8_t client_random[TLS_RANDOM_LEN];
    uint8_t server_random[TLS_RANDOM_LEN];

    uint16_t cipher_suite; /* negotiated; must be TLS_AES_128_GCM_SHA256 */

    /* Running transcript: every handshake message (with its 4-byte header, no
     * record header) in order. Plan 03 hashes prefixes of this. */
    buf_t transcript;

    /* Derived secrets and per-direction record protection contexts. */
    key_schedule_t ks;
    aead_ctx_t rd_hs, wr_hs;   /* handshake traffic (server read / client write) */
    aead_ctx_t rd_app, wr_app; /* application traffic */

    /* Certificate / CertificateVerify material captured for plan 05. */
    buf_t cert_msg;       /* Certificate handshake body (after 4-byte header) */
    buf_t cert_verify;    /* CertificateVerify handshake body */
    uint8_t th_cert[HASH_LEN]; /* Transcript-Hash(ClientHello..Certificate) */
    int have_th_cert;

    /* Reassembly buffer for handshake messages arriving after the handshake
     * completes (e.g. NewSessionTicket over application records). */
    hs_buf_t app_hsbuf;

    int handshake_done;
    int dump_certs;       /* write server DER certs to cert_N.der for debugging */

    const char *cafile;   /* trust anchor bundle (plan 05); NULL = not set */
    int insecure;         /* skip cert verification (plan 05); default off */
    const char *keylog;   /* SSLKEYLOGFILE path (plan 06); NULL = disabled */
} tls_conn_t;

void tls_conn_init(tls_conn_t *c, int fd, const char *host);
void tls_conn_free(tls_conn_t *c);

#endif /* TLS_TLS_H */
