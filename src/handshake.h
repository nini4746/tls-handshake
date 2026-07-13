/* TLS 1.3 client handshake state machine (RFC 8446 section 4).
 *
 * Precondition: ClientHello sent and ServerHello parsed (plan 02), so the
 * connection already holds client keys, server_pub, and a transcript of
 * ClientHello||ServerHello. This drives the rest: derive handshake keys, read
 * the encrypted server flight (EncryptedExtensions, Certificate,
 * CertificateVerify, Finished) enforcing message order, verify the server
 * Finished, send the client Finished, and derive application traffic keys. */
#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include "tls.h"

/* Generate client keys, send ClientHello, receive and parse ServerHello.
 * Appends both hellos to the transcript. Returns 0 on success, -1 on failure. */
int handshake_do_hello(tls_conn_t *c);

/* Run the handshake to completion (after handshake_do_hello). Returns 0 on
 * success, -1 on any failure (order violation, Finished mismatch, alert,
 * transport error). */
int handshake_run(tls_conn_t *c);

/* After the handshake, drain and discard any NewSessionTicket messages the
 * server sends (session resumption is out of scope). Bounded by a short recv
 * timeout so it cannot block. */
void handshake_drain_tickets(tls_conn_t *c);

/* Parse a Certificate handshake body into up to max_out DER certificate slices
 * (pointers into body). Returns the count, or -1 on malformed input. */
int certificate_list_parse(const uint8_t *body, size_t len,
                           const uint8_t **der_out, size_t *der_len_out,
                           int max_out);

#endif /* TLS_HANDSHAKE_H */
