/* Handshake message reassembly buffer.
 *
 * Record fragments carrying handshake content are pushed in as they arrive.
 * A handshake message is msg_type(1) + length(3) + body[length], and its
 * boundary is independent of record boundaries: one message can span several
 * records (e.g. a large Certificate) and one record can carry several messages
 * (e.g. EncryptedExtensions + Certificate + ...). hsbuf_next yields exactly one
 * complete message at a time, or reports that more bytes are needed.
 *
 * Usage is drain-then-push: after pushing a fragment, call hsbuf_next in a loop
 * until it returns 0; the pointers it returns stay valid until the next push
 * (push compacts consumed bytes, which may move memory). */
#ifndef TLS_HANDSHAKE_BUF_H
#define TLS_HANDSHAKE_BUF_H

#include <stdint.h>
#include <stddef.h>

#include "buf.h"

typedef struct {
    buf_t acc;
    size_t consumed;
} hs_buf_t;

void hsbuf_init(hs_buf_t *h);
void hsbuf_free(hs_buf_t *h);

/* Append a handshake fragment (the plaintext body of a handshake record). */
void hsbuf_push(hs_buf_t *h, const uint8_t *data, size_t n);

/* Pop the next complete handshake message.
 * Returns 1 and sets type, body and len (body points into internal storage,
 * valid until the next hsbuf_push) if a full message is available.
 * Returns 0 if more bytes are needed.
 * The 4-byte handshake header (type + 3-byte length), starting at *body - 4,
 * is also contiguous in storage — used for transcript hashing later. */
int hsbuf_next(hs_buf_t *h, uint8_t *type, const uint8_t **body, size_t *len);

#endif /* TLS_HANDSHAKE_BUF_H */
