/* PEM CERTIFICATE block parsing + hand-written base64 decode (SPEC C4), and a
 * trust-anchor store loaded from a CA bundle file (e.g. curl cacert.pem). */
#ifndef TLS_PEM_H
#define TLS_PEM_H

#include <stdint.h>
#include <stddef.h>

#include "x509.h"

typedef struct {
    uint8_t *der;   /* owned DER bytes of one certificate */
    size_t der_len;
    x509_cert_t cert;
} ca_entry_t;

typedef struct {
    ca_entry_t *entries;
    int count;
    int cap;
} ca_store_t;

/* Load all CERTIFICATE PEM blocks from path into store. Returns 0 on success. */
int pem_load_ca(const char *path, ca_store_t *store);
void ca_store_free(ca_store_t *store);

/* Decode base64 (ignoring whitespace) into out. Returns bytes written or
 * (size_t)-1 on error. */
size_t base64_decode(uint8_t *out, size_t out_cap, const char *in, size_t inlen);

#endif /* TLS_PEM_H */
