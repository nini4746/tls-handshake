#include "pem.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t base64_decode(uint8_t *out, size_t out_cap, const char *in,
                     size_t inlen) {
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < inlen; i++) {
        char ch = in[i];
        if (ch == '=' || ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t')
            continue;
        int v = b64val((unsigned char)ch);
        if (v < 0)
            return (size_t)-1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_cap)
                return (size_t)-1;
            out[n++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    return n;
}

static void store_push(ca_store_t *s, uint8_t *der, size_t der_len) {
    if (s->count == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 32;
        s->entries = realloc(s->entries, (size_t)s->cap * sizeof *s->entries);
        if (!s->entries)
            die("pem: out of memory");
    }
    ca_entry_t *e = &s->entries[s->count];
    e->der = der;
    e->der_len = der_len;
    if (x509_parse(der, der_len, &e->cert) == 0)
        s->count++; /* keep only parseable CAs */
    else
        free(der);
}

int pem_load_ca(const char *path, ca_store_t *store) {
    store->entries = NULL;
    store->count = 0;
    store->cap = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        warn("cannot open CA file: %s", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) {
        fclose(f);
        return -1;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';

    const char *B = "-----BEGIN CERTIFICATE-----";
    const char *E = "-----END CERTIFICATE-----";
    const char *p = buf;
    while ((p = strstr(p, B)) != NULL) {
        p += strlen(B);
        const char *end = strstr(p, E);
        if (!end)
            break;
        size_t b64len = (size_t)(end - p);
        uint8_t *der = malloc(b64len); /* decoded is smaller than base64 */
        if (der) {
            size_t dlen = base64_decode(der, b64len, p, b64len);
            if (dlen != (size_t)-1 && dlen > 0)
                store_push(store, der, dlen);
            else
                free(der);
        }
        p = end + strlen(E);
    }
    free(buf);
    return store->count > 0 ? 0 : -1;
}

void ca_store_free(ca_store_t *store) {
    for (int i = 0; i < store->count; i++)
        free(store->entries[i].der);
    free(store->entries);
    store->entries = NULL;
    store->count = 0;
    store->cap = 0;
}
