/* TCP transport: connect, and read/write that loop over partial results.
 * TCP delivers a byte stream with no message boundaries, so a single read()
 * can return fewer bytes than asked; read_full loops until n bytes arrive. */
#ifndef TLS_NET_H
#define TLS_NET_H

#include <stdint.h>
#include <stddef.h>

/* Connect to host:port over TCP. Returns fd, or -1 on failure. */
int net_connect(const char *host, const char *port);

/* Read exactly n bytes into buf. Returns 0 on success, -1 on error/EOF. */
int read_full(int fd, uint8_t *buf, size_t n);

/* Write exactly n bytes from buf. Returns 0 on success, -1 on error. */
int write_full(int fd, const uint8_t *buf, size_t n);

/* Set a receive timeout in seconds (0 clears it). Used to bound the
 * post-handshake NewSessionTicket drain so reads don't block forever. */
void net_set_recv_timeout(int fd, int seconds);

void net_close(int fd);

#endif /* TLS_NET_H */
