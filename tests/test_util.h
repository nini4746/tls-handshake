/* Tiny assert-based test harness shared by all unit tests. */
#ifndef TLS_TEST_UTIL_H
#define TLS_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        g_tests_run++;                                                         \
        if (!(cond)) {                                                         \
            g_tests_failed++;                                                  \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                      \
    } while (0)

#define CHECK_MEM(a, b, n)                                                     \
    do {                                                                       \
        g_tests_run++;                                                         \
        if (memcmp((a), (b), (n)) != 0) {                                      \
            g_tests_failed++;                                                  \
            fprintf(stderr, "  FAIL %s:%d: memcmp(%s, %s, %s)\n", __FILE__,    \
                    __LINE__, #a, #b, #n);                                     \
        }                                                                      \
    } while (0)

#define TEST_REPORT()                                                         \
    do {                                                                       \
        printf("  %d checks, %d failed\n", g_tests_run, g_tests_failed);       \
        return g_tests_failed == 0 ? 0 : 1;                                    \
    } while (0)

#endif /* TLS_TEST_UTIL_H */
