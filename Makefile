# TLS 1.3 handmade client - build.
# Crypto primitives from libsodium (X25519, SHA-256, HMAC, AES-GCM via OpenSSL)
# and OpenSSL libcrypto (AES-128-GCM AEAD, RSA-PSS/ECDSA raw verify). All
# protocol logic is hand-written (SPEC N4).

SODIUM  := $(shell brew --prefix libsodium)
OPENSSL := $(shell brew --prefix openssl@3)

CC      := cc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -g \
           -I src -I$(SODIUM)/include -I$(OPENSSL)/include
LDFLAGS := -L$(SODIUM)/lib -L$(OPENSSL)/lib
LDLIBS  := -lsodium -lcrypto

# Optional sanitizers: `make SAN=1` / `make SAN=1 test`.
ifdef SAN
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

SRC := $(filter-out src/main.c,$(wildcard src/*.c))
OBJ := $(SRC:.c=.o)

BIN := tls-client

TESTSRC  := $(wildcard tests/test_*.c)
TESTBINS := $(TESTSRC:.c=)

.PHONY: all test clean

all: $(BIN)

$(BIN): src/main.o $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Each test binary links against every non-main object.
tests/test_%: tests/test_%.c $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(OBJ) $(LDLIBS)

test: $(TESTBINS)
	@fail=0; \
	for t in $(TESTBINS); do \
		echo "== $$t =="; \
		./$$t || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "TESTS FAILED"; exit 1; fi; \
	echo "ALL TESTS PASSED"

clean:
	rm -f src/*.o $(BIN) $(TESTBINS)
