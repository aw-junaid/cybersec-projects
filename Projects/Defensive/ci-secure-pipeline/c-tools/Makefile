# Makefile for C verification tools
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -ljansson

# Default target
all: verifier

# Dependencies on Ubuntu/Debian:
# sudo apt-get install build-essential libjansson-dev

verifier: verifier.c
	$(CC) $(CFLAGS) -o verifier verifier.c $(LDFLAGS)

clean:
	rm -f verifier

install-deps-ubuntu:
	sudo apt-get update
	sudo apt-get install -y build-essential libjansson-dev

install-deps-alpine:
	apk add --no-cache build-base jansson-dev

test: verifier
	./verifier --help || true

.PHONY: all clean install-deps-ubuntu install-deps-alpine test
