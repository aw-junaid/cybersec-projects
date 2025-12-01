# Honeynet C Tools Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LIBS = -lpcap -ljansson -lssl -lcrypto

# Safety notice
SAFETY_NOTICE = "Honeynet Tools - FOR LAB USE ONLY"

.PHONY: all clean

all: pcap_extractor signature_checker

pcap_extractor: pcap_extractor.c
	@echo Building $(SAFETY_NOTICE)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

signature_checker: signature_checker.c
	@echo Building $(SAFETY_NOTICE)  
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f pcap_extractor signature_checker

install: all
	cp pcap_extractor signature_checker /usr/local/bin/

test: all
	@echo "Running basic tests..."
	./pcap_extractor --help || true
	./signature_checker --help || true

.PHONY: all clean install test
