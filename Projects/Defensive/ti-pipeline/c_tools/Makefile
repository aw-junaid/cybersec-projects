# Makefile for Threat Intelligence Pipeline C Tools

CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS_PCAP = -lpcap -ljansson -lssl -lcrypto
LIBS_CERT = -lssl -lcrypto -ljansson

# Targets
all: pcap_parser cert_parser

pcap_parser: pcap_parser.c
	$(CC) $(CFLAGS) -o pcap_parser pcap_parser.c $(LIBS_PCAP)

cert_parser: cert_parser.c
	$(CC) $(CFLAGS) -o cert_parser cert_parser.c $(LIBS_CERT)

# Test with sample data
test-pcap: pcap_parser
	@echo "Testing PCAP parser..."
	@if [ -f sample.pcap ]; then \
		./pcap_parser sample.pcap > pcap_output.json; \
		echo "Output saved to pcap_output.json"; \
	else \
		echo "Warning: sample.pcap not found, creating test file..."; \
		echo "Run with actual PCAP file for meaningful results"; \
		touch sample.pcap; \
		./pcap_parser sample.pcap > pcap_output.json; \
	fi

test-cert: cert_parser
	@echo "Testing certificate parser..."
	@if [ -f sample.pem ]; then \
		./cert_parser sample.pem > cert_output.json; \
		echo "Output saved to cert_output.json"; \
	else \
		echo "Warning: sample.pem not found, creating test file..."; \
		openssl req -x509 -newkey rsa:2048 -keyout key.pem -out sample.pem -days 365 -nodes -subj "/CN=example.com"; \
		./cert_parser sample.pem > cert_output.json; \
		echo "Output saved to cert_output.json"; \
	fi

clean:
	rm -f pcap_parser cert_parser *.json sample.pem key.pem

install-deps:
	@echo "Installing dependencies on Ubuntu/Debian:"
	sudo apt-get update
	sudo apt-get install libpcap-dev libjansson-dev libssl-dev

.PHONY: all test-pcap test-cert clean install-deps
