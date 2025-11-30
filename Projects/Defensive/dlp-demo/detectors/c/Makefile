# DLP PCAP Parser - Lab Use Only
# WARNING: Never use against production data

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LIBS = -lpcap -ljansson

# Safety notice
SAFETY_NOTICE = "WARNING: This tool is for lab demonstration only. Never use on production networks or real user data."

TARGET = pcap_parser
SOURCES = pcap_parser.c

.PHONY: all clean safety-warning

all: safety-warning $(TARGET)

$(TARGET): $(SOURCES)
	@echo "Building $(TARGET) - $(SAFETY_NOTICE)"
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

safety-warning:
	@echo "=================================================="
	@echo "DLP PCAP Parser - LAB USE ONLY"
	@echo "=================================================="
	@echo $(SAFETY_NOTICE)
	@echo "=================================================="

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Not installing - lab tool only"

test: $(TARGET)
	@echo "Running basic test..."
	@./$(TARGET) samples/exfil_examples/exfil_http.pcap > /dev/null && echo "Test passed" || echo "Test failed"

.PHONY: all clean test safety-warning
