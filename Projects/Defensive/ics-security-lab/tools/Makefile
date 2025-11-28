# Modbus Parser Build
# SAFETY: This tool is for offline analysis only

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LIBS = -ljansson

TARGET = modbus_parser
SOURCES = modbus_parser.c

# Safety notice during build
.PHONY: safety
safety:
	@echo "=== SAFETY NOTICE ==="
	@echo "This tool is for OFFLINE analysis in lab environments only."
	@echo "Never deploy to production ICS/OT networks."
	@echo "====================="

$(TARGET): $(SOURCES) safety
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Tool installed. REMEMBER: For lab use only!"

test: $(TARGET)
	./$(TARGET) sample.pcap

.PHONY: clean install test safety
