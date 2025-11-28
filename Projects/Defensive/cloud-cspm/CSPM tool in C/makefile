# CSPM Tool Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LIBS = -lcurl -ljansson
TARGET = cspm_tool
SOURCES = main.c cspm.c

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET) security_report.json

install-deps:
	sudo apt-get install libcurl4-openssl-dev libjansson-dev

.PHONY: clean install-deps
