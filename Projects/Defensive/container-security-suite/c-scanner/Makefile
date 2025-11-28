CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_POSIX_C_SOURCE=200809L
LIBS = -lcurl -ljansson -lcrypto

SOURCES = main.c registry.c vulnerability.c signature.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = container-scanner

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install-deps:
	sudo apt-get update
	sudo apt-get install -y libcurl4-openssl-dev libjansson-dev

test: $(TARGET)
	./$(TARGET) --image alpine:latest --test

.PHONY: clean install-deps test
