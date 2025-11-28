CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lcurl -ljansson -ljwt

SRC = src/c/microservice.c
TARGET = microservice

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: clean
