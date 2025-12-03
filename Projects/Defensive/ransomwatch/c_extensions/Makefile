# Makefile for entropy_fast C extension

CC = gcc
CFLAGS = -O3 -Wall -Wextra -fPIC $(shell python3-config --cflags)
LDFLAGS = -shared $(shell python3-config --ldflags)

TARGET = entropy_fast.so
SRC = entropy_fast.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC) -lm

test: $(TARGET)
	python3 -c "import entropy_fast; print(entropy_fast.calculate_file_entropy('test.txt'))"

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) ../core/

.PHONY: all test clean install
