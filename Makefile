CC = gcc

CFLAGS = -Wall
CFLAGS += -Wextra
CFLAGS += $(shell pkg-config --cflags check)

LDFLAGS = -lpcap
LDFLAGS += $(shell pkg-config --libs check)


all: test default

default:
	$(CC) main.c -o main $(CFLAGS) $(LDFLAGS)

test:
	$(CC) test_main.c -o test_main $(CFLAGS) $(LDFLAGS)
	- ./test_main

clean:
	rm main test_main
