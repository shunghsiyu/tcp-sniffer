CC = gcc

CFLAGS = -Wall
CFLAGS += -Wextra
CFLAGS += $(shell pkg-config --cflags check)

LDFLAGS = -lpcap
LDFLAGS += $(shell pkg-config --libs check)


all:
	$(CC) main.c -o main $(CFLAGS) $(LDFLAGS)
	$(CC) test_main.c -o test_main $(CFLAGS) $(LDFLAGS)
