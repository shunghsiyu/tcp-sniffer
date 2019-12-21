CC = gcc

CFLAGS = -Wall
CFLAGS += -Wextra
CFLAGS += $(shell pkg-config --cflags check)

LDFLAGS = -lpcap

TEST_CFLAGS = $(CFLAGS)
TEST_LDFLAGS = $(LDFLAGS)
TEST_LDFLAGS += $(shell pkg-config --libs check)

all: test default

default:
	$(CC) main.c helper.o -o main $(CFLAGS) $(LDFLAGS)

test:
	$(CC) helper.c -c $(CFLAGS) $(LDFLAGS)
	$(CC) test_main.c fixture.c helper.o -o test_main $(TEST_CFLAGS) $(TEST_LDFLAGS)
	./test_main

clean:
	rm main test_main
