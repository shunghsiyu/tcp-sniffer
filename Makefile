CC = gcc

CFLAGS = -Wall
CFLAGS += -Wextra
CFLAGS += $(shell pkg-config --cflags check)

LDFLAGS = -lpcap

TEST_CFLAGS = $(CFLAGS)
TEST_LDFLAGS = $(LDFLAGS)
TEST_LDFLAGS += $(shell pkg-config --libs check)

.PHONY: all default test e2e clean

all: test default

default: main.out

test: test_main.out
	./test_main.out

e2e: default
	./e2e.sh

clean:
	rm helper.o main.out test_main.out

main.out: main.c helper.o
	$(CC) main.c helper.o -o main.out $(CFLAGS) $(LDFLAGS)

test_main.out: test_main.c helper.o
	$(CC) test_main.c helper.o -o test_main.out $(TEST_CFLAGS) $(TEST_LDFLAGS)

helper.o: helper.c
	$(CC) helper.c -c $(CFLAGS) $(LDFLAGS)
