CC = gcc
CFLAGS = -Wall -Wextra -g

bin: main.c alloc.c alloc.h
	$(CC) $(CFLAGS) -o bin main.c alloc.c
debug: main.c alloc.c alloc.h
	$(CC) $(CFLAGS) -o dbin main.c alloc.c -DDEBUG
