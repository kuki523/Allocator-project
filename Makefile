CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g

.PHONY: all runme test clean

all: liballocator.so runme

allocator.o: allocator.c allocator.h
	$(CC) $(CFLAGS) -fPIC -c allocator.c

liballocator.so: allocator.o
	$(CC) -shared -o liballocator.so allocator.o

runme.o: runme.c allocator.h
	$(CC) $(CFLAGS) -c runme.c

runme: runme.o liballocator.so
	$(CC) $(CFLAGS) runme.o -L. -lallocator -o runme

test: runme
	./runme --seed 1 --storm 0 --size 8192

clean:
	rm -f *.o liballocator.so runme
