all: libflb.a test

CC=gcc
CFLAGS=-g -Wall
#LIBFLAGS=-fPIC -shared

LIB=-L. -lflb

#libflb.so:flb.c
#	$(CC) $(LIBFLAGS) flb.c -o libflb.so $(CFLAGS)
libflb.a: flb.o
	ar -cr libflb.a flb.o
flb.o: flb.c
	$(CC) -c flb.c
test: test.c 
	$(CC) $(CFLAGS) -L. test.c -o test -lflb
#	$(CC) $(CFLAGS)  test.c flb.c -o test 
clean:
	rm -rf *.o *.so test *.a
