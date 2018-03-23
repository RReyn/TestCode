all: librlp.so test
test: rlp.c
	gcc rlp.c -DDEBUG -o test -g -Wall
librlp.so: rlp.o
#	gcc -c -o rlp.o -fPIC rlp.c
	gcc -shared -fPIC rlp.c -o librlp.so -g -Wall
clean:
	rm -rf *.o
	rm -rf librlp.so
	rm -rf test
