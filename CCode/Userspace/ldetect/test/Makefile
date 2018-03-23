all:test

test:test.c
	gcc -I../ -I../include -I../include/lib  test.c -o test -g -Wall -ldetect -lm
clean:
	rm -rf test *.o
