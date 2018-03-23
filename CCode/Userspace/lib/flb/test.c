#include <stdlib.h>
#include <stdio.h>

#include "flb.h"

int
main(int argc, char *argv[])
{
	unsigned int test1=0x1001;
	unsigned int test2=0x3ff;
	unsigned long test3=0x1001;
	unsigned long test4=0x3ff;

	printf("test1 last bit: %lu\n", find_last_bit((unsigned long *)&test1, BITS_PER_LONG));
	printf("test2 last bit: %lu\n", find_last_bit((unsigned long *)&test2, BITS_PER_LONG));
	printf("test3 last bit: %lu\n", find_last_bit((unsigned long *)&test3, BITS_PER_LONG));
	printf("test4 last bit: %lu\n", find_last_bit((unsigned long *)&test4, BITS_PER_LONG));
	return 0;
}
