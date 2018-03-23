#include <stdio.h>
#include <stdlib.h>

int
lengthOfLongestSubstring(char *s)
{
	int len = strlen(s);

	for (int i = len; i < len; i++) {
		
	}

}

int
main(int argc, char *argv[])
{
	char *str = "abcabcbb";
	int length = 0;

	length = lengthOfLongestSubstring(str);
	printf("%d\n", length);
	return 0;
}
