#include <stdio.h>
#include <stdlib.h>
/**
 *  * Note: The returned array must be malloced, assume caller calls free().
 *   */
int*
twoSum(int* nums, int numsSize, int target) {
	for (int i = 0; i < numsSize; i++) {
		for (int j = i + 1; j < numsSize; j++) {
			if (nums[i] + nums[j] == target) {
				int *array = (int *)malloc(2 * sizeof(int));
				if (array) {
					array[0] = i;
					array[1] = j;
					return array;
				} else {
					return NULL;
				}
			}
		}
	}
	return NULL;
}

int
main(int argc, char *argv[])
{
	int nums[] = {2, 7, 11, 15};
	int *result;

	result = twoSum(nums, 4, 9);
	if (result == NULL)
		return 1;
	printf("result1: [%d,%d]\n", result[0], result[1]);
	free(result);
	
	result = twoSum(nums, 4, 13);
	if (result == NULL)
		return 1;
	printf("result2: [%d,%d]\n", result[0], result[1]);
	free(result);
	result = twoSum(nums, 4, 18);
	if (result == NULL)
		return 1;
	printf("result3: [%d,%d]\n", result[0], result[1]);
	free(result);
	result = twoSum(nums, 4, 22);
	if (result == NULL)
		return 1;
	printf("result4: [%d,%d]\n", result[0], result[1]);
	free(result);

	return 0;
}
