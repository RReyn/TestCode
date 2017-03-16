#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>

void *
test1_func(void *arg)
{
	int cpus, i;
	cpu_set_t mask;
	cpu_set_t get;
	
	cpus = sysconf(_SC_NPROCESSORS_CONF);
	printf("This system has %d process.\n", cpus);

	CPU_ZERO(&mask);
	
	/* set this thread to number 1 cpu */
	if (cpus > 1) {
		CPU_SET(1, &mask);
		if (pthread_setaffinity_np(pthread_self(),
				sizeof(mask), &mask) < 0) {
			printf("set thread affinity failed.\n");
			return (void *)-1;
		}

		CPU_ZERO(&get);
		if (pthread_getaffinity_np(pthread_self(),
				sizeof(get), &get) < 0) {
			printf("get thread affinity failed.\n");
			return (void *)-1;
		}
		for (i = 0; i < cpus; i++) {
			if (CPU_ISSET(i, &get))
				printf("Test-1 thread %d is running "
						"in processor %d\n",
					 (int)pthread_self(), i);
		}
	}
	while (1) {
		;
	}
	return (void *)0;
}

void *
test2_func(void *arg)
{
	int cpus;
	int i = 0;
	cpu_set_t mask;
	cpu_set_t get;
	
	cpus = sysconf(_SC_NPROCESSORS_CONF);
	printf("This system has %d process.\n", cpus);

	CPU_ZERO(&mask);
	
	/* set this thread to number 2 cpu */
	if (cpus > 2) {
		CPU_SET(2, &mask);
		if (pthread_setaffinity_np(pthread_self(),
				sizeof(mask), &mask) < 0) {
			printf("set thread affinity failed.\n");
			return (void *)-1;
		}

		CPU_ZERO(&get);
		if (pthread_getaffinity_np(pthread_self(),
				sizeof(get), &get) < 0) {
			printf("get thread affinity failed.\n");
			return (void *)-1;
		}
		for (i = 0; i < cpus; i++) {
			if (CPU_ISSET(i, &get))
				printf("Test-2 thread %d is running "
						"in processor %d\n",
					 (int)pthread_self(), i);
		}
	
	}
	while (1) {
		;
	}
	return (void *)0;

}

int
main(int argc, char *argv[])
{
	pthread_t test1, test2;	
	int ret = 0;
	
	ret = pthread_create(&test1, NULL, test1_func, NULL);
	if (ret) {
		printf("create test1 thread failed\n");
		return -1;
	}
	ret = pthread_create(&test2, NULL, test2_func, NULL);
	if (ret) {
		printf("Ceate test2 thread failed.\n");
		return -1;
	}
	pthread_join(test1, NULL);	
	pthread_join(test2, NULL);
	return 0;
}
