#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <assert.h>

#include "linux_kfifo.h"
#include "rte_spinlock.h"

typedef struct {
	uint64_t stu_id;
	uint32_t age;
	uint32_t score;
} stu_info_t;

#define KFIFO_SIZE (1024 * 1024)

static struct kfifo test;

rte_spinlock_t lock;

//unsigned int proc_count = 0;

void
print_student_info(stu_info_t *stu)
{
	assert(stu);
	printf("id: %lu\n", stu->stu_id);
	printf("age: %u\n", stu->age);
	printf("score: %u\n", stu->score);
}

stu_info_t *
get_student_info(time_t timer)
{
	stu_info_t *stu = (stu_info_t *)malloc(sizeof(stu_info_t));
	if (stu == NULL) {
		fprintf(stderr, "Failed to malloc memory.\n");
		return NULL;
	}

	srand(timer);
	stu->stu_id = 10000 + rand() % 9999;
	stu->age = rand() % 30;
	stu->score = rand() % 101;
	print_student_info(stu);
	return stu;
}

void *
producer_proc(void *arg)
{

	time_t cur_time;
	int seed = 0;
//	unsigned int count = 0;
	int sleep_time = 0;
	
	while(1) {
		time(&cur_time);
		
		seed = rand() % 11111;

		printf("***************************************\n");
		stu_info_t *stu_info = get_student_info(cur_time + seed);
		printf("put a student info to ring buffer.\n");
		rte_spinlock_lock(&lock);
		kfifo_in(&test, stu_info, sizeof(stu_info_t));
		printf("ring buffer length: %u\n", kfifo_len(&test));
		rte_spinlock_unlock(&lock);
		printf("***************************************\n");
		sleep_time = rand() % 5;
		sleep(sleep_time);
	}

	return (void *)0;
}

void *
consumer_proc(void *arg)
{
	stu_info_t stu_info;	

	while (1) {
		sleep(1);
		printf("====================================\n");	
		printf("get a student info from ring buffer.\n");
		rte_spinlock_lock(&lock);
		if (kfifo_len(&test) == 0) {
			rte_spinlock_unlock(&lock);
			printf("The ring buffer is empty.\n");
			printf("====================================\n");	
			continue;
		}
		kfifo_out(&test, &stu_info, sizeof(stu_info_t));
		printf("ring buffer length: %u\n", kfifo_len(&test));
		rte_spinlock_unlock(&lock);
		print_student_info(&stu_info);
		printf("====================================\n");	
	}
	return (void *)0;
}


pthread_t
produce_thread(void)
{
	int err = 0;
	pthread_t tid;

	err = pthread_create(&tid, NULL, producer_proc, NULL);
	if (err != 0) {
		printf("Failed to create producer thread.\n");
		return -1;
	}
	
	return tid;
}

pthread_t
consume_thread(void)
{
	int err = 0;
	pthread_t tid;

	err = pthread_create(&tid, NULL, consumer_proc, NULL);
	if (err != 0) {
		printf("Failed to create consumer thread.\n");
		return -1;
	}
	return tid;
}


int
main(int argc, char *argv[])
{
	pthread_t consume_tid, produce_tid;
	int ret = 0;
#if 0
	if (argc == 2) {
		proc_count = atoi(argv[1]);
	}
#endif
	ret = kfifo_alloc(&test, KFIFO_SIZE);
	if (ret) {
		printf("Error kfifo_alloc.\n");
		return ret;
	}
	rte_spinlock_init(&lock);

	printf("Multi thread test....\n");
	produce_tid = produce_thread();
	consume_tid = consume_thread();
	if (produce_tid != -1)
		pthread_join(produce_tid, NULL);
	if (consume_tid != -1)
		pthread_join(consume_tid, NULL);
	
	kfifo_free(&test);
	return 0;
}
