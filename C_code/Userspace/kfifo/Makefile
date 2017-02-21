all:
	gcc test_kfifo.c ./lib/linux_kfifo.c -o test_kfifo -I./lib/ -g -Wall -pthread
	gcc test_kfifo_all.c ./lib/linux_kfifo.c -o test_kfifo_all -I./lib/ -g -Wall 
clean:
	rm -rf ./test_kfifo_all ./test_kfifo
