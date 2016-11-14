obj-m = hello.o
hello-objs := helloworld.o

M := $(shell pwd)
KERNELDIR := /usr/src/kernels/$(shell uname -r)/

all:
	make -C $(KERNELDIR) M=$(M) modules
clean:
	make -C $(KERNELDIR) M=$(M) clean

