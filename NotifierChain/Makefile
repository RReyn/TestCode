obj-m := buildchain.o regchain.o notify.o

M := $(shell pwd)
KERNELDIR := /usr/src/kernels/$(shell uname -r)/

all:
	make -C $(KERNELDIR) M=$(shell pwd) modules

clean:
	make -C $(KERNELDIR) M=$(shell pwd) clean
