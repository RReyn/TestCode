obj-m := hello.o

KERNDIR ?= /usr/src/kernels/$(shell uname -r)
M := $(shell pwd)

all:
	make -C $(KERNDIR) M=$(M) modules
clean:
	make -C $(KERNDIR) M=$(M) clean
