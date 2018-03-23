CONFIG_MODULE_SIG=n

ifneq ($(KERNELRELEASE),)
	obj-m := driver.o bus.o device.o
else
	KERNELDIR ?= /usr/src/kernels/$(shell uname -r)/
	PWD := $(shell pwd)

modules:
	make -C $(KERNELDIR) M=$(PWD) modules
clean:
	make -C $(KERNELDIR) M=$(PWD) clean 
endif
