ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m := udptun.o

else
# Run this Makefile as follows:
# make clean && make all && make test
#
KDIR= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) M=$(PWD) modules

test:
	scp ./hello.ko dev@test-instance:~/
	ssh test-instance sudo rmmod hello
	ssh test-instance sudo insmod ./hello.ko
	ssh test-instance cat /proc/hello/system

clean:
	rm -f *~
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) M=$(PWD) clean
endif
