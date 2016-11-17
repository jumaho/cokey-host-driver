# to be able to build this install:
# apt-get install linux-headers-amd64

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m  := cokey.o test-cokey.o

else
KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

endif
