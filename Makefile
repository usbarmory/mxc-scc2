KERNEL_SRC = /lib/modules/$(shell uname -r)/build

obj-m += scc2.o scc2_aes.o
scc2-y := scc2_driver.o
scc2_aes-y := scc2_aes_dev.o

ccflags-y := -march=armv7-a

all:
	make -C ${KERNEL_SRC} M=$(CURDIR) modules

modules_install:
	make -C ${KERNEL_SRC} M=$(CURDIR) modules_install

clean:
	make -C ${KERNEL_SRC} M=$(CURDIR) clean
