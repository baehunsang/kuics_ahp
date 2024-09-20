obj-m := holstein.o
KBUILD_DIR := ../../linux/
CFLAGS_holstein.o := -O0 -fno-stack-protector

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
