obj-m := rop_basic.o
KBUILD_DIR := ../../linux/
CFLAGS_rop_basic.o := -O0

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
