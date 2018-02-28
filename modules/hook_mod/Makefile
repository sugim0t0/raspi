KSRC = ../../linux
ARCH = arm
CROSS_COMPILE = arm-linux-gnueabihf-
EXTRA_CFLAGS += -DCONFIG_LITTLE_ENDIAN
KVER = 4.9.80

# Module name
obj-m := hookmod.o

# List objects in <Module name>-objs
hookmod-objs := hook_mod.o

all:
	make -C $(KSRC) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
clean:
	make -C $(KSRC) M=$(PWD) clean

