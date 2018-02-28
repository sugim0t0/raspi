
# 自作LKM(Loadable Kernel Module)開発

## Raspberry py 用LKMビルド手順
クロスコンパイル@Linux  
Raspberry piにはsshでアクセス

### 適当な作業ディレクトリ作成
    $ cd raspi/modules
    $ mkdir hello_mod
    $ cd hello_mod

### Moduleコード
    $ vim hello_mod.c
```c
#include <linux/module.h>

MODULE_DESCRIPTION("Output message when this module is loaded/unloaded.");
MODULE_AUTHOR("sugimoto");
MODULE_LICENSE("GPL");

/* Initialize routine called when module is loaded. */
static int hellomod_init_module(void)
{
    printk("hellomod is loaded.\n");
    printk("Hello world!\n");
    return 0;
}

/* Cleanup routine called when module is unloaded. */
static void hellomod_cleanup_module(void)
{
    printk("hellomod is unloaded.\n");
}

module_init(hellomod_init_module);
module_exit(hellomod_cleanup_module);
```

### Makefile
    $ vim Makefile
```Makefile
KSRC = ../../linux
ARCH = arm
CROSS_COMPILE = arm-linux-gnueabihf-
EXTRA_CFLAGS += -DCONFIG_LITTLE_ENDIAN
KVER = 4.9.80

# Module name
obj-m := hellomod.o

# List objects in <Module name>-objs
hellomod-objs := hello_mod.o

all:
	make -C $(KSRC) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
clean:
	make -C $(KSRC) M=$(PWD) clean
```

### ビルド

    $ make
hellomod.koができる。  

### クリーン
    $ make clean

### Raspberry piへのロード
    $ scp hellomod.ko pi@<IP address of raspberry pi>:/home/pi/
    $ ssh pi@<IP address of raspberry pi>
    $ sudo insmod hellomod.ko

### アンロード
    $ sudo rmmod hellomod.ko

### ロード/アンロード時のメッセージ確認
    $ dmesg

### モジュールのロード状況確認
    $ lsmod
