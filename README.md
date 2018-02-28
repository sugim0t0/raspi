# Raspberry pi 用 Kernel ビルド手順
クロスコンパイル@Linux  
[参考記事](https://qiita.com/hishi/items/c720ce8f8e550cb23e82)  

## Raspberry pi に特化した作業

### 適当な作業ディレクトリ作成
    $ mkdir raspi
    $ cd raspi
    $ mkdir apps
    $ mkdir modules
appsは今後開発するアプリケーション用ディレクトリ。  
modulesは今後開発するLKM用ディレクトリ。

### Kernel sourceとtoolchainの取得
    $ git clone --depth=1 git://github.com/raspberrypi/linux.git
    $ git clone --depth=1 git://github.com/raspberrypi/tools.git
    $ tree -L 1
    .
    |-- apps
    |-- linux
    |-- modules
    `-- tools

### 環境変数の設定
    $ vim setup.sh
```bash
#!/bin/bash

SCRIPT_DIR=$(cd $(dirname ${BASH_SOURCE:-$0}); pwd)

PATH="$PATH":$SCRIPT_DIR/tools/arm-bcm-2708/gcc-linaro-arm-linux-gnueabihf-raspbian
PATH="$PATH":$SCRIPT_DIR/tools/arm-bcm-2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin

export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
```
    $ source setup.sh

### SSHでRaspberry pi から.configの取得
    $ cd linux
    $ ssh pi@<IP address of raspberry pi> 'sudo modprobe configs'
    $ ssh pi@<IP address of raspberry pi> 'zcat /proc/config.gz' > config-pi
    $ mv config-pi .config

### 追加のコンフィグ設定(あれば)
    $ make menuconfig

## Linux Kernel ビルド共通作業

### Kernelに命名
Makefile内のEXTRAVERSIONを指定するとKernel名の後ろに名前が付けられる。

    $ vim Makefile
```Makefile
EXTRAVERSION = -sugi
```

### Kernel全ビルドせずに自分の変更したソースのみコンパイルが通るかどうかを確認する
最終的にKernelを生成する際は全ビルドが必要(あくまでも確認用)。  
例) kernel/sched/core.cのみを編集した場合  

    $ make kernel/sched/core.o

### Kernelのビルド
    $ make -j 4
-jの後の数字は並行処理させるジョブ数。  
ビルドするPCのCPUのコア数x2が目安。

### ModuleのビルドとModuleとKernelのまとめあげ
    $ export KERNEL_RELEASE=`cat include/config/kernel.release`
    $ export INSTALL_MOD_PATH=../$KERNEL_RELEASE
    $ mkdir -p $INSTALL_MOD_PATH
    $ mkdir -p ../$KERNEL_RELEASE/boot
    $ make modules
    $ make modules_install
    $ cp arch/arm/boot/Image ../$KERNEL_RELEASE/boot/kernel-$KERNEL_RELEASE.img

## Raspberry pi 上での動作確認
    $ cd ../$KERNEL_RELEASE
    $ tar zcvf $KERNEL_RELEASE.tar.gz boot lib
    $ scp $KERNEL_RELEASE.tar.gz pi@<IP address of raspberry pi>:/home/pi/
    $ ssh pi@<IP address of raspberry pi>
    $ sudo tar zxC / -f <kernel version>.tar.gz
    $ ls /boot
作成したkernel-<KERNEL_VERSION>.imgがあることを確認

    $ sudo vim /boot/config.txt
末尾に以下を追加

    kernel=kernel-<kernel version>.img
Raspberry piを再起動

    $ sudo reboot
再起動後、ログインしてunameで今回設定したKernel名が表示されるかを確認。

    $ uname -a
起動に失敗した場合はSDカードを取り出して、config.txtの末尾に追加したkernel指定を元に戻せば修正前の状態で起動できる。
