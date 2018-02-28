#!/bin/bash

SCRIPT_DIR=$(cd $(dirname ${BASH_SOURCE:-$0}); pwd)

PATH="$PATH":$SCRIPT_DIR/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian
PATH="$PATH":$SCRIPT_DIR/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin

export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-

