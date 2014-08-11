##!/bin/bash

export ARCH=arm
export CROSS_COMPILE=/opt/toolchains/arm-eabi-4.4.3/bin/arm-eabi-
export VARIANT_DEFCONFIG=t0ktt_04_defconfig

make t0_04_defconfig
make
