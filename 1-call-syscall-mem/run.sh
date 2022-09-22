#! /bin/bash

echo -e "$(tput setaf 1)测试用户程序$(tput setaf 7)"
LD_PRELOAD=./build/libs/syscall-stats/libsyscall-stats.so ./build/app/app
