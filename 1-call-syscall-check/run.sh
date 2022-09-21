#! /bin/bash

echo -e "$(tput setaf 1)测试用户程序$(tput setaf 0)"
LD_PRELOAD=./build/libs/syscall-stats/libsyscall-stats.so  ./build/app/app

echo -e "$(tput setaf 1)测试ls$(tput setaf 0)"
LD_PRELOAD=./build/libs/syscall-stats/libsyscall-stats.so  ls

echo -e "$(tput setaf 1)测试nc$(tput setaf 0)"
LD_PRELOAD=./build/libs/syscall-stats/libsyscall-stats.so  nc -w 1 127.0.0.1 22
