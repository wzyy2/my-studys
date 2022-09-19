/*
 * Copyright 2022 Jacob Chen
 */
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include <stdio.h>
#include <unistd.h>

int main() {
  write(0, "Hello, Kernel!\n", 15);
  printf("Hello, World!\n");

  return 0;
}
