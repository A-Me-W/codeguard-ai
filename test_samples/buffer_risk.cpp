#include <cstring>
#include <iostream>

void copy_input(const char *user_input) {
  char buffer[16];
  // Vulnerability: Unbounded strcpy causes buffer overflow
  strcpy(buffer, user_input);
  std::cout << "Buffer content: " << buffer << std::endl;
}