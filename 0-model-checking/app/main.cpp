#include <boost/sml.hpp>
#include <iostream>

int main(int, char **) {
  std::cout << "1 + 2 = " << lib1::sum(1, 2) << '\n';
  return 0;
}
