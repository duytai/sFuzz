#include <iostream>
#include <vector>

using namespace std;

int main(int argc, char* argv[]) {
  // Accept the first one as file name
  if (argc > 1) {
    string filename(argv[1]);
    
    return 0;
  }
  cout << "X Provide solidity contract file" << endl;
  return 0;
}
