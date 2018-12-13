#include "StaticFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  void StaticFactory::analyze(bytes bin) {
    bool hasDelegate = count_if(bin.begin(), bin.end(), [](byte i) {
      return i == 0xf4;
    });
    int index = -1;
    index = toHex(bin).find("60003660405180838380828437", 0);
    cout << hasDelegate << endl;
    cout << index << endl;
  }
}
