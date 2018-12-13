#include "BlockNumDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  u256 blockNumDependency(bytes opcodes) {
    bool hasBlocknumber = count_if(opcodes.begin(), opcodes.end(), [](byte i) {
      return i == 0x43;
    });
    bool hasCall = count_if(opcodes.begin(), opcodes.end(), [](byte i) {
      return i == 0xf1;
    });
    bool hasCallcode = count_if(opcodes.begin(), opcodes.end(), [](byte i) {
      return i == 0xf2;
    });
    return hasBlocknumber && (hasCallcode || hasCall);
  }
}


