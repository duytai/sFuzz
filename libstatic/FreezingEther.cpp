#include "FreezingEther.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  u256 freezingEther(bytes opcodes) {
    bool hasCall = count_if(opcodes.begin(), opcodes.end(), [](byte i) {
      return i == (byte)Instruction::CALL;
    });
    bool hasCallcode = count_if(opcodes.begin(), opcodes.end(), [](byte i) {
      return i == (byte)Instruction::CALLCODE;
    });
    return !hasCall && !hasCallcode;
  }
}

