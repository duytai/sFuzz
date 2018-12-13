#include "DangerDelegateCall.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  u256 dangerDelegateCall(bytes opcodes, bytes bin) {
    string msgPattern = "60003660405180838380828437";
    bool hasDelegate = count_if(opcodes.begin(), opcodes.end(), [](byte i) {
      return i == (byte) Instruction::DELEGATECALL;
    });
    auto binStr = toHex(bin);
    int index = binStr.find(msgPattern, 0);
    return hasDelegate && (index >= 0 && index <= (int) binStr.size());
  }
}
