#include "Reentrancy.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool reentrancy(CallLog callLog) {
    u256 numReentrancies = 0;
    unordered_map<string, u256> signatures;
    for (auto callLogItem : callLog) {
      auto level = callLogItem.level;
      auto data = callLogItem.payload.data;
      auto inst = callLogItem.payload.inst;
      if (data.size()
          && (inst == Instruction::CALL || inst == Instruction::CALLCODE)) {
        auto sig = bytes(data.begin(), data.begin() + 4);
        auto sigStr = toHex(sig);
        if (!level) {
          signatures[sigStr] = 1;
        } else if (signatures.count(sigStr)) {
          signatures[sigStr] ++;
        }
      }
    }
    for (auto it : signatures) {
      if (it.second > 1) numReentrancies ++;
    }
    return !!numReentrancies;
  }
}
