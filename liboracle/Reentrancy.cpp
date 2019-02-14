#include "Reentrancy.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool Reentrancy::analyze(CallLog callLog) {
    auto ethTransfer = false;
    auto isReentrancy = false;
    for (auto callLogItem : callLog) {
      auto data = callLogItem.payload.data;
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      auto wei = callLogItem.payload.wei;
      if ((inst == Instruction::CALL
      || inst == Instruction::CALLCODE
      || inst == Instruction::DELEGATECALL
      || inst == Instruction::STATICCALL
      ) && level > 1 && wei > 0) {
        ethTransfer = true;
      }

      if (level >= 4 && toHex(data) == "000000ff") {
        isReentrancy = true;
      }
    }
    if (ethTransfer && isReentrancy) {
      testData = callLog[0].payload.testData;
      return true;
    }
    return false;
  }
}

