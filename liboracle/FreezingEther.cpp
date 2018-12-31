#include "FreezingEther.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool FreezingEther::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto inst = callLogItem.payload.inst;
      auto level = callLogItem.level;
      if (level > 0) {
        if (inst == Instruction::DELEGATECALL) numDelegatecall += 1;
        if (level == 1 && (inst == Instruction::CALL || inst == Instruction::SUICIDE)) {
          numTransfer ++;
        }
      }
      if (!numTransfer && !!numDelegatecall) {
        testData = callLogItem.payload.testData;
      }
    }
    return !numTransfer && !!numDelegatecall;
  }
}

