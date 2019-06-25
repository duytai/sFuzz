#include "FreezingEther.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool FreezingEther::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto inst = callLogItem.payload.inst;
      auto level = callLogItem.level;
      if (inst == Instruction::DELEGATECALL) numDelegatecall ++;
      if (level == 1 && (inst == Instruction::CALL || inst == Instruction::CALLCODE || inst == Instruction::SUICIDE)) {
        numTransfer ++;
      }
      /* Detect test case */
      if (!numTransfer && numDelegatecall) {
        testData = callLogItem.payload.testData;
        issuePayloadPc = callLogItem.payload.pc;
      }
    }
    return false;
  }
}

