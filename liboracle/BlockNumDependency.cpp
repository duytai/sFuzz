#include "BlockNumDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool BlockNumberDependency::analyze(CallLog callLog) {
    auto ethTransfer = hasEthTransfer(callLog);
    auto storageChanged = hasStorageChanged(callLog);
    auto blockNumber = false;
    u64 pc = 0;
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.inst == Instruction::NUMBER) {
        pc = callLogItem.payload.pc;
        blockNumber = true;
      }
    }
    if (blockNumber && (ethTransfer || storageChanged)) {
      testData = callLog[0].payload.testData;
      issuePayloadPc =  pc;
      return true;
    }
    return false;
  }
}

