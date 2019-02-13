#include "BlockNumDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool BlockNumberDependency::analyze(CallLog callLog) {
    auto ethTransfer = hasEthTransfer(callLog);
    auto storageChanged = hasStorageChanged(callLog);
    auto blockNumber = false;
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.inst == Instruction::NUMBER)
        blockNumber = true;
    }
    if (blockNumber && (ethTransfer || storageChanged)) {
      testData = callLog[0].payload.testData;
      return true;
    }
    return false;
  }
}

