#include "TimestampDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool TimestampDependency::analyze(CallLog callLog) {
    auto ethTransfer = hasEthTransfer(callLog);
    // TODO: find storage changed
    auto storageChanged = false;
    auto blockNumber = false;
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.inst == Instruction::TIMESTAMP)
        blockNumber = true;
    }
    return blockNumber && (ethTransfer || storageChanged);
  }
}

