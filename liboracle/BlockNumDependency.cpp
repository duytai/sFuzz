#include "BlockNumDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool BlockNumberDependency::analyze(CallLog callLog) {
    auto ethTransfer = hasEthTransfer(callLog);
    // TODO: Find storage changed
    auto storageChanged = false;
    auto blockNumber = false;
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.inst == Instruction::NUMBER)
        blockNumber = true;
    }
    return blockNumber && (ethTransfer || storageChanged);
  }
}

