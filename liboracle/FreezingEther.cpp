#include "FreezingEther.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool freezingEther(CallLog callLog) {
    u256 numTransfer = 0;
    u256 initWei = 0;
    for (auto callLogItem : callLog) {
      auto type = callLogItem.type;
      auto wei = callLogItem.payload.wei;
      if (type == CONTRACT_WEI) {
        if (!initWei) {
          initWei = wei;
        } else if (initWei != wei) {
          numTransfer += 1;
        }
      }
    }
    return !numTransfer;
  }
}

