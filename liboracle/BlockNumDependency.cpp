
#include "BlockNumDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool blockNumDependency(CallLog callLog) {
    u256 numBlockNumber = 0;
    u256 numCallWithWei = 0;
    u256 numBlockNumberDependency = 0;
    for (auto callLogItem : callLog) {
      auto type = callLogItem.type;
      auto level = callLogItem.level;
      if (type == CALL_OPCODE && !level) {
        if (numBlockNumber && numCallWithWei) {
          numBlockNumberDependency += 1;
        }
        numBlockNumber = 0;
        numCallWithWei = 0;
      } else {
        if (type == NUMBER_OPCODE) numBlockNumber ++;
        if (type == CALL_OPCODE) {
          auto payload = callLogItem.payload;
          if (payload.wei) {
            numCallWithWei ++;
          }
        }
      }
    }
    numBlockNumberDependency += (numBlockNumber && numCallWithWei) ? 1 : 0;
    return !!numBlockNumberDependency;
  }
}

