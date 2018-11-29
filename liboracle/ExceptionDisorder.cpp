#include "ExceptionDisorder.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool exceptionDisorder(CallLog callLog) {
    bool hasRootException, hasNestedException;
    u256 numDisorder = 0;
    for (auto callLogItem : callLog) {
      auto type = callLogItem.type;
      auto level = callLogItem.level;
      if (type == CALL_OPCODE) {
        if (!level) {
          if (!hasRootException && hasNestedException) {
            numDisorder += 1;
          }
          hasRootException = false;
          hasNestedException = false;
        }
      }
      if (type == CALL_EXCEPTION) {
        if (!level) {
          hasRootException = true;
        } else {
          hasNestedException = true;
        }
      }
    }
    numDisorder += (!hasRootException && hasNestedException) ? 1 : 0;
    return !!numDisorder;
  }
}

