#include "GaslessSend.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool gaslessSend(CallLog callLog) {
    u256 sendGas = 2300;
    u256 numSend = 0;
    for (auto callLogItem : callLog) {
      if (callLogItem.type == CALL_OPCODE) {
        auto level = callLogItem.level;
        auto inst = callLogItem.payload.inst;
        auto gas = callLogItem.payload.gas;
        if (inst == Instruction::CALL && gas == sendGas && level == 1) {
          numSend += 1;
        };
      }
    }
    return !!numSend;
  }
}

