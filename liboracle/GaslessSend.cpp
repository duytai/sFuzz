#include "GaslessSend.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool gaslessSend(CallLog callLog) {
    u256 sendGas = 2300;
    for (auto call : callLog) {
      if (call.inst == Instruction::CALL && call.gas == sendGas) return true;
    }
    return false;
  }
}

