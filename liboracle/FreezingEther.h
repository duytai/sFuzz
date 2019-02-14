#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class FreezingEther : public Oracle {
    u256 numTransfer = 0;
    u256 numDelegatecall = 0;
    public:
      bool isFreezed() { return !numTransfer && numDelegatecall; };
      bool analyze(CallLog callLog);
  };
}
