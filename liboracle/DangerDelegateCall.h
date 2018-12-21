#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class DangerDelegateCall : public Oracle {
    u256 numDanger = 0;
    public:
      bool analyze(CallLog callLog);
  };
}
