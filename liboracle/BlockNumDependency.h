#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class BlockNumberDependency {
    u256 numBlocknumber = 0;
    u256 numSend = 0;
    public:
      bool analyze(CallLog callLog);
  };
}
