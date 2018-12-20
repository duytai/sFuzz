#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class TimestampDependency {
    u256 numTimestamp = 0;
    u256 numSend = 0;
    public:
      bool analyze(CallLog callLog, bytes code);
  };
}
