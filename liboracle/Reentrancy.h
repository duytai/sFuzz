#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class Reentrancy : public Oracle {
  public:
    bool analyze(CallLog callLog);
  };
}