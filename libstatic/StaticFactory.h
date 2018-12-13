#pragma once
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class StaticFactory {
    public:
      void analyze(bytes bin);
  };
}
