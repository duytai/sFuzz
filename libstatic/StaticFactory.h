#pragma once
#include "Common.h"
#include <liboracle/Common.h>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class StaticFactory {
    public:
      OracleResult analyze(bytes bin);
  };
}
