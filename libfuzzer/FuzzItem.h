#pragma once
#include "TargetContainer.h"
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    bytes data;
    TargetContainerResult res;
    bool fuzzed = false;
    uint64_t depth = 0;
    FuzzItem(bytes _data) {
      data = _data;
    }
  };
  using OnMutateFunc = function<FuzzItem (bytes b)>;
}
