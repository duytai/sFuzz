#pragma once
#include "TargetContainer.h"
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    unordered_map<uint64_t, double> score;
    bytes data;
    TargetContainerResult res;
    bool isInteresting = false;
    uint64_t fuzzedCount = 0;
    uint64_t depth = 0;
    FuzzItem(bytes _data) {
      data = _data;
    }
  };
  using OnMutateFunc = function<FuzzItem (bytes b)>;
}
