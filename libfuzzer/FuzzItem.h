#pragma once
#include "TargetContainer.h"
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    bytes data;
    vector<size_t> order;
    TargetContainerResult res;
    uint64_t fuzzedCount = 0;
    uint64_t depth = 0;
    FuzzItem(bytes _data, vector<size_t> _order) {
      data = _data;
      order = _order;
    }
  };
  using OnMutateFunc = function<FuzzItem (bytes b, vector<size_t>)>;
}
