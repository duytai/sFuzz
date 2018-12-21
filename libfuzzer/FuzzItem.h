#pragma once
#include "TargetContainer.h"
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    FuzzItem(bytes data) {
      this->data = data;
      this->wasFuzzed = false;
      this->depth = 0;
    }
    bytes data;
    TargetContainerResult res;
    bool wasFuzzed;
    int depth;
  };
  using OnMutateFunc = function<FuzzItem (bytes b)>;
}
