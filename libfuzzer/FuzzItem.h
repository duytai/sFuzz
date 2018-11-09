#pragma once
#include <iostream>
#include "TargetContainer.h"
#include <libdevcore/Common.h>

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    FuzzItem() {}
    FuzzItem(bytes data) {
      this->data = data;
      this->wasFuzzed = false;
    }
    bytes data;
    TargetContainerResult res;
    bool wasFuzzed;
  };
  using OnMutateFunc = function<FuzzItem (bytes b)>;
}
