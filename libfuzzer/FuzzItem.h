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
    uint64_t from = 0;
    string stage = "";
    FuzzItem(bytes _data) {
      data = _data;
    }
  };
  using OnMutateFunc = function<FuzzItem (bytes b)>;
  struct SubFuzzItem {
    FuzzItem item;
    uint64_t branch = 0;
    uint64_t stageCur = 0;
    SubFuzzItem(FuzzItem _item, uint64_t _branch, uint64_t _stageCur)
      :item(_item), branch(_branch), stageCur(_stageCur) {};
    bool operator <(const SubFuzzItem& other) const {
      /* Compare main branch */
      if (item.score.at(branch) < other.item.score.at(branch)) return true;
      return stageCur < other.stageCur;
    }
  };
}
