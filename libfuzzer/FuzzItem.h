#pragma once
#include "TargetContainer.h"
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    vector<uint64_t> orders;
    unordered_map<uint64_t, double> score;
    bytes data;
    TargetContainerResult res;
    bool isInteresting = false;
    bool hasUncovered = false;
    uint64_t fuzzedCount = 0;
    uint64_t depth = 0;
    uint64_t totalFuncs = 0;
    FuzzItem(bytes _data, vector<uint64_t> _orders, uint64_t _totalFuncs) {
      data = _data;
      totalFuncs = _totalFuncs;
      orders = _orders;
    }
    static vector<uint64_t> fixedOrders(uint64_t totalFuncs) {
      vector<uint64_t> orders;
      for (uint64_t i = 0; i < totalFuncs; i ++)
        orders.push_back(i);
      return orders;
    }
  };
  using OnMutateFunc = function<FuzzItem (bytes b, vector<uint64_t>)>;
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
