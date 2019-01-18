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
    bool wasFuzzed = false;
    bool isInteresting = false;
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
    double score;
    SubFuzzItem(FuzzItem _item, double _score) : item(_item), score(_score) {};
    bool operator <(const SubFuzzItem& other) const {
      return score < other.score;
    }
  };
}
