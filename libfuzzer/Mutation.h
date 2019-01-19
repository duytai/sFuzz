#pragma once
#include <vector>
#include "Common.h"
#include "TargetContainer.h"
#include "Dictionary.h"
#include "FuzzItem.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  using Dicts = tuple<Dictionary/* code */, Dictionary/* address */>;
  class Mutation {
    FuzzItem curFuzzItem;
    Dicts dicts;
    int effCount;
    bytes eff;
    void flipbit(int pos);
    public:
      Mutation(FuzzItem item, Dicts dicts);
      vector<FuzzItem> mixCallOrders(bytes data, vector<uint64_t> orders, OnMutateFunc cb);
      FuzzItem havocCallOrders(bytes data, vector<uint64_t> orders, OnMutateFunc cb);
      void singleWalkingBit(OnMutateFunc cb);
      void twoWalkingBit(OnMutateFunc cb);
      void fourWalkingBit(OnMutateFunc cb);
      void singleWalkingByte(OnMutateFunc cb);
      void twoWalkingByte(OnMutateFunc cb);
      void fourWalkingByte(OnMutateFunc cb);
      void singleArith(OnMutateFunc cb);
      void twoArith(OnMutateFunc cb);
      void fourArith(OnMutateFunc cb);
      void singleInterest(OnMutateFunc cb);
      void twoInterest(OnMutateFunc cb);
      void fourInterest(OnMutateFunc cb);
      void overwriteWithAddressDictionary(OnMutateFunc cb);
      void overwriteWithDictionary(OnMutateFunc cb);
      void insertWithDictionary(OnMutateFunc cb);
      void overwriteWithAutoDictionary(OnMutateFunc cb);
      void random(OnMutateFunc cb);
      void havoc(OnMutateFunc cb);
      void newHavoc(OnMutateFunc cb);
      bool splice(vector<FuzzItem> items);
      static void addCandidate(unordered_map<uint64_t, set<SubFuzzItem>>& candidates, FuzzItem& item, uint64_t stageCur);
      int dataSize;
      int stageMax;
      int stageCur;
      string stageName;
      string stageShort;
      static int stageCycles[32];
  };
}
