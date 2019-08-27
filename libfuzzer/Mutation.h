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
    uint64_t effCount = 0;
    bytes eff;
    void flipbit(int pos);
    public:
      uint64_t dataSize = 0;
      uint64_t stageMax = 0;
      uint64_t stageCur = 0;
      string stageName = "";
      static uint64_t stageCycles[32];
      Mutation(FuzzItem item, Dicts dicts);
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
      void random(OnMutateFunc cb);
      void havoc(OnMutateFunc cb);
      bool splice(vector<FuzzItem> items);
  };
}
