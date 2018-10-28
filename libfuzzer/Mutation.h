#pragma once
#include <iostream>
#include <vector>
#include <functional>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>
#include "TargetContainer.h"
#include "Fuzzer.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  using OnMutateFunc = function<FuzzItem (bytes b)>;
  class Mutation {
    FuzzItem curFuzzItem;
    int dataSize;
    int effCount;
    bytes eff;
    void flipbit(int pos);
    vector<int8_t> interesting8;
    vector<int16_t> interesting16;
    vector<int32_t> interesting32;
    public:
      Mutation(FuzzItem item);
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
  };
}
