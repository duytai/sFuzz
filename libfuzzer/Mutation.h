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
#include "Dictionary.h"
#include "FuzzItem.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class Mutation {
    FuzzItem curFuzzItem;
    Dictionary dict;
    int effCount;
    bytes eff;
    void flipbit(int pos);
    public:
      Mutation(FuzzItem item, Dictionary dict);
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
      void overwriteWithDictionary(OnMutateFunc cb);
      void insertWithDictionary(OnMutateFunc cb);
      void overwriteWithAutoDictionary(OnMutateFunc cb);
      void random(OnMutateFunc cb);
      void havoc(unordered_set<uint64_t> tracebits, OnMutateFunc cb);
      bool splice(vector<FuzzItem> items);
      double calculateScore(const FuzzItem& item, unordered_set<uint64_t> tracebits);
      int dataSize;
      int stageMax;
      int stageCur;
      string stageName;
      string stageShort;
      static int stageCycles[32];
  };
}
