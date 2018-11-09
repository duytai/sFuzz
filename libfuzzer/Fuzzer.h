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
#include "ContractABI.h"
#include "Util.h"

using namespace dev;
using namespace eth;
using namespace std;

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
  
  class Fuzzer {
    ContractABI ca;
    bytes code;
    bytes virginbits;
    TargetContainer container;
    vector<FuzzItem> queues;
    int idx;
    public:
      Fuzzer(bytes code /* code */, ContractABI ca /* contract abi */);
      u8 hasNewBits(bytes tracebits);
      FuzzItem saveIfInterest(bytes data);
      void start();
  };
}
