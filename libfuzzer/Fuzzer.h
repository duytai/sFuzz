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
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class Fuzzer {
    ContractABI ca;
    bytes code;
    bytes virginbits;
    TargetContainer container;
    vector<FuzzItem> queues;
    int idx;
    bool clearScreen;
    int totalExecs;
    int queueCycle;
    int stageFinds[32];
    double lastNewPath;
    Timer timer;
    public:
      Fuzzer(bytes code /* code */, ContractABI ca /* contract abi */);
      u8 hasNewBits(bytes tracebits);
      FuzzItem saveIfInterest(bytes data);
      void start();
      void showStats(Mutation mutation, FuzzItem item);
  };
}
