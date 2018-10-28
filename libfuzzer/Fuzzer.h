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

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  static const unsigned int HIT_AGAIN = 1;
  static const unsigned int NEW_BRANCH = 2;
  static const unsigned int NOTHING = 0;
  
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
    private:
      bytes code;
      map<string, vector<string>> abi;
      bytes virginbits;
      bytes createInitialInput();
    public:
      uint8_t hasNewBits(bytes tracebits);
      Fuzzer(bytes c /* code */, map<string, vector<string>> a /* abi */);
      void start();
  };
}
