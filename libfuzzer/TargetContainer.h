#pragma once
#include <iostream>
#include <vector>
#include <map>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>
#include "TargetProgram.h"
#include "ContractABI.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(unordered_set<uint64_t> tracebits, double cksum, unordered_map<uint64_t, double> predicates, unordered_map<string, unordered_set<uint64_t>> uniqExceptions) {
      this->tracebits = tracebits;
      this->cksum = cksum;
      this->predicates = predicates;
      this->uniqExceptions = uniqExceptions;
    }
    /* Contains execution paths */
    unordered_set<uint64_t> tracebits;
    /* Contains checksum of tracebits */
    double cksum;
    /* Save predicates */
    unordered_map<uint64_t, double> predicates;
    unordered_map<string, unordered_set<uint64_t>> uniqExceptions;
  };
  
  class TargetContainer {
    bytes code;
    ContractABI ca;
    TargetProgram program;
    u160 contractBaseAddress;
    u160 assetBaseAddress;
    public:
      TargetContainer();
      TargetContainerResult exec(bytes data);
      void loadContract(bytes code, ContractABI ca);
      void loadAsset(bytes code, ContractABI ca);
  };
}
