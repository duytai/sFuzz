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
  struct EnumClassHash {
    template <typename T>
    std::size_t operator()(T t) const {
      return static_cast<std::size_t>(t);
    }
  };
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(bytes tracebits, h256 cksum, double exTime, unordered_map<TransactionException, int, EnumClassHash> exceptions) {
      this->tracebits = tracebits;
      this->cksum = cksum;
      this->exTime = exTime;
      this->exceptions = exceptions;
    }
    /* Contains execution paths */
    bytes tracebits;
    /* Contains checksum of tracebits */
    h256 cksum;
    /* Execution time */
    double exTime;
    /* Exceptions */
    unordered_map<TransactionException, int, EnumClassHash> exceptions;
  };
  
  class TargetContainer {
    bytes code;
    ContractABI ca;
    TargetProgram program;
    public:
      TargetContainer(bytes code, ContractABI ca);
      TargetContainerResult exec(bytes data);
  };
}
