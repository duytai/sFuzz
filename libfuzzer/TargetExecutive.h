#pragma once
#include <vector>
#include <map>
#include <liboracle/OracleFactory.h>
#include "Common.h"
#include "TargetProgram.h"
#include "ContractABI.h"
#include "TargetContainerResult.h"
#include "Util.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct RecordParam {
    u64 lastpc = 0;
    bool isDeployment = false;
  };
  class TargetExecutive {
      TargetProgram *program;
      OracleFactory *oracleFactory;
      ContractABI ca;
      bytes code;
    public:
      Address addr;
      TargetExecutive(OracleFactory *oracleFactory, TargetProgram *program, Address addr, ContractABI ca, bytes code) {
        this->code = code;
        this->ca = ca;
        this->addr = addr;
        this->program = program;
        this->oracleFactory = oracleFactory;
      }
      TargetContainerResult exec(bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void deploy(bytes data, OnOpFunc onOp);
  };
}
