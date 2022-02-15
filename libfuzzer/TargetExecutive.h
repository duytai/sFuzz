#pragma once
#include <vector>
#include <map>
#include <liboracle/OracleFactory.h>
#include "Common.h"
#include "TargetProgram.h"
#include "ContractABI.h"
#include "TargetContainerResult.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct RecordParam {
    u64 lastpc = 0;
    bool isDeployment = false;
  };
  class TargetExecutive {
      Timer timer;
      TargetProgram *program;
      OracleFactory *oracleFactory;
      ContractABI ca;
      uint32_t curSelector = 0;
      bytes code;
    public:
      Address addr;
      TargetExecutive(OracleFactory *oracleFactory, TargetProgram *program, Address addr, ContractABI& ca, bytes code) {
        this->code = code;
        this->ca = ca;
        this->addr = addr;
        this->program = program;
        this->oracleFactory = oracleFactory;
      }
      TargetContainerResult execP(pair<bytes/*FuzzData*/, vector<size_t>/*order*/> item, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis, 
        bool newOrder, unordered_set<string> tracebits);
      TargetContainerResult execA(pair<bytes/*FuzzData*/, vector<size_t>/*order*/> item, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis, 
        bool newOrder, unordered_set<string> tracebits);
      void deploy(bytes data, OnOpFunc onOp);
  };
}
