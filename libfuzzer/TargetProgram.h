#pragma once
#include <iostream>
#include <vector>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>
#include "LastBlockHashes.h"
#include "ContractABI.h"


using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  static const int CONTRACT_CONSTRUCTOR = 1;
  static const int CONTRACT_FUNCTION = 2;
  class TargetProgram {
    private:
      State state;
      u256 gas;
      u160 senderAddrValue;
      unordered_map<u160, u256> nonces;
      Address contractAddress;
      Executive *executive;
      ExecutionResult invoke(bytes data, OnOpFunc onOp);
    public:
      TargetProgram();
      ~TargetProgram();
      void deploy(bytes code);
      void reset();
      void updateEnv(ContractEnv env);
      ExecutionResult invoke(int type, bytes data, OnOpFunc onOp);
  };
}
