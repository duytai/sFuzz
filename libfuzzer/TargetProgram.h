#include <iostream>
#include <vector>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethereum/LastBlockHashesFace.h>
#include "LastBlockHashes.h"


using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  void startEVMWithCode(bytes code);
  class TargetProgram {
    public:
      TargetProgram();
      void warmup();
      ExecutionResult deployContract(bytes code);
      ExecutionResult invokeFunction(bytes data);
    private:
      u256 gas;
      u256 gasPrice;
      u256 value;
      u256 nonce;
      BlockHeader blockHeader;
      LastBlockHashes lastBlockHashes;
      State state;
      Address sender;
      Address addr;
      Executive* executive;
  };
}
