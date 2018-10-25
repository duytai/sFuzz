#include <iostream>
#include <vector>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>
#include "LastBlockHashes.h"


using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class TargetProgram {
    private:
      State state;
      u256 gas;
      u256 nonce;
      Address sender;
      Address contractAddress;
      Executive *executive;
      ExecutionResult invoke(bytes data);
    public:
      TargetProgram();
      ~TargetProgram();
      void deploy(bytes code);
      ExecutionResult invokeConstructor(bytes data);
      ExecutionResult invokeFunction(bytes data);
  };
}
