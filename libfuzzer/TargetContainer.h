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

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class TargetContainer {
    bytes code;
    map<string, vector<string>> abi;
    TargetProgram program;
    public:
      TargetContainer(bytes c, map<string, vector<string>> a);
      void exec(bytes data);
  };
}
