#include <iostream>
#include <vector>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>

using namespace dev;
using namespace eth;

namespace fuzzer {
  class Mutation {
    bytes data;
    public:
      Mutation(bytes data);
      void bitflip(void(*cb)(bytes data));
  };
}
