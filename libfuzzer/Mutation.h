#include <iostream>
#include <vector>
#include <functional>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>

using namespace dev;
using namespace eth;
using namespace std;
using OnMutateFunc = function<void(bytes b)>;

namespace fuzzer {
  class Mutation {
    bytes data;
    int dataSize;
    int effCount;
    bytes eff;
    void flipbit(int pos);
    public:
      Mutation(bytes data);
      void singleWalkingBit(OnMutateFunc cb);
      void twoWalkingBit(OnMutateFunc cb);
      void fourWalkingBit(OnMutateFunc cb);
      void singleWalkingByte(OnMutateFunc cb);
      void twoWalkingByte(OnMutateFunc cb);
      void fourWalkingByte(OnMutateFunc cb);
  };
}
