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

namespace fuzzer {
  class Fuzzer {
    private:
      bytes code;
      map<string, vector<string>> abi;
      bytes createInitialInput();
    public:
      Fuzzer(bytes c /* code */, map<string, vector<string>> a /* abi */);
      void start();
  };
}
