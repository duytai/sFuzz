#pragma once
#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <libdevcore/FixedHash.h>
#include "Util.h"

using namespace std;
using namespace dev;

namespace fuzzer {
  struct ExtraData {
    bytes data;
    u32 hitCount;
  };
  /*
  * Read push data inside bytecode to from dictionary
  * Pad left and right to enough 32 bytes
  */
  class Dictionary {
    public:
      vector<ExtraData> extras;
      Dictionary() {};
      Dictionary(bytes code);
  };
}
