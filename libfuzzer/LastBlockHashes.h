#pragma once
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  class LastBlockHashes : public eth::LastBlockHashesFace {
  public:
    h256s precedingHashes(h256 const&) const override {
      return h256s(256, h256());
    };
    void clear() override {};
  };
}
