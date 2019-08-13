#pragma once

#include "Common.h"
#include "Util.h"
#include "Fuzzer.h"

namespace fuzzer {

  class BytecodeBranch {
    public:
      BytecodeBranch(const ContractInfo &contractInfo);
      static vector<string> split(string str, char separator);
      static vector<vector<uint64_t>> decompressSourcemap(string srcmap);
      static vector<pair<uint64_t, Instruction>> decodeBytecode(bytes bytecode);
  };

}
