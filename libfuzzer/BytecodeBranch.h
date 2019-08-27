#pragma once

#include "Common.h"
#include "Util.h"
#include "Fuzzer.h"

namespace fuzzer {

  class BytecodeBranch {
    private:
      unordered_set<uint64_t> deploymentJumpis;
      unordered_set<uint64_t> runtimeJumpis;
    public:
      unordered_map<uint64_t, string> snippets;
      BytecodeBranch(const ContractInfo &contractInfo);
      pair<unordered_set<uint64_t>, unordered_set<uint64_t>> findValidJumpis();
      static vector<vector<uint64_t>> decompressSourcemap(string srcmap);
      static vector<pair<uint64_t, Instruction>> decodeBytecode(bytes bytecode);
  };

}
