#include "TargetContainerResult.h"

namespace fuzzer {
  TargetContainerResult::TargetContainerResult(
    unordered_set<uint64_t> tracebits,
    unordered_set<uint64_t> branches,
    double cksum,
    unordered_map<uint64_t, u256> predicates,
    unordered_map<string,
    unordered_set<uint64_t>> uniqExceptions
  ) {
    this->tracebits = tracebits;
    this->cksum = cksum;
    this->predicates = predicates;
    this->uniqExceptions = uniqExceptions;
    this->branches = branches;
  }
}
