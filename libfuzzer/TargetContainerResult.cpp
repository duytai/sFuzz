#include "TargetContainerResult.h"

namespace fuzzer {

  TargetContainerResult::TargetContainerResult(
    unordered_set<uint64_t> tracebits,
    unordered_map<uint64_t, u256> predicates,
    unordered_map<string,
    unordered_set<uint64_t>> uniqExceptions,
    double cksum
  ) {
    this->tracebits = tracebits;
    this->cksum = cksum;
    this->predicates = predicates;
    this->uniqExceptions = uniqExceptions;
  }
}
