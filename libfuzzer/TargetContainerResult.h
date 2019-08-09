#pragma once
#include <vector>
#include <map>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(
        unordered_set<uint64_t> tracebits,
        unordered_map<uint64_t, u256> predicates,
        unordered_set<uint64_t> uniqExceptions,
        double cksum
    );

    /* Contains execution paths */
    unordered_set<uint64_t> tracebits;
    /* Save predicates */
    unordered_map<uint64_t, u256> predicates;
    /* Exception path */
    unordered_set<uint64_t> uniqExceptions;
    /* Contains checksum of tracebits */
    double cksum;
  };
}
