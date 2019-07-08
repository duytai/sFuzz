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
        unordered_set<uint64_t> branches,
        double cksum,
        unordered_map<uint64_t, u256> predicates,
        unordered_map<string,
        unordered_set<uint64_t>> uniqExceptions
    );

    /* Contains execution paths */
    unordered_set<uint64_t> tracebits;
    /* Contains all branches */
    unordered_set<uint64_t> branches;
    /* Contains checksum of tracebits */
    double cksum;
    /* Save predicates */
    unordered_map<uint64_t, u256> predicates;
    /* Exception path */
    unordered_map<string, unordered_set<uint64_t>> uniqExceptions;
  };
}
