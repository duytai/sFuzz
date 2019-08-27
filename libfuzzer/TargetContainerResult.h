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
        unordered_set<string> tracebits,
        unordered_map<string, u256> predicates,
        unordered_set<string> uniqExceptions,
        string cksum
    );

    /* Contains execution paths */
    unordered_set<string> tracebits;
    /* Save predicates */
    unordered_map<string, u256> predicates;
    /* Exception path */
    unordered_set<string> uniqExceptions;
    /* Contains checksum of tracebits */
    string cksum;
  };
}
