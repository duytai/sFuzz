#pragma once
#include "Common.h"
#include "Util.h"
#include <map>
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
struct TargetContainerResult
{
    TargetContainerResult() {}
    TargetContainerResult(unordered_set<string> newTracebits, unordered_map<string, u256> predicates,
        unordered_set<string> uniqExceptions, string cksum, vector<Pattern*> patterns,
        vector<tuple<bool/*isCostructor*/, uint32_t, bytes, unordered_set<string>, vector<ReadWriteNode>>> funcsExec,
	    double execDur);
    
    /* Contains execution paths */
    unordered_set<string> newTracebits;
    /* Save predicates */
    unordered_map<string, u256> predicates;
    /* Exception path */
    unordered_set<string> uniqExceptions;
    /* Contains checksum of tracebits */
    string cksum;
    /* Contains execution patterns*/
    vector<Pattern*> patterns;
    /* Contains maps from function to excution trace*/
    vector<tuple<bool/*isCostructor*/, uint32_t, bytes, unordered_set<string>, vector<ReadWriteNode>>> funcsExec;
    /* Contains execDuration */
    double execDur;
};
}  // namespace fuzzer
