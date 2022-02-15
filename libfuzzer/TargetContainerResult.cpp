#include "TargetContainerResult.h"

namespace fuzzer {

  TargetContainerResult::TargetContainerResult(
    unordered_set<string> newTracebits,
    unordered_map<string, u256> predicates,
    unordered_set<string> uniqExceptions,
    string cksum,
    vector<Pattern*> patterns,
    vector<tuple<bool/*isCostructor*/, uint32_t, bytes, unordered_set<string>, vector<ReadWriteNode>>> funcsExec,
    double execDur
    ) {
    this->newTracebits = newTracebits;
    this->cksum = cksum;
    this->predicates = predicates;
    this->uniqExceptions = uniqExceptions;
    this->patterns = patterns;
    this->funcsExec = funcsExec;
    this->execDur = execDur;
  }
}
