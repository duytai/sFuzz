#include <thread>
#include <unistd.h>
#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "AutoDictionary.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(bytes code, ContractABI ca): ca(ca), code(code), virginbits(bytes(MAP_SIZE, 255)){}

/* Detect new branch by comparing tracebits to virginbits */
u8 Fuzzer::hasNewBits(bytes tracebits) {
  u8 ret = 0;
  for (vector<int>::size_type i = 0; i < tracebits.size(); i += 1) {
    byte cur = tracebits[i];
    byte virgin = virginbits[i];
    if (cur && (cur & virgin)) {
      if (ret < 2) {
        if (cur && virgin == 0xFF) ret = 2;
        else ret = 1;
      }
      virginbits[i] &= ~cur;
    }
  }
  return ret;
}

/* Start fuzzing */
void Fuzzer::start() {
  /* Statistic information */
  int idx = 0;
  TargetContainer container(code, ca);
  Dictionary dict(code);
  AutoDictionary autoDict;
  Logger logger;
  vector<FuzzItem> queues;
  /* Handle new created testcase */
  auto commomFuzzStuff = [&](bytes data) {
    FuzzItem item(data);
    item.res = container.exec(data);
    item.wasFuzzed = false;
    if (hasNewBits(item.res.tracebits)) {
      queues.push_back(item);
      if (logger.stages.size()) {
        auto stage = logger.stages.back();
        stage->numTest ++;
      }
    }
    return item;
  };
  /* Exec the sample testcase first */
  commomFuzzStuff(ca.randomTestcase());
  /* Jump to fuzz round */
  //logger.startTimer();
  while (idx < 1) {
    FuzzItem curItem = queues[idx];
    Mutation mutation(curItem, dict, autoDict, logger);
    //mutation.singleWalkingBit(commomFuzzStuff);
    //mutation.twoWalkingBit(commomFuzzStuff);
    //mutation.fourWalkingBit(commomFuzzStuff);
    //mutation.singleWalkingByte(commomFuzzStuff);
    //mutation.twoWalkingByte(commomFuzzStuff);
    //mutation.fourWalkingByte(commomFuzzStuff);
    //mutation.singleArith(commomFuzzStuff);
    //mutation.twoArith(commomFuzzStuff);
    //mutation.fourArith(commomFuzzStuff);
    //mutation.singleInterest(commomFuzzStuff);
    //mutation.twoInterest(commomFuzzStuff);
    //mutation.fourInterest(commomFuzzStuff);
    //if (dict.extras.size()) {
    //  mutation.overwriteWithDictionary(commomFuzzStuff);
    //  mutation.insertWithDictionary(commomFuzzStuff);
    //}
    //if (autoDict.extras.size()) {
    //  mutation.overwriteWithAutoDictionary(commomFuzzStuff);
    //}
    mutation.havoc(commomFuzzStuff);
    idx ++;
  }
  //logger.endTimer();
}
