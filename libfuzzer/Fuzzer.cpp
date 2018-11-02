#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"

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
  int idx = 0;
  int totalFuzzed = 0;
  TargetContainer container(code, ca);
  Dictionary dict(code);
  vector<FuzzItem> queues;
  /* Update virgin bits and save testcase */
  auto saveIfInterest = [&](FuzzItem item) {
    if (hasNewBits(item.res.tracebits)) {
      cout << ">>> Saving ..... Done" << endl;
      queues.push_back(item);
    }
  };
  /* Handle new created testcase */
  auto commomFuzzStuff = [&](bytes data) {
    FuzzItem item(data);
    item.res = container.exec(data);
    item.wasFuzzed = false;
    saveIfInterest(item);
    totalFuzzed ++;
    return item;
  };
  /* Exec the sample testcase first */
  commomFuzzStuff(ca.randomTestcase());
  /* Jump to fuzz round */
  while (idx < 1) {
    FuzzItem curItem = queues[idx];
    Mutation mutation(curItem, dict);
    Timer timer;
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
    //mutation.overwriteWithDictionary(commomFuzzStuff);
    mutation.insertWithDictionary(commomFuzzStuff);
    cout << "EXEC  : " << timer.elapsed() << endl;
    cout << "TOTAl : " << totalFuzzed << endl;
    cout << "SPEED : " << totalFuzzed / timer.elapsed() << endl;
    idx ++;
    // TODO: update queue cycle
  }
}
