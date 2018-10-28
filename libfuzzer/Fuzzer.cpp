#include "Fuzzer.h"
#include "Abi.h"
#include "Mutation.h"
#include "Util.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(bytes c, map<string, vector<string>> a): code(c), abi(a), virginbits(bytes(MAP_SIZE, 255)){}

/* Create empty input */
bytes Fuzzer::createInitialInput() {
  bytes data;
  for (auto e : abi) {
    bytes b = createElem(e.second);
    data.insert(data.end(), b.begin(), b.end());
  }
  return data;
}

/* Detect new branch by comparing tracebits to virginbits */
uint8_t Fuzzer::hasNewBits(bytes tracebits) {
  uint8_t ret = 0;
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
  TargetContainer container(code, abi);
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
  commomFuzzStuff(createInitialInput());
  /* Jump to fuzz round */
  while (idx < 1) {
    FuzzItem curItem = queues[idx];
    Mutation mutation(curItem);
    Timer timer;
    mutation.singleWalkingBit(commomFuzzStuff);
    mutation.twoWalkingBit(commomFuzzStuff);
    mutation.fourWalkingBit(commomFuzzStuff);
    mutation.singleWalkingByte(commomFuzzStuff);
    mutation.twoWalkingByte(commomFuzzStuff);
    mutation.fourWalkingByte(commomFuzzStuff);
    mutation.singleArith(commomFuzzStuff);
    mutation.twoArith(commomFuzzStuff);
    mutation.fourArith(commomFuzzStuff);
    mutation.singleInterest(commomFuzzStuff);
    mutation.twoInterest(commomFuzzStuff);
    cout << "EXEC  : " << timer.elapsed() << endl;
    cout << "TOTAl : " << totalFuzzed << endl;
    cout << "SPEED : " << totalFuzzed / timer.elapsed() << endl;
    idx ++;
  }
}
