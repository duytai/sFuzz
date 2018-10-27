#include "Fuzzer.h"
#include "Abi.h"
#include "Mutation.h"
#include "TargetContainer.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

Fuzzer::Fuzzer(bytes c, map<string, vector<string>> a): code(c), abi(a){}
/* Create empty input */
bytes Fuzzer::createInitialInput() {
  bytes data;
  for (auto e : abi) {
    bytes b = createElem(e.second);
    data.insert(data.end(), b.begin(), b.end());
  }
  return data;
}

/* Start fuzzing */
void Fuzzer::start() {
  int idx = 0;
  TargetContainer container(code, abi);
  vector<bytes> queues = { createInitialInput() };
  while (idx < 1) {
    bytes input = queues[idx];
    Mutation mutation(input);
    mutation.singleWalkingBit([&](bytes data) {
      container.exec(input);
      cout << toHex(data) << endl;
    });
    idx++;
  }
}
